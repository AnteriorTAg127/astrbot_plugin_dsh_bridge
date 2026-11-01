#!/usr/bin/env python3
"""A-side (AstrBot) peer process for the cross-language transport harness.

This file is *test scaffolding only*. It does not re-implement the bridge: it
imports the real A-side modules (``bridge.session``, ``bridge.transport.*``,
``bridge.router``) and drives them over a real socket. It never patches bridge
code; it only wraps ``send_envelope``/``send_plain`` of the live carrier with a
recording proxy so the harness can observe the ``seq`` allocation and the
objects that were handed to the carrier.

Control channel
---------------
* commands: JSON lines on **stdin** (one object per line).
* events:   JSON lines on **fd 3** (passed by the parent). Using fd 3 keeps the
  control stream away from the bridge's own stdout logging.

The peer answers every command with an object carrying the command ``id``.

This peer is deliberately *not* a business implementation: the message handlers
it registers echo their params back. They exist to exercise the real
``Router`` + real ``Session`` byte path, and MUST NOT be reported as task
execution (protocol §9.3 semantics are not implemented on B yet).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import sys
import time
from typing import Any

A_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
if A_ROOT not in sys.path:
    sys.path.insert(0, A_ROOT)

from bridge.crypto import (  # noqa: E402  (import after sys.path fix)
    handshake_key,
    mac_object,
    psk_master,
    verify_mac,
)
from bridge.router import Router  # noqa: E402
from bridge.session import (  # noqa: E402
    Role,
    Session,
    SessionConfig,
    build_caps,
)
from bridge.transport.base import TransportHooks  # noqa: E402
from bridge.transport.manager import build_transport  # noqa: E402

#: Message names whose handlers this peer registers. All of them are answered by
#: an echo handler; see the module docstring.
ECHO_MESSAGES = (
    "task.status",
    "task.list_open",
    "event.ack",
    "approval.lookup",
    "session.list",
)

#: Control pipe fd, assigned by the parent so the peer never guesses.
CONTROL_FD = int(os.environ.get("DSH_BRIDGE_CONTROL_FD", "3"))


class Peer:
    """One A-side session bound to a real carrier."""

    def __init__(self, args: argparse.Namespace) -> None:
        """Configure the peer from CLI arguments.

        Args:
            args: Parsed command line.
        """
        self.args = args
        self.messages: list[dict] = []
        self.security_events: list[dict] = []
        self.states: list[tuple[str, str]] = []
        self.sent_plain: list[dict] = []
        self.received_plain: list[dict] = []
        self.sent_envelopes: list[dict] = []
        self.received_envelopes: list[dict] = []
        self.transport = None
        self.session: Session | None = None
        self._message_event = asyncio.Event()
        self._announced = False
        # Observations are per attempt, exactly like `sent_plain`.
        self.replied_plain: list[dict] = []
        # Carrier-level evidence (§7.4): a poll round is a request this endpoint
        # made, an ack is only ever sent for frames a poll handed back, and a
        # served poll is one this endpoint answered as the listening side.
        self.poll_rounds = 0
        self.poll_acks: list[list[str]] = []
        self.polls_served: list[dict] = []

    # -- helpers -----------------------------------------------------------------------

    def emit(self, obj: dict) -> None:
        """Write one event line to the control pipe.

        The pipe fd number is assigned by the parent at spawn time, because an
        inherited fd keeps its number only for the fds explicitly passed on.

        Args:
            obj: JSON-serialisable event object.
        """
        sys.stdout.flush()
        os.write(
            CONTROL_FD, (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
        )

    def _caps(self) -> dict:
        """Build the A-side caps object with the real builder (§4.5).

        Returns:
            Caps dictionary.
        """
        return build_caps(
            side="A",
            host="astrbot",
            version="0.1.0",
            transports=[self.args.transport],
            tls=False,
            native_tool=False,
            image_enabled=True,
            image_max_count=4,
            image_max_bytes=10_485_760,
            image_total_max_bytes=20_971_520,
        )

    def _probe_ack(self, probe: dict) -> dict:
        """Verify an inbound ``probe`` MAC and answer ``probe_ack`` (§7.3 rule 5).

        The A-side transport layer calls ``hooks.on_probe``; A's session module
        does not implement a probe signer/verifier, so the assembly layer owns
        it (see the harness report, "assembly gap").

        Args:
            probe: Received probe object.

        Returns:
            Signed ``probe_ack``.

        Raises:
            ValueError: When the probe MAC does not verify.
        """
        master = psk_master(self.args.psk_id, self.args.psk_secret)
        if not verify_mac(
            handshake_key(master, "probe"), probe, str(probe.get("mac", ""))
        ):
            raise ValueError("probe mac mismatch")
        body = {
            "v": 1,
            "type": "probe_ack",
            "conn": self.args.conn,
            "nonce": probe.get("nonce"),
            "ts": int(time.time() * 1000),
        }
        body["mac"] = mac_object(handshake_key(master, "probe_ack"), body)
        return body

    # -- lifecycle ---------------------------------------------------------------------

    async def start(self) -> None:
        """Create the session, start the carrier and run the handshake."""
        cfg = SessionConfig(
            conn=self.args.conn,
            side="A",
            role=Role.RESPONDER if self.args.mode == "listen" else Role.INITIATOR,
            transport=self.args.transport,
            psk_id=self.args.psk_id,
            psk_secret=self.args.psk_secret,
            heartbeat_s=self.args.heartbeat_s,
            req_timeout_s=10.0,
            caps=self._caps(),
            version="0.1.0",
            host_id="astrbot",
            addr="127.0.0.1",
            port=self.args.peer_port,
            bind_addr="127.0.0.1",
            bind_port=self.args.bind_port,
            path=self.args.path,
            mode=self.args.mode,
            poll_wait_s=self.args.poll_wait_s,
        )
        transport = build_transport(self.args.transport, cfg)
        # The probe period is an operator setting (§7.3 rule 5); a scenario that
        # must observe three consecutive probe failures shortens it here instead
        # of sleeping 90 s.
        if hasattr(transport, "_heartbeat_s"):
            transport._heartbeat_s = self.args.probe_interval_s
        self.transport = transport

        async def on_message(msg: dict) -> None:
            self.messages.append(msg)
            self._message_event.set()
            router = self.router
            if msg.get("k") == "req":
                reply = await router.dispatch(msg)
                if reply is not None:
                    await self.session.send_message(reply)
                return
            await router.dispatch(msg)

        def on_security(code: str, detail: str) -> None:
            self.security_events.append({"code": code, "detail": detail})

        session = Session(cfg, transport, on_message, on_security)
        self.session = session

        async def on_plain(obj: dict) -> dict | None:
            # Recorded for the harness: the four-step handshake must be verified
            # from real bytes, not from a re-derivation of the same helpers.
            self.received_plain.append(dict(obj))
            reply = await session.handle_plain(obj)
            if reply is not None:
                self.replied_plain.append(dict(reply))
            return reply

        async def on_envelope(env: dict) -> None:
            self.received_envelopes.append(dict(env))
            await session.handle_envelope(env)

        async def on_probe(obj: dict) -> dict:
            return self._probe_ack(obj)

        hooks = TransportHooks(
            on_plain=on_plain,
            on_envelope=on_envelope,
            on_probe=on_probe,
            on_state=lambda state, reason: self.states.append((state, reason)),
            on_activity=session.touch,
        )

        # Record what the session hands to the carrier. The real carrier still
        # performs every send; this only observes (§5.6 seq allocation).
        real_send_envelope = transport.send_envelope
        real_send_plain = transport.send_plain

        async def recording_send_envelope(env: dict) -> None:
            self.sent_envelopes.append(dict(env))
            await real_send_envelope(env)

        async def recording_send_plain(obj: dict) -> dict | None:
            self.sent_plain.append(dict(obj))
            return await real_send_plain(obj)

        transport.send_envelope = recording_send_envelope  # type: ignore[method-assign]
        transport.send_plain = recording_send_plain  # type: ignore[method-assign]

        # Downstream evidence (§7.4): count the poll round-trips this endpoint
        # made, the `acks` it sent (only a poll's frames can be acked) and the
        # polls it *served* as the listening side. The real carrier still does
        # every request; these wrappers only observe.
        real_poll_once = getattr(transport, "_poll_once", None)
        if callable(real_poll_once):

            async def recording_poll_once() -> None:
                self.poll_rounds += 1
                await real_poll_once()

            transport._poll_once = recording_poll_once  # type: ignore[method-assign]

        real_send_ack = getattr(transport, "_send_ack", None)
        if callable(real_send_ack):

            async def recording_send_ack(acks: list[str]) -> None:
                self.poll_acks.append(list(acks))
                await real_send_ack(acks)

            transport._send_ack = recording_send_ack  # type: ignore[method-assign]

        real_handle_poll = getattr(transport, "_handle_poll", None)
        if callable(real_handle_poll):

            async def recording_handle_poll(request: Any) -> Any:
                response = await real_handle_poll(request)
                self.polls_served.append(
                    {
                        "status": int(getattr(response, "status", 0) or 0),
                        "has_frames": bool(getattr(response, "body", b"")),
                    }
                )
                return response

            transport._handle_poll = recording_handle_poll  # type: ignore[method-assign]

        self.router = Router(conn=self.args.conn)
        for name in ECHO_MESSAGES:
            self.router.register(name, self._echo)

        # A's Session.start() does not start the carrier (B's does); the
        # assembly layer must call transport.start() first. Verified against
        # bridge/session.py:532 and lib/session.js:227.
        await transport.start(cfg, hooks)
        # The listener must tell the parent it is bound *before* it blocks in
        # the handshake: the parent spawns the connecting peer in response.
        if not self._announced:
            self._announced = True
            self.emit(
                {
                    "event": "listening",
                    "transport": self.args.transport,
                    "mode": self.args.mode,
                }
            )
        if self.args.mode == "listen":
            await session.start()
            await session.wait_ready(self.args.handshake_timeout_s)
        else:
            await transport.wait_ready(self.args.handshake_timeout_s)
            await session.start()

    async def _echo(self, params: dict, ctx: Any) -> dict:
        """Echo handler used to exercise Router/Session semantics.

        Args:
            params: Request parameters.
            ctx: Message context.

        Returns:
            The params echoed back, tagged with the handler side.
        """
        return {"echo": params, "handled_by": "A", "router_m": ctx.message}

    async def reconnect(self) -> dict:
        """Tear the session down and build a fresh one over a fresh carrier.

        This is the assembly layer's job (§6.3, §7.4): the session object is
        single-use -- it owns one sid and one nonce pair -- so a reconnect must
        create a new one. The harness performs exactly that, and reports the new
        `hello` nonce so the test can prove nonce freshness from real bytes.

        Returns:
            A snapshot after the new session reached `ready`.
        """
        await self.close()
        # Reset the per-attempt observations: only the new handshake matters.
        self.sent_plain.clear()
        self.replied_plain.clear()
        self.sent_envelopes.clear()
        self.received_plain.clear()
        self.received_envelopes.clear()
        self.states.clear()
        await self.start()
        return self.snapshot()

    async def close(self) -> None:
        """Close the session and the carrier, suppressing teardown errors."""
        if self.session is not None:
            with contextlib.suppress(Exception):
                await self.session.close("draining", "harness_done")
        if self.transport is not None:
            with contextlib.suppress(Exception):
                await self.transport.stop()

    # -- commands ----------------------------------------------------------------------

    def snapshot(self) -> dict:
        """Return the current session state for the parent.

        Returns:
            State dictionary with no secret material.
        """
        return {
            "state": self.session.state.value if self.session else "none",
            "sid": self.session.sid if self.session else None,
            "peer_caps_side": (self.session.peer_caps or {}).get("side")
            if self.session
            else None,
            "sent_plain_types": [item.get("type") for item in self.sent_plain],
            "received_plain_types": [item.get("type") for item in self.received_plain],
            "received_plain": self.received_plain,
            "replied_plain": self.replied_plain,
            "sent_plain": self.sent_plain,
            "received_envelope_types": [
                item.get("type") for item in self.received_envelopes
            ],
            "received_envelopes": self.received_envelopes,
            "sent_envelope_seqs": [item.get("seq") for item in self.sent_envelopes],
            "sent_envelope_types": [item.get("type") for item in self.sent_envelopes],
            "sent_envelopes": self.sent_envelopes,
            "security_events": self.security_events,
            "states": self.states,
            "received": self.messages,
            # Downstream evidence (§7.4): polls made, frames acked (only a poll
            # can produce those) and polls served as the listening side.
            "poll_rounds": self.poll_rounds,
            "poll_acks": self.poll_acks,
            "polls_served": self.polls_served,
            "has_runner": getattr(self.transport, "_runner", None) is not None,
            "carrier": self.transport.diagnostics() if self.transport else None,
        }

    async def handle(self, cmd: dict) -> dict:
        """Execute one command object.

        Args:
            cmd: Command with ``op``.

        Returns:
            Reply object (``id`` is filled by the caller).
        """
        op = cmd.get("op")
        if op == "snapshot":
            return {"event": "snapshot", **self.snapshot()}
        if op == "call":
            try:
                result = await self.session.call(
                    cmd["m"], cmd.get("params", {}), float(cmd.get("timeout_s", 10))
                )
                return {"event": "result", "ok": True, "result": result}
            except Exception as exc:  # noqa: BLE001 - reported, not raised
                return {
                    "event": "result",
                    "ok": False,
                    "error": {"code": getattr(exc, "code", type(exc).__name__)},
                }
        if op == "emit":
            await self.session.send_message(
                {
                    "k": "evt",
                    "m": cmd["m"],
                    "id": cmd["id_value"],
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".000Z",
                    "params": cmd.get("params", {}),
                }
            )
            # Report the sealed frame the session allocated for this emit: the
            # test correlates it with the peer's inbound `evt` by seq, so an
            # unrelated message can never satisfy the assertion.
            return {
                "event": "emitted",
                "sent_envelope": self.sent_envelopes[-1]
                if self.sent_envelopes
                else None,
                "own_seqs": [
                    item.get("seq")
                    for item in self.sent_envelopes
                    if item.get("type") == "data"
                ],
            }
        if op == "wait_messages":
            deadline = time.monotonic() + float(cmd.get("timeout_s", 10))
            want = int(cmd.get("count", 1))
            match = cmd.get("match") or {}

            def matched() -> list[dict]:
                """Inbound messages satisfying the requested filter.

                Returns:
                    Matching messages, in arrival order.
                """
                return [
                    msg
                    for msg in self.messages
                    if all(msg.get(key) == value for key, value in match.items())
                ]

            while len(matched()) < want and time.monotonic() < deadline:
                self._message_event.clear()
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._message_event.wait(), timeout=0.2)
            return {
                "event": "messages",
                "messages": self.messages,
                "matched": matched(),
                "count": len(matched()),
                "total": len(self.messages),
            }
        if op == "burst":
            count = int(cmd.get("count", 100))
            message = cmd.get("m", "task.status")
            results = await asyncio.gather(
                *[
                    self.session.call(message, {"task_id": f"burst-{index}"}, 10)
                    for index in range(count)
                ],
                return_exceptions=True,
            )
            failures = [item for item in results if isinstance(item, Exception)]
            return {
                "event": "burst",
                "count": count,
                "failures": [
                    {"code": getattr(item, "code", type(item).__name__)}
                    for item in failures
                ],
                "seqs": [item.get("seq") for item in self.sent_envelopes],
                "types": [item.get("type") for item in self.sent_envelopes],
            }
        if op == "reconnect":
            try:
                snapshot = await self.reconnect()
            except Exception as exc:  # noqa: BLE001 - reported, not raised
                return {
                    "event": "reconnect_error",
                    "code": getattr(exc, "code", type(exc).__name__),
                }
            return {"event": "reconnected", **snapshot}
        if op == "close":
            await self.close()
            return {"event": "closed"}
        return {"event": "unknown_op", "op": op}


async def main() -> int:
    """Run the peer command loop.

    Returns:
        Process exit code.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--transport", required=True, choices=("ws", "webhook", "longpoll")
    )
    parser.add_argument("--mode", required=True, choices=("listen", "connect"))
    parser.add_argument("--peer-port", type=int, required=True)
    parser.add_argument("--bind-port", type=int, default=0)
    parser.add_argument("--path", default="/dsh-bridge")
    parser.add_argument("--conn", default="default")
    parser.add_argument("--psk-id", required=True)
    parser.add_argument("--psk-secret", required=True)
    parser.add_argument("--handshake-timeout-s", type=float, default=15.0)
    parser.add_argument("--poll-wait-s", type=int, default=2)
    parser.add_argument("--heartbeat-s", type=int, default=30)
    parser.add_argument("--probe-interval-s", type=int, default=30)
    args = parser.parse_args()

    peer = Peer(args)
    try:
        await peer.start()
    except Exception as exc:  # noqa: BLE001 - reported to the parent
        peer.emit(
            {
                "event": "start_error",
                "code": getattr(exc, "code", type(exc).__name__),
                "detail": str(exc)[:200],
            }
        )
        if peer.transport is not None:
            with contextlib.suppress(Exception):
                await peer.transport.stop()
        return 3
    peer.emit({"event": "ready", **peer.snapshot()})

    loop = asyncio.get_running_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if line == "":
            break
        line = line.strip()
        if not line:
            continue
        cmd = json.loads(line)
        reply = await peer.handle(cmd)
        reply["id"] = cmd.get("id")
        peer.emit(reply)
        if cmd.get("op") == "close":
            break
    await peer.close()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
