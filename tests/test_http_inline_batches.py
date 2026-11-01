"""Real-socket regression for the §7.3-2 / §7.4 inline frame batch.

The production code under test is the *whole* carrier + session stack on both
ends: each side runs a real ``Session`` with real crypto over a real loopback
TCP socket, and nothing about the four-step handshake is re-derived or faked.
The only test-side instrumentation is a transparent proxy around the outbound
``aiohttp`` client session, which records the HTTP status and response body of
each request the production code sent — observation, never substitution.

Covered here (each case failed before the inline-batch fix):

* the responder answers the ``POST /frames`` batch that carried ``auth`` with
  **200** plus ``frames`` containing ``auth_ack``, and the initiator consumes it
  (§7.3 rule 2 both halves);
* later batches stay **202** with ``accepted`` references, and never become a
  silent handshake success;
* a bare **200** whose body is not a batch is rejected, not accepted as a
  completed handshake ("不能把所有 200 当握手成功");
* malformed batches keep their §8.1 status codes (``bad_batch`` 400,
  ``frame_too_large`` 413);
* a ``connect`` long-poll endpoint binds nothing (poll/upload only), so a
  one-way-reachable deployment can still handshake and carry messages both ways;
* a ``connect`` webhook endpoint binds an *ephemeral local* port, never the peer
  port, so starting it cannot collide with the peer's own listener.
"""

from __future__ import annotations

import asyncio
import json
import socket
import time
from typing import Any
from urllib.parse import urlsplit

import aiohttp
import pytest
from _session_doubles import TEST_PSK_ID, TEST_PSK_SECRET, make_caps
from bridge.constants import (
    CONTENT_TYPE_JSON,
    HEADER_VERSION,
    MAX_BATCH_FRAMES,
)
from bridge.errors import BridgeError
from bridge.session import Role, Session, SessionConfig, SessionState, make_message
from bridge.transport.base import TransportHooks
from bridge.transport.longpoll import LongPollTransport
from bridge.transport.webhook import WebhookTransport


def _free_port() -> int:
    """Return an unused loopback TCP port.

    Returns:
        A port the kernel just handed out.
    """
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _RecordingRequest:
    """Context-manager proxy that records one HTTP exchange, then delegates."""

    def __init__(self, context: Any, sink: list[dict], method: str, url: str) -> None:
        """Wrap one pending ``aiohttp`` request.

        Args:
            context: The real ``_RequestContextManager``.
            sink: List the recorded exchange is appended to.
            method: HTTP method.
            url: Absolute request URL.
        """
        self._context = context
        self._sink = sink
        self._method = method
        self._url = url
        self._response: Any = None

    async def __aenter__(self) -> Any:
        """Enter the real request context.

        Returns:
            The real ``ClientResponse``.
        """
        self._response = await self._context.__aenter__()
        return self._response

    async def __aexit__(self, *exc_info: object) -> Any:
        """Record status and body, then leave the real request context.

        ``read()`` caches the payload on the response, so recording here does not
        consume anything the production code still needs.

        Args:
            *exc_info: Exception information (forwarded unchanged).

        Returns:
            Whatever the real context manager returns.
        """
        body: Any = None
        try:
            raw = await self._response.read()
            body = json.loads(raw.decode("utf-8")) if raw else None
        except Exception:  # noqa: BLE001 - recording must never fail the test
            body = None
        self._sink.append(
            {
                "method": self._method,
                "path": urlsplit(self._url).path,
                "status": self._response.status,
                "body": body,
            }
        )
        return await self._context.__aexit__(*exc_info)


class _RecordingSession:
    """Transparent proxy around a real ``aiohttp.ClientSession``."""

    def __init__(self, real: Any, sink: list[dict]) -> None:
        """Wrap the production client session.

        Args:
            real: The ``aiohttp.ClientSession`` the transport created.
            sink: List receiving one entry per request.
        """
        self._real = real
        self._sink = sink

    def post(self, url: str, **kwargs: Any) -> _RecordingRequest:
        """Proxy ``POST``.

        Args:
            url: Request URL.
            **kwargs: Passed through unchanged.

        Returns:
            The recording context manager.
        """
        return _RecordingRequest(
            self._real.post(url, **kwargs), self._sink, "POST", url
        )

    def get(self, url: str, **kwargs: Any) -> _RecordingRequest:
        """Proxy ``GET``.

        Args:
            url: Request URL.
            **kwargs: Passed through unchanged.

        Returns:
            The recording context manager.
        """
        return _RecordingRequest(self._real.get(url, **kwargs), self._sink, "GET", url)

    @property
    def closed(self) -> bool:
        """Whether the wrapped session is closed."""
        return bool(self._real.closed)

    async def close(self) -> None:
        """Close the wrapped session."""
        await self._real.close()


class HttpPair:
    """Two production sessions joined over real loopback sockets."""

    def __init__(
        self,
        *,
        transport: str,
        a_role: str,
        a_bind_port: int | None = None,
        max_batch_bytes: int | None = None,
    ) -> None:
        """Configure the pair.

        Args:
            transport: ``webhook`` or ``longpoll``.
            a_role: ``"listen"`` or ``"connect"`` for side A.
            a_bind_port: Explicit bind port for A; ``None`` keeps ``bind_port=0``.
            max_batch_bytes: Optional small batch cap for the listener.
        """
        self.transport_name = transport
        self.a_role = a_role
        self.b_role = "connect" if a_role == "listen" else "listen"
        self.b_listen_port = _free_port()
        self.a_listen_port = _free_port()
        self.a_messages: list[dict] = []
        self.b_messages: list[dict] = []
        self.states: list[tuple[str, str]] = []
        self.recorded: list[dict] = []

        # The responder owns the single listening port; the initiator dials it.
        listen_port = self.a_listen_port if a_role == "listen" else self.b_listen_port
        if a_bind_port is not None:
            a_bind = a_bind_port
        else:
            # Only a listening endpoint owns an inbound socket; a connecting one
            # binds an ephemeral port (webhook) or nothing at all (long-poll).
            a_bind = self.a_listen_port if a_role == "listen" else 0
        b_bind = self.b_listen_port if self.b_role == "listen" else 0

        self.a_cfg = SessionConfig(
            conn="default",
            side="A",
            role=Role.INITIATOR if a_role == "connect" else Role.RESPONDER,
            transport=transport,
            psk_id=TEST_PSK_ID,
            psk_secret=TEST_PSK_SECRET,
            caps=make_caps("A"),
            addr="127.0.0.1",
            port=listen_port,
            bind_addr="127.0.0.1",
            bind_port=a_bind,
            mode=a_role,
            path="/dsh-bridge",
            poll_wait_s=1,
        )
        self.b_cfg = SessionConfig(
            conn="default",
            side="B",
            role=Role.INITIATOR if self.b_role == "connect" else Role.RESPONDER,
            transport=transport,
            psk_id=TEST_PSK_ID,
            psk_secret=TEST_PSK_SECRET,
            caps=make_caps("B"),
            addr="127.0.0.1",
            port=listen_port,
            bind_addr="127.0.0.1",
            bind_port=b_bind,
            mode=self.b_role,
            path="/dsh-bridge",
            poll_wait_s=1,
        )
        if transport == "webhook":
            maker = WebhookTransport
        else:
            maker = LongPollTransport
        extra = {"max_batch_bytes": max_batch_bytes} if max_batch_bytes else {}
        self.a_transport = maker(
            role=a_role,
            conn="default",
            side="A",
            psk_id=TEST_PSK_ID,
            psk_secret=TEST_PSK_SECRET,
            heartbeat_s=3600,
            **extra,
        )
        self.b_transport = maker(
            role=self.b_role,
            conn="default",
            side="B",
            psk_id=TEST_PSK_ID,
            psk_secret=TEST_PSK_SECRET,
            heartbeat_s=3600,
            **extra,
        )
        self.a = Session(self.a_cfg, self.a_transport, self._capture_a, self._security)
        self.b = Session(self.b_cfg, self.b_transport, self._capture_b, self._security)
        self._hooks_a = TransportHooks(
            on_plain=self.a.handle_plain,
            on_envelope=self.a.handle_envelope,
            on_probe=self._probe_ack,
            on_state=lambda state, reason: self.states.append((f"A:{state}", reason)),
            on_activity=self.a.touch,
        )
        self._hooks_b = TransportHooks(
            on_plain=self.b.handle_plain,
            on_envelope=self.b.handle_envelope,
            on_probe=self._probe_ack,
            on_state=lambda state, reason: self.states.append((f"B:{state}", reason)),
            on_activity=self.b.touch,
        )

    async def _probe_ack(self, obj: dict) -> dict:
        """Answer a probe with a MAC that verifies (§7.3 rule 5).

        Args:
            obj: Incoming probe object.

        Returns:
            Valid ``probe_ack``.
        """
        from bridge.crypto import handshake_key, mac_object, psk_master

        body = {
            "v": 1,
            "type": "probe_ack",
            "conn": obj.get("conn", "default"),
            "nonce": obj.get("nonce"),
            "ts": obj.get("ts"),
        }
        body["mac"] = mac_object(
            handshake_key(psk_master(TEST_PSK_ID, TEST_PSK_SECRET), "probe_ack"), body
        )
        return body

    async def _capture_a(self, msg: dict) -> None:
        self.a_messages.append(msg)
        await self._answer(self.a, msg)

    async def _capture_b(self, msg: dict) -> None:
        self.b_messages.append(msg)
        await self._answer(self.b, msg)

    async def _answer(self, session: Session, msg: dict) -> None:
        """Answer a ``req`` through the production sender (§5.5, §9.2).

        Args:
            session: Session that received the request.
            msg: Inbound message object.
        """
        if msg.get("k") != "req":
            return
        reply = make_message(
            "rep",
            msg["m"],
            result={"echo": msg.get("params", {})},
            reply_to=msg["id"],
        )
        await session.send_message(reply)

    def _security(self, code: str, detail: str) -> None:
        self.states.append((f"security:{code}", detail))

    async def start(self) -> None:
        """Start both carriers, then the handshake, over real sockets."""
        await self.a_transport.start(self.a_cfg, self._hooks_a)
        await self.b_transport.start(self.b_cfg, self._hooks_b)
        # Observe the production client's HTTP exchanges without changing them.
        for transport in (self.a_transport, self.b_transport):
            transport._client = _RecordingSession(  # noqa: SLF001 - observation only
                transport._client_session(),
                self.recorded,  # noqa: SLF001
            )
        responder = self.b if self.b_role == "listen" else self.a
        initiator = self.a if self.b_role == "listen" else self.b
        await responder.start()
        await initiator.start()
        await responder.wait_ready(15)

    async def close(self) -> None:
        """Close both sessions and carriers."""
        for session in (self.a, self.b):
            try:
                await session.close("draining", "test_done")
            except Exception:
                pass
        for transport in (self.a_transport, self.b_transport):
            try:
                await transport.stop()
            except Exception:
                pass

    def statuses(self, path: str) -> list[dict]:
        """Return recorded exchanges for one endpoint, in order.

        Args:
            path: Endpoint path such as ``/dsh-bridge/frames``.

        Returns:
            Matching records.
        """
        return [item for item in self.recorded if item["path"] == path]

    async def wait_for(self, sink: list[dict], message: str, count: int = 1) -> dict:
        """Wait for one inbound message with the given ``m`` name.

        Args:
            sink: Message list of the receiving side.
            message: Message name to match.
            count: Occurrences required before returning.

        Returns:
            The first matching message.

        Raises:
            AssertionError: When the message never arrives.
        """
        for _ in range(400):
            matches = [item for item in sink if item.get("m") == message]
            if len(matches) >= count:
                return matches[0]
            await asyncio.sleep(0.02)
        raise AssertionError(f"{message} never arrived; received={sink}")


def _event(name: str, ident: str) -> dict:
    """Build an event message object (§9.1).

    Args:
        name: Message name.
        ident: Message id.

    Returns:
        Message object.
    """
    return {
        "k": "evt",
        "m": name,
        "id": ident,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".000Z",
        "params": {"version": 1, "grants": [], "revoked": []},
    }


@pytest.mark.asyncio
async def test_webhook_auth_batch_is_answered_200_and_consumed() -> None:
    """§7.3 rule 2: the ``auth`` batch is answered ``200`` with ``auth_ack`` inline."""
    pair = HttpPair(transport="webhook", a_role="connect")
    await pair.start()
    try:
        assert pair.a.state is SessionState.READY
        assert pair.b.state is SessionState.READY
        assert pair.a.sid == pair.b.sid

        frames_calls = pair.statuses("/dsh-bridge/frames")
        assert frames_calls, "the initiator never posted a frame batch"
        auth_call = frames_calls[0]
        assert auth_call["status"] == 200, auth_call
        assert isinstance(auth_call["body"], dict), auth_call
        inline = auth_call["body"].get("frames")
        assert isinstance(inline, list) and inline, auth_call
        assert inline[0]["type"] == "auth_ack", inline[0]
        assert inline[0]["seq"] == 0, inline[0]
        assert set(inline[0]) == {"v", "type", "conn", "seq", "ct"}, inline[0]
        # The handshake only reaches `ready` when that inline frame is consumed.
        assert pair.a.sid == pair.b.sid
    finally:
        await pair.close()


@pytest.mark.asyncio
async def test_webhook_data_batch_stays_202_with_accepted_refs() -> None:
    """Later batches answer ``202`` with ``accepted`` refs, not a second ``200``."""
    pair = HttpPair(transport="webhook", a_role="connect")
    await pair.start()
    try:
        await pair.a.send_message(
            _event("session.authz", "11111111-1111-4111-8111-111111111111")
        )
        await pair.wait_for(pair.b_messages, "session.authz")

        frames_calls = pair.statuses("/dsh-bridge/frames")
        assert frames_calls[-1]["status"] == 202, frames_calls[-1]
        body = frames_calls[-1]["body"]
        assert body["accepted"], body
        assert body["accepted"][0].startswith("data#"), body
        assert body["rejected"] == [], body
        # Only the auth batch may be a 200 batch.
        ones = [item for item in frames_calls if item["status"] == 200]
        assert len(ones) == 1, ones
    finally:
        await pair.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reply_body",
    [
        {"v": 1, "ok": True},
        {"v": 1, "accepted": ["data#1"], "rejected": []},
        {"v": 1, "frames": []},
        {"v": 1, "frames": "not-a-list"},
    ],
    ids=["no-frames", "accepted-only", "empty-frames", "frames-not-a-list"],
)
async def test_bare_200_is_not_a_handshake_success(reply_body: dict) -> None:
    """A ``200`` whose body is not a *non-empty* frame batch is refused.

    Only §7.3 rule 2 makes a ``200`` meaningful, and only when it carries the
    inline ``auth_ack`` batch. A peer that answers ``200`` with a health body, a
    ``202``-shaped acknowledgement, an empty ``frames`` array or a non-array must
    never be mistaken for a completed handshake.

    Args:
        reply_body: Body the stand-in peer returns with its ``200``.
    """
    from aiohttp import web

    received: list[dict] = []

    async def fake_frames(request: Any) -> Any:
        received.append(await request.json())
        return web.json_response(
            reply_body, headers={HEADER_VERSION: "1", "Cache-Control": "no-store"}
        )

    app = web.Application()
    app.router.add_post("/dsh-bridge/frames", fake_frames)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = int(site._server.sockets[0].getsockname()[1])  # noqa: SLF001 - test probe
    transport = WebhookTransport(
        role="connect",
        conn="default",
        side="A",
        psk_id=TEST_PSK_ID,
        psk_secret=TEST_PSK_SECRET,
        heartbeat_s=3600,
    )
    cfg = SessionConfig(
        conn="default",
        side="A",
        role=Role.INITIATOR,
        transport="webhook",
        psk_id=TEST_PSK_ID,
        psk_secret=TEST_PSK_SECRET,
        caps=make_caps("A"),
        addr="127.0.0.1",
        port=port,
        bind_port=0,
        path="/dsh-bridge",
    )
    hooks = TransportHooks(
        on_plain=lambda obj: _none(),
        on_envelope=lambda env: _none(),
        on_probe=lambda obj: _none(),
        on_state=lambda state, reason: None,
    )
    await transport.start(cfg, hooks)
    try:
        with pytest.raises(BridgeError) as caught:
            await transport._post_frames(  # noqa: SLF001 - the unit under test
                [{"v": 1, "type": "data", "conn": "default", "seq": 1, "ct": "AAAA"}]
            )
        assert caught.value.code == "bad_frame", caught.value
        assert received, "the batch was never posted"
    finally:
        await transport.stop()
        await runner.cleanup()


async def _none() -> None:
    """Async no-op hook used by the direct-carrier tests."""
    return None


@pytest.mark.asyncio
async def test_malformed_batches_keep_their_status_codes() -> None:
    """``bad_batch`` answers 400 and an oversized body answers 413 (§8.1)."""
    pair = HttpPair(transport="webhook", a_role="connect", max_batch_bytes=4096)
    await pair.start()
    try:
        base = f"http://127.0.0.1:{pair.b_listen_port}/dsh-bridge"
        async with aiohttp.ClientSession() as client:
            async with client.post(
                f"{base}/frames",
                json={"v": 1, "frames": [{"seq": 5}, {"seq": 1}]},
                headers={"Content-Type": CONTENT_TYPE_JSON},
            ) as response:
                assert response.status == 400
                assert (await response.json())["error"]["code"] == "bad_batch"

            frames = [
                {"v": 1, "type": "data", "conn": "default", "seq": index, "ct": "AA"}
                for index in range(MAX_BATCH_FRAMES + 1)
            ]
            async with client.post(
                f"{base}/frames",
                json={"v": 1, "frames": frames},
                headers={"Content-Type": CONTENT_TYPE_JSON},
            ) as response:
                assert response.status == 400
                assert (await response.json())["error"]["code"] == "bad_batch"

            oversized = b"{" + b" " * 8192 + b"}"
            async with client.post(
                f"{base}/frames",
                data=oversized,
                headers={"Content-Type": CONTENT_TYPE_JSON},
            ) as response:
                assert response.status == 413
                body = await response.json()
                assert body["error"]["code"] == "frame_too_large"
                assert body["error"]["retryable"] is False
    finally:
        await pair.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("a_role", ["listen", "connect"])
async def test_longpoll_connect_binds_nothing_and_carries_both_ways(
    a_role: str,
) -> None:
    """A ``connect`` long-poll endpoint polls/uploads only, yet traffic flows both ways.

    This is the one-way-reachability property: the dialing side owns no inbound
    socket at all, so a deployment where only that side can reach the other still
    handshakes and carries messages in both directions (downstream arrives on the
    ``GET /poll`` response, not on a pushed connection).

    Args:
        a_role: ``listen`` (B connects) or ``connect`` (A connects).
    """
    pair = HttpPair(transport="longpoll", a_role=a_role)
    await pair.start()
    try:
        connector = pair.a if a_role == "connect" else pair.b
        listener = pair.b if a_role == "connect" else pair.a
        connector_sink = pair.a_messages if a_role == "connect" else pair.b_messages
        listener_sink = pair.b_messages if a_role == "connect" else pair.a_messages
        connector_transport = (
            pair.a_transport if a_role == "connect" else pair.b_transport
        )
        listener_transport = (
            pair.b_transport if a_role == "connect" else pair.a_transport
        )
        assert connector.state is SessionState.READY
        assert listener.state is SessionState.READY
        assert connector.sid == listener.sid
        # The dialing side owns no listener: nothing to dial in to.
        assert connector_transport._runner is None  # noqa: SLF001
        assert listener_transport._runner is not None  # noqa: SLF001

        # Connector → listener over POST /frames, and the reply comes back on the
        # upload response's own path (§7.4 uploads are bidirectional HTTP).
        uplink = await connector.call("task.status", {"t": "中文"}, timeout_s=15)
        assert uplink["echo"]["t"] == "中文", uplink

        # Listener → connector: the listener cannot dial in, so this decrypted
        # request can only arrive on the connector's ``GET /poll`` response.
        downlink = await listener.call("task.status", {"t": "下行"}, timeout_s=15)
        assert downlink["echo"]["t"] == "下行", downlink

        # Events take the same two paths.
        await connector.send_message(
            _event("session.authz", "22222222-2222-4222-8222-222222222222")
        )
        await pair.wait_for(listener_sink, "session.authz")
        await listener.send_message(
            _event("task.event", "33333333-3333-4333-8333-333333333333")
        )
        await pair.wait_for(connector_sink, "task.event")

        polls = connector_transport.diagnostics()["last_status"]
        assert polls in (0, 200, 204), polls
    finally:
        await pair.close()


@pytest.mark.asyncio
async def test_webhook_connect_binds_local_port_not_peer_port() -> None:
    """B-02: a connecting webhook binds its own ephemeral port, never the peer's.

    The peer's listener is already up, so the old fallback (``bind_port == 0`` →
    bind the peer port) would either fail with ``address already in use`` or make
    the endpoint post to itself. It must bind an ephemeral local port instead and
    still complete the handshake.
    """
    pair = HttpPair(transport="webhook", a_role="connect")
    # B is the responder (listen); bring its listener up before A dials, so the
    # peer port really is occupied when the connect side starts.
    await pair.b_transport.start(pair.b_cfg, pair._hooks_b)
    try:
        await pair.a_transport.start(pair.a_cfg, pair._hooks_a)
        runner = pair.a_transport._runner  # noqa: SLF001 - the bind under test
        assert runner is not None and runner.sites, "connect side bound nothing"
        site = next(iter(runner.sites))
        bound = int(site._server.sockets[0].getsockname()[1])  # noqa: SLF001
        assert bound != pair.b_listen_port, (bound, pair.b_listen_port)
        assert bound > 0, "connect side must bind a concrete local port"

        await pair.b.start()
        await pair.a.start()
        await pair.b.wait_ready(15)
        assert pair.a.state is SessionState.READY
        assert pair.a.sid == pair.b.sid
    finally:
        await pair.close()
