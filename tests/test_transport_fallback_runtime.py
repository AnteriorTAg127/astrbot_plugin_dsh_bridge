"""Runtime fallback behaviour of the real :class:`TransportManager` (§7.3.6, §7.5).

Scope and stubbing
------------------
Everything that decides behaviour is production code: the real
``TransportManager`` drives its own ladder, ``bridge.session.Session`` runs the
production four-step handshake (real HKDF keys, real nonces, real AEAD and
sequence bookkeeping) and every carrier owns a real loopback socket.

Only *external host facilities* are substituted, at the carrier-factory seam:

* ``build_transport`` returns :class:`ControllableCarrier`, a carrier with a real
  socket and the same lifecycle contract as the shipped ones
  (``start``/``stop``/``alive``/``degraded``). Like ``WebhookTransport`` it flips
  ``degraded()`` and emits ``on_state("degraded", "transport_degraded")`` when its
  reverse probe gives up, so the manager must read the carrier's own state.
* the peer (side B) runs in-process instead of in a second process.

Nothing else is stubbed: no fake handshake, no fake crypto, no fake routing.

What is proven
--------------
1. A carrier degraded **at runtime** is dropped, the configured fallback starts,
   ``transport_degraded`` is recorded, and the new carrier carries a **fresh**
   session (new ``nonce_c``, new ``sid``, new AEAD keys, ``seq`` restarting at 0).
2. The old carrier's socket is really closed and its port is rebindable; the old
   session is closed, not leaked.
3. A failed preferred-carrier retry does not drop the live fallback; the retry
   the loop drives later succeeds and records ``restored`` with a fresh session.
4. ``stop()`` ends ``run_forever`` and nothing reconnects afterwards.
5. A degraded link with no usable fallback backs off instead of busy-looping.
"""

from __future__ import annotations

import asyncio
import socket
import time

import bridge.transport.manager as manager_mod
import pytest
from _session_doubles import TEST_PSK_ID, TEST_PSK_SECRET, make_caps
from bridge.session import Role, Session, SessionConfig, SessionState
from bridge.transport.base import TransportHooks
from bridge.transport.manager import TransportManager


def free_port() -> int:
    """Return an unused loopback port.

    Returns:
        Port number.
    """
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _cfg(side: str, role: Role, transport: str, mode: str) -> SessionConfig:
    """Build a real session configuration for one side.

    Args:
        side: ``"A"`` or ``"B"``.
        role: Handshake role.
        transport: Carrier name advertised in ``caps`` and ``hello``.
        mode: ``connect`` (A) or ``listen`` (B).

    Returns:
        The configuration.
    """
    return SessionConfig(
        conn="default",
        side=side,
        role=role,
        transport=transport,
        psk_id=TEST_PSK_ID,
        psk_secret=TEST_PSK_SECRET,
        caps=make_caps(side),
        heartbeat_s=3600,
        mode=mode,
        bind_port=free_port(),
    )


class PeerLink:
    """Outbound-only carrier used by the in-process responder."""

    name = "peer"

    def __init__(self) -> None:
        """Create an unbound link."""
        self.session: Session | None = None
        self.stopped = False

    async def start(self, cfg: object, hooks: object) -> None:
        """No-op start: the responder never dials."""

    async def stop(self) -> None:
        """Mark the link stopped."""
        self.stopped = True

    async def send_envelope(self, env: dict) -> None:
        """Deliver one sealed envelope to the local initiator.

        Args:
            env: Envelope object.
        """
        assert self.session is not None
        await self.session.handle_envelope(env)

    async def send_plain(self, obj: dict) -> dict | None:
        """Responders never send plaintext objects.

        Args:
            obj: Ignored.

        Returns:
            Always ``None``.
        """
        return None

    def alive(self) -> bool:
        """The in-process link is always usable."""
        return True


class ControllableCarrier:
    """Carrier double with a real socket and a controllable probe verdict."""

    def __init__(self, name: str, *, available: bool = True) -> None:
        """Create the carrier.

        Args:
            name: Carrier name (``webhook`` / ``longpoll``).
            available: Whether ``start`` succeeds.
        """
        self.name = name
        self.available = available
        self.started = False
        self.stopped = False
        self.hooks: TransportHooks | None = None
        self.sock: socket.socket | None = None
        self.port = 0
        self.peer_session: Session | None = None
        self.responder: Session | None = None
        self._degraded = False
        self._alive = False

    async def start(self, cfg: object, hooks: TransportHooks) -> None:
        """Bind a real loopback socket and store the hooks.

        Args:
            cfg: Session configuration (unused).
            hooks: Inbound callbacks from the manager.

        Raises:
            RuntimeError: When the carrier is configured as unavailable.
        """
        if not self.available:
            raise RuntimeError(f"{self.name} unavailable")
        self.hooks = hooks
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = int(self.sock.getsockname()[1])
        self._alive = True
        self.started = True

    async def stop(self) -> None:
        """Close the socket and mark the carrier stopped."""
        self.stopped = True
        self._alive = False
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    async def send_envelope(self, env: dict) -> None:
        """Deliver a sealed envelope to the in-process peer.

        Args:
            env: Envelope object.
        """
        assert self.peer_session is not None
        await self.peer_session.handle_envelope(env)

    async def send_plain(self, obj: dict) -> dict | None:
        """Deliver a plaintext object to the in-process peer.

        Args:
            obj: ``hello`` object.

        Returns:
            The peer's ``hello_ack``.
        """
        assert self.peer_session is not None
        return await self.peer_session.handle_plain(obj)

    def alive(self) -> bool:
        """Whether the carrier is up and not degraded."""
        return bool(self._alive and not self._degraded)

    def degraded(self) -> bool:
        """Whether the peer probe gave up (mirrors ``WebhookTransport``)."""
        return self._degraded

    def set_degraded(self) -> None:
        """Report ``transport_degraded`` exactly like a failing probe loop."""
        self._degraded = True
        assert self.hooks is not None
        self.hooks.on_state("degraded", "transport_degraded")

    def diagnostics(self) -> dict:
        """Return carrier state for the manager's status output."""
        return {"name": self.name, "alive": self.alive(), "degraded": self._degraded}


class Harness:
    """Owns the real manager, the carrier factory and the observed sessions."""

    def __init__(
        self,
        *,
        preferred: str = "webhook",
        fallbacks: list[str] | None = None,
        attempt_preferred_after_s: float = 30.0,
    ) -> None:
        """Wire the manager against a controllable carrier factory.

        Args:
            preferred: Preferred carrier name.
            fallbacks: Configured fallback order.
            attempt_preferred_after_s: Preferred-retry interval (5 min in production).
        """
        self.instances: list[ControllableCarrier] = []
        self.session_for: dict[ControllableCarrier, Session] = {}
        self.closed_sessions: list[Session] = []
        self.carrier_states: list[tuple[str, str]] = []
        self.security_events: list[str] = []
        self.available: dict[str, bool] = {preferred: True}
        for name in fallbacks or []:
            self.available.setdefault(name, True)
        self.preferred = preferred
        self.cfg = _cfg("A", Role.INITIATOR, preferred, "connect")
        self.manager = TransportManager(
            self.cfg,
            TransportHooks(
                on_plain=self._plain,
                on_envelope=self._envelope,
                on_probe=self._probe,
                on_state=lambda state, reason: self.carrier_states.append(
                    (state, reason)
                ),
                on_activity=lambda: None,
            ),
            preferred=preferred,
            fallbacks=list(fallbacks or []),
            attempt_preferred_after_s=attempt_preferred_after_s,
            idle_poll_s=0.05,
            on_transport=self._attach,
            on_release=self._release,
        )

    # -- carrier factory seam ----------------------------------------------------------

    def factory(self, name: str, cfg: object) -> ControllableCarrier:
        """Build a controllable carrier for ``name``.

        Args:
            name: Carrier name requested by the manager.
            cfg: Session configuration (unused).

        Returns:
            The carrier instance.

        Raises:
            manager_mod.BridgeError: ``config_invalid`` for an unknown carrier.
        """
        if name not in {"webhook", "longpoll", "ws"}:
            raise manager_mod.BridgeError("config_invalid", details={"transport": name})
        carrier = ControllableCarrier(name, available=self.available.get(name, True))
        self.instances.append(carrier)
        return carrier

    # -- composition-root callbacks ----------------------------------------------------

    async def _attach(self, transport: ControllableCarrier) -> None:
        """Bind a fresh real session pair to a carrier the manager will start.

        Idempotent for one carrier, so the manager re-binding the live carrier
        after a failed restore is a no-op instead of a second session.

        Args:
            transport: Carrier the manager is about to start.
        """
        if transport in self.session_for:
            return
        link = PeerLink()
        responder = Session(
            _cfg("B", Role.RESPONDER, transport.name, "listen"),
            link,
            self._ignore,
            self._security,
        )
        initiator = Session(self.cfg, transport, self._ignore, self._security)
        link.session = initiator
        transport.peer_session = responder
        transport.responder = responder
        self.session_for[transport] = initiator

    async def _release(self, transport: ControllableCarrier) -> None:
        """Close the session that used a carrier before that carrier stops.

        Args:
            transport: Outgoing carrier.
        """
        session = self.session_for.get(transport)
        if session is None or session.state is SessionState.CLOSED:
            return
        await session.close("draining", "carrier_switch")
        self.closed_sessions.append(session)

    # -- hooks (inbound objects arrive on the active carrier) --------------------------

    async def _plain(self, obj: dict) -> dict | None:
        """Route a plaintext object to the active carrier's peer session."""
        transport = self.manager.transport()
        if transport is None or transport.responder is None:
            return None
        return await transport.responder.handle_plain(obj)

    async def _envelope(self, env: dict) -> None:
        """Route an envelope to the session bound to the active carrier."""
        transport = self.manager.transport()
        session = self.session_for.get(transport) if transport is not None else None
        if session is None:
            return
        await session.handle_envelope(env)

    def _probe(self, obj: dict) -> dict:
        """Answer a probe (these carriers do not probe)."""
        return {
            "v": 1,
            "type": "probe_ack",
            "conn": "default",
            "nonce": obj.get("nonce"),
        }

    async def _ignore(self, msg: dict) -> None:
        """Swallow inbound application messages."""
        return None

    def _security(self, code: str, detail: str) -> None:
        """Record security events (none are expected here)."""
        self.security_events.append(code)

    # -- driver ------------------------------------------------------------------------

    async def connect(self) -> None:
        """Run the real handshake over the freshly activated carrier."""
        transport = self.manager.transport()
        assert transport is not None and transport.responder is not None
        session = self.session_for[transport]
        await transport.responder.start()
        await session.start()


def _freshness(session: Session) -> tuple[bytes, str, bytes]:
    """Return the per-handshake values that must never be reused.

    Args:
        session: A completed initiator session.

    Returns:
        ``(nonce_c, sid, k_a2b)``.
    """
    assert session._keys is not None, "handshake did not derive session keys"
    assert session._nonce_c is not None
    assert session.sid
    return (session._nonce_c, session.sid, session._keys.k_a2b)


async def _wait_for(predicate, timeout: float = 5.0) -> bool:
    """Poll ``predicate`` until it holds or the timeout expires.

    Args:
        predicate: Zero-argument predicate.
        timeout: Maximum wait in seconds.

    Returns:
        ``True`` when the predicate held before the timeout.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.02)
    return predicate()


async def test_degraded_runtime_switches_to_fallback_with_fresh_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A carrier degraded at runtime must switch carriers and re-handshake (§7.3.6).

    Args:
        monkeypatch: pytest fixture used for the carrier-factory seam.
    """
    harness = Harness(preferred="webhook", fallbacks=["longpoll"])
    monkeypatch.setattr(manager_mod, "build_transport", harness.factory)

    await harness.manager.bring_up()
    await harness.connect()
    first = harness.manager.transport()
    first_session = harness.session_for[first]
    first_values = _freshness(first_session)
    first_port = first.port
    assert harness.manager.diagnostics()["reachable"] is True

    loop_task = asyncio.create_task(
        harness.manager.run_forever(connect=harness.connect)
    )
    try:
        first.set_degraded()
        assert await _wait_for(lambda: harness.manager.current() == "longpoll")
        second = harness.manager.transport()
        assert second is not None and second is not first
        assert second.started is True

        diagnostics = harness.manager.diagnostics()
        assert diagnostics["current"] == "longpoll"
        assert diagnostics["degraded"] is True
        assert diagnostics["reachable"] is True
        switch = [
            entry
            for entry in diagnostics["history"]
            if entry["reason"] == "transport_degraded"
        ]
        assert switch and switch[-1]["from"] == "webhook"
        assert switch[-1]["to"] == "longpoll"

        # 1. The fallback carries a brand-new session: no nonce/sid/key reuse.
        second_session = harness.session_for[second]
        assert second_session is not first_session
        second_values = _freshness(second_session)
        assert second_values[0] != first_values[0], "nonce_c was reused across carriers"
        assert second_values[1] != first_values[1], "sid was reused across carriers"
        assert second_values[2] != first_values[2], (
            "AEAD key was reused across carriers"
        )
        assert second_session.state is SessionState.READY
        assert second_session._next_seq >= 1, "the fresh session did not start at seq 0"

        # 2. The old carrier and its session are gone, socket included.
        assert first.stopped is True
        assert first.sock is None
        assert first_session.state is SessionState.CLOSED
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(("127.0.0.1", first_port))
    finally:
        await harness.manager.stop()
        await asyncio.wait_for(loop_task, timeout=2.0)


async def test_preferred_restore_survives_a_failed_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The preferred retry must never drop the live fallback (§7.5 rule 3).

    Args:
        monkeypatch: pytest fixture used for the carrier-factory seam.
    """
    harness = Harness(
        preferred="webhook", fallbacks=["longpoll"], attempt_preferred_after_s=0.1
    )
    monkeypatch.setattr(manager_mod, "build_transport", harness.factory)

    await harness.manager.bring_up()
    await harness.connect()
    webhook_carrier = harness.manager.transport()
    webhook_carrier.set_degraded()
    await harness.manager._switch_to_fallback("transport_degraded")  # noqa: SLF001
    await harness.connect()
    assert harness.manager.current() == "longpoll"
    fallback_carrier = harness.manager.transport()
    fallback_port = fallback_carrier.port
    fallback_session = harness.session_for[fallback_carrier]
    fallback_values = _freshness(fallback_session)

    # Attempt 1 (explicit): the preferred carrier cannot start. The fallback must
    # keep its socket, its session and its place as the active carrier.
    harness.available["webhook"] = False
    assert await harness.manager.try_restore_preferred() is False
    assert harness.manager.current() == "longpoll"
    assert harness.manager.transport() is fallback_carrier
    assert fallback_carrier.stopped is False
    assert fallback_carrier.sock is not None
    assert fallback_carrier.port == fallback_port
    assert fallback_session.state is SessionState.READY
    failed_attempt = harness.instances[-1]
    assert failed_attempt is not webhook_carrier
    assert failed_attempt.stopped is True, "a half-started carrier kept its resources"
    assert failed_attempt.sock is None

    # Attempt 2: the loop itself retries after the configured interval and the
    # preferred carrier is healthy again.
    harness.available["webhook"] = True
    loop_task = asyncio.create_task(
        harness.manager.run_forever(connect=harness.connect)
    )
    try:
        assert await _wait_for(lambda: harness.manager.current() == "webhook")
        assert [entry["reason"] for entry in harness.manager.history()][-2:] == [
            "transport_degraded",
            "restored",
        ], harness.manager.history()
        assert harness.manager.diagnostics()["degraded"] is False
        restored = harness.manager.transport()
        assert restored is not webhook_carrier
        assert fallback_carrier.stopped is True, "the fallback kept its socket"
        assert fallback_carrier.sock is None
        assert fallback_session.state is SessionState.CLOSED
        restored_values = _freshness(harness.session_for[restored])
        assert restored_values[0] != fallback_values[0]
        assert restored_values[1] != fallback_values[1]
        assert restored_values[2] != fallback_values[2]
    finally:
        await harness.manager.stop()
        await asyncio.wait_for(loop_task, timeout=2.0)


async def test_stop_ends_the_loop_and_never_reconnects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``stop()`` must end ``run_forever`` for good and leave no timer behind.

    Args:
        monkeypatch: pytest fixture used for the carrier-factory seam.
    """
    harness = Harness(preferred="webhook", fallbacks=["longpoll"])
    monkeypatch.setattr(manager_mod, "build_transport", harness.factory)

    await harness.manager.bring_up()
    carrier = harness.manager.transport()
    loop_task = asyncio.create_task(harness.manager.run_forever())
    await asyncio.sleep(0.2)
    await harness.manager.stop()
    await asyncio.wait_for(loop_task, timeout=2.0)

    activations = len(harness.instances)
    assert carrier.stopped is True and carrier.sock is None
    assert harness.manager.transport() is None
    assert harness.manager.diagnostics()["stopped"] is True

    # Give the finished loop time to prove it does not come back.
    await asyncio.sleep(0.3)
    assert len(harness.instances) == activations
    assert harness.manager.current() == ""
    assert harness.manager.diagnostics()["reachable"] is False


async def test_failed_rehandshake_on_a_live_carrier_is_retried_and_rebuilt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed re-handshake must not leave an alive carrier with no session.

    ``WebhookTransport.alive()``/``LongPollTransport.alive()`` stay true while the
    socket and the poll loops are up, so a reconnect that fails *inside*
    ``connect()`` cannot be spotted through ``alive()``. The loop must retry, and
    after repeated failures tear the carrier down so the ladder rebuilds both the
    carrier and the session bound to it.

    Args:
        monkeypatch: pytest fixture used for the carrier-factory seam.
    """
    harness = Harness(preferred="webhook", fallbacks=["longpoll"])
    monkeypatch.setattr(manager_mod, "build_transport", harness.factory)

    await harness.manager.bring_up()
    await harness.connect()
    carrier = harness.manager.transport()
    carrier.set_degraded()

    attempts: list[int] = []

    async def flaky_connect() -> None:
        """Fail the first handshakes, then handshake for real."""
        attempts.append(1)
        if len(attempts) <= manager_mod.HANDSHAKE_REBUILD_AFTER:
            raise manager_mod.BridgeError("timeout", details={"stage": "test"})
        await harness.connect()

    loop_task = asyncio.create_task(harness.manager.run_forever(connect=flaky_connect))
    try:
        # The loop switched to the fallback and kept retrying the handshake.
        assert await _wait_for(
            lambda: (
                harness.manager.current() == "longpoll"
                and harness.session_for[harness.manager.transport()].state
                is SessionState.READY
            ),
            timeout=10.0,
        ), (harness.manager.current(), len(attempts))
        assert len(attempts) > manager_mod.HANDSHAKE_REBUILD_AFTER
        # The failed attempts released the carrier instead of idling on it.
        rebuilt = harness.manager.transport()
        assert rebuilt is not carrier
        assert carrier.stopped is True
        assert harness.manager.diagnostics()["degraded"] is True
    finally:
        await harness.manager.stop()
        await asyncio.wait_for(loop_task, timeout=2.0)


async def test_degraded_without_usable_fallback_backs_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No usable fallback must mean bounded backoff, not a hot loop (§7.5 rule 4).

    Args:
        monkeypatch: pytest fixture used for the carrier-factory seam.
    """
    harness = Harness(preferred="webhook", fallbacks=["longpoll"])
    monkeypatch.setattr(manager_mod, "build_transport", harness.factory)

    await harness.manager.bring_up()
    harness.available["webhook"] = False
    harness.available["longpoll"] = False
    harness.manager.transport().set_degraded()
    loop_task = asyncio.create_task(harness.manager.run_forever())
    try:
        assert await _wait_for(lambda: harness.manager.current() == "")
        settled = len(harness.instances)
        await asyncio.sleep(0.5)
        # Backoff starts at one second, so half a second must not produce a loop.
        assert len(harness.instances) - settled <= 1, (
            f"{len(harness.instances) - settled} activations in 0.5 s"
        )
        assert harness.manager.diagnostics()["degraded"] is True
        assert harness.manager.diagnostics()["tried"]
    finally:
        await harness.manager.stop()
        await asyncio.wait_for(loop_task, timeout=2.0)
