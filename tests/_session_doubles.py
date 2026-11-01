"""Test doubles for the session/transport tests.

``FakeTransport`` links two sessions in-process so the four-step handshake and the
sealed-frame exchange can be exercised without sockets. It is deliberately dumb:
it only moves bytes, exactly like a real carrier (§7.0).
"""

from __future__ import annotations

import asyncio
from typing import Any

from bridge.session import (
    Role,
    Session,
    SessionConfig,
    SessionState,
    build_caps,
)

#: Deterministic test PSK. Never a real credential.
TEST_PSK_ID = "test-conn"
TEST_PSK_SECRET = "test-only-psk-secret-not-real"


def make_caps(side: str, *, native_tool: bool = False) -> dict:
    """Build a caps object for tests.

    Args:
        side: ``"A"`` or ``"B"``.
        native_tool: Whether native tool approvals are advertised.

    Returns:
        Caps dictionary.
    """
    return build_caps(
        side=side,
        host="astrbot" if side == "A" else "dsh",
        version="0.1.0",
        transports=["longpoll", "webhook", "ws"],
        tls=False,
        native_tool=native_tool,
        image_enabled=True,
        image_max_count=4,
        image_max_bytes=10_485_760,
        image_total_max_bytes=20_971_520,
    )


class FakeTransport:
    """In-memory transport linking one session to its peer."""

    def __init__(self, role: Role, *, transport: str = "ws") -> None:
        """Create the transport.

        Args:
            role: Role this transport serves; drives plain-object routing.
            transport: Carrier name advertised in ``hello.tp``.
        """
        self.role = role
        self.name = transport
        self.peer_session: Session | None = None
        self.sent_envelopes: list[dict] = []
        self.sent_plain: list[dict] = []
        self.started = False
        self.stopped = False
        self.fail_on_send: Exception | None = None

    async def start(self, cfg: SessionConfig, hooks: Any) -> None:
        """Mark the transport as started.

        Args:
            cfg: Session configuration (unused by the fake).
            hooks: Transport hooks (unused by the fake).
        """
        self.started = True

    async def stop(self) -> None:
        """Mark the transport as stopped."""
        self.stopped = True

    async def send_plain(self, obj: dict) -> dict | None:
        """Deliver a plaintext handshake object to the peer.

        Args:
            obj: ``hello`` object.

        Returns:
            The peer's ``hello_ack``, if the peer is a responder.
        """
        self.sent_plain.append(obj)
        if self.peer_session is None:
            return None
        return await self.peer_session.handle_plain(obj)

    async def send_envelope(self, env: dict) -> None:
        """Deliver a sealed envelope to the peer.

        Args:
            env: Envelope object.

        Raises:
            Exception: Re-raises ``fail_on_send`` when set, to simulate a dead link.
        """
        if self.fail_on_send is not None:
            raise self.fail_on_send
        self.sent_envelopes.append(env)
        if self.peer_session is None:
            return
        await self.peer_session.handle_envelope(env)

    def alive(self) -> bool:
        """Whether the fake link is usable."""
        return not self.stopped


class SessionPair:
    """Two linked sessions (A as initiator, B as responder) plus message capture."""

    def __init__(
        self,
        *,
        conn: str = "default",
        native_tool_b: bool = False,
        psk_b: str = TEST_PSK_SECRET,
    ) -> None:
        """Create the pair.

        Args:
            conn: Connection identifier shared by both sides.
            native_tool_b: Whether B advertises native tool approvals.
            psk_b: PSK secret used by the responder; differs to test mismatches.
        """
        self.conn = conn
        self.security_events: list[tuple[str, str]] = []
        self.a_messages: list[dict] = []
        self.b_messages: list[dict] = []

        self.a_cfg = SessionConfig(
            conn=conn,
            side="A",
            role=Role.INITIATOR,
            transport="ws",
            psk_id=TEST_PSK_ID,
            psk_secret=TEST_PSK_SECRET,
            caps=make_caps("A"),
        )
        self.b_cfg = SessionConfig(
            conn=conn,
            side="B",
            role=Role.RESPONDER,
            transport="ws",
            psk_id=TEST_PSK_ID,
            psk_secret=psk_b,
            caps=make_caps("B", native_tool=native_tool_b),
        )
        self.a_transport = FakeTransport(Role.INITIATOR)
        self.b_transport = FakeTransport(Role.RESPONDER)

        self.a = Session(
            self.a_cfg,
            self.a_transport,
            self._capture_a,
            self._on_security,
        )
        self.b = Session(
            self.b_cfg,
            self.b_transport,
            self._capture_b,
            self._on_security,
        )
        self.a_transport.peer_session = self.b
        self.b_transport.peer_session = self.a

    async def _capture_a(self, msg: dict) -> None:
        """Record messages received by A."""
        self.a_messages.append(msg)

    async def _capture_b(self, msg: dict) -> None:
        """Record messages received by B."""
        self.b_messages.append(msg)

    def _on_security(self, code: str, detail: str) -> None:
        """Record security events."""
        self.security_events.append((code, detail))

    async def handshake(self) -> None:
        """Run the four-step handshake to ``ready`` on both sides."""
        await self.b.start()
        await self.a.start()
        assert self.a.state is SessionState.READY
        assert self.b.state is SessionState.READY

    async def close(self) -> None:
        """Close both sessions, suppressing errors."""
        for session in (self.a, self.b):
            try:
                await session.close("draining", "test_done")
            except Exception:
                pass


async def settle(rounds: int = 3) -> None:
    """Yield control a few times so cross-session sends complete.

    Args:
        rounds: Number of event loop turns to yield.
    """
    for _ in range(rounds):
        await asyncio.sleep(0)
