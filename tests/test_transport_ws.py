"""End-to-end WebSocket transport test over a real loopback socket (§7.2).

Two real sessions handshake through :class:`bridge.transport.ws.WsTransport` on
localhost, exchange sealed frames and then close cleanly. Nothing is mocked.
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import replace

import pytest

from bridge.constants import WS_SUBPROTOCOL
from bridge.errors import BridgeError
from bridge.session import Role, Session, SessionConfig, SessionState
from bridge.transport.base import TransportHooks
from bridge.transport.ws import WsTransport
from _session_doubles import TEST_PSK_ID, TEST_PSK_SECRET, make_caps


def free_port() -> int:
    """Return an unused localhost TCP port.

    Returns:
        Port number.
    """
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class WsPair:
    """Two sessions joined by real WebSocket transports."""

    def __init__(self, port: int) -> None:
        """Configure the pair.

        Args:
            port: Port for the listening side.
        """
        self.port = port
        self.a_messages: list[dict] = []
        self.b_messages: list[dict] = []
        self.states: list[tuple[str, str]] = []

        def hooks_a() -> TransportHooks:
            return TransportHooks(
                on_plain=self._a_plain,
                on_envelope=self._a_envelope,
                on_probe=self._probe,
                on_state=lambda state, reason: self.states.append((f"A:{state}", reason)),
            )

        def hooks_b() -> TransportHooks:
            return TransportHooks(
                on_plain=self._b_plain,
                on_envelope=self._b_envelope,
                on_probe=self._probe,
                on_state=lambda state, reason: self.states.append((f"B:{state}", reason)),
            )

        self.a_transport = WsTransport(role="connect", conn="default")
        self.b_transport = WsTransport(role="listen", conn="default")
        self.a_cfg = SessionConfig(
            conn="default",
            side="A",
            role=Role.INITIATOR,
            transport="ws",
            psk_id=TEST_PSK_ID,
            psk_secret=TEST_PSK_SECRET,
            caps=make_caps("A"),
        )
        self.b_cfg = SessionConfig(
            conn="default",
            side="B",
            role=Role.RESPONDER,
            transport="ws",
            psk_id=TEST_PSK_ID,
            psk_secret=TEST_PSK_SECRET,
            caps=make_caps("B"),
        )
        self.a = Session(self.a_cfg, self.a_transport, self._capture_a, self._security)
        self.b = Session(self.b_cfg, self.b_transport, self._capture_b, self._security)
        self._hooks_a = hooks_a()
        self._hooks_b = hooks_b()

    async def _a_plain(self, obj: dict) -> dict | None:
        return await self.a.handle_plain(obj)

    async def _b_plain(self, obj: dict) -> dict | None:
        return await self.b.handle_plain(obj)

    async def _a_envelope(self, env: dict) -> None:
        await self.a.handle_envelope(env)

    async def _b_envelope(self, env: dict) -> None:
        await self.b.handle_envelope(env)

    async def _probe(self, obj: dict) -> dict:
        return {"v": 1, "type": "probe_ack", "conn": "default", "nonce": obj.get("nonce")}

    async def _capture_a(self, msg: dict) -> None:
        self.a_messages.append(msg)

    async def _capture_b(self, msg: dict) -> None:
        self.b_messages.append(msg)

    def _security(self, code: str, detail: str) -> None:
        self.states.append((f"security:{code}", detail))

    async def start(self, *, port_override: int | None = None) -> None:
        """Bring up the listener and connect the client.

        Args:
            port_override: Optional listener port override.
        """
        port = port_override or self.port
        self.b_cfg = replace(self.b_cfg, addr="127.0.0.1", port=port, path="/dsh-bridge")
        self.a_cfg = replace(self.a_cfg, addr="127.0.0.1", port=port, path="/dsh-bridge")
        self.b = Session(self.b_cfg, self.b_transport, self._capture_b, self._security)
        self.a = Session(self.a_cfg, self.a_transport, self._capture_a, self._security)
        await self.b_transport.start(self.b_cfg, self._hooks_b)
        await self.b.start()
        await self.a_transport.start(self.a_cfg, self._hooks_a)
        await self.a_transport.wait_ready(5)
        await self.a.start()
        await self.b.wait_ready(5)

    async def close(self) -> None:
        """Close both sessions and transports."""
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


@pytest.mark.asyncio
async def test_ws_handshake_and_frame_delivery() -> None:
    """A real WS connection completes the handshake and carries a sealed frame."""
    pair = WsPair(free_port())
    await pair.start()
    try:
        assert pair.a.state is SessionState.READY
        assert pair.b.state is SessionState.READY
        assert pair.a.sid == pair.b.sid
        await pair.a.send_message(
            {
                "k": "evt",
                "m": "session.authz",
                "id": "11111111-1111-4111-8111-111111111111",
                "ts": "2026-10-29T11:30:00.000Z",
                "params": {"version": 1, "grants": [], "revoked": []},
            }
        )
        for _ in range(100):
            if pair.b_messages:
                break
            await asyncio.sleep(0.02)
        assert pair.b_messages
        assert pair.b_messages[0]["m"] == "session.authz"
        assert any(state.startswith("B:ready") for state, _ in pair.states)
    finally:
        await pair.close()


@pytest.mark.asyncio
async def test_ws_subprotocol_is_negotiated() -> None:
    """The accepted socket uses the ``dsh-bridge.v1`` subprotocol (§7.2 rule 1)."""
    pair = WsPair(free_port())
    await pair.start()
    try:
        negotiated = getattr(pair.a_transport._ws, "protocol", None) or getattr(
            pair.a_transport._ws, "ws_protocol", None
        )
        assert negotiated == WS_SUBPROTOCOL
        assert pair.a_transport.diagnostics()["subprotocol"] == WS_SUBPROTOCOL
    finally:
        await pair.close()


@pytest.mark.asyncio
async def test_ws_rejects_wrong_psk() -> None:
    """A PSK mismatch aborts the handshake over the real socket."""
    port = free_port()
    pair = WsPair(port)
    pair.a_cfg = replace(pair.a_cfg, psk_secret="wrong-secret")
    # The listener rejects the ``hello`` and closes the socket; the client observes
    # either the peer's ``psk_mismatch`` or a dropped connection.
    with pytest.raises(BridgeError) as excinfo:
        await pair.start()
    assert excinfo.value.code in ("psk_mismatch", "timeout")
    assert pair.b.state is not SessionState.READY
    await pair.close()


@pytest.mark.asyncio
async def test_ws_health_endpoint_has_no_secrets() -> None:
    """``GET {base}/health`` answers ``{"v":1,"ok":true}`` with no configuration (§7.0)."""
    import aiohttp

    port = free_port()
    pair = WsPair(port)
    await pair.start()
    try:
        async with aiohttp.ClientSession() as client:
            async with client.get(f"http://127.0.0.1:{port}/dsh-bridge/health") as response:
                assert response.status == 200
                body = await response.json()
        assert body == {"v": 1, "ok": True}
    finally:
        await pair.close()


@pytest.mark.asyncio
async def test_ws_diagnostics_report_alive() -> None:
    """Diagnostics expose liveness without secrets."""
    pair = WsPair(free_port())
    await pair.start()
    try:
        diagnostics = pair.a_transport.diagnostics()
        assert diagnostics["alive"] is True
        assert "psk" not in str(diagnostics).lower()
    finally:
        await pair.close()
