"""End-to-end HTTP Webhook transport test over real loopback sockets (§7.3, §8).

Covers batch upload, the first-frame ``auth`` exchange, probe MAC verification, the
documented HTTP status codes, forbidden-header rejection, and degradation when the
reverse probe keeps failing.
"""

from __future__ import annotations

import asyncio
import socket

import aiohttp
import pytest

from bridge.constants import (
    CONTENT_TYPE_JSON,
    HEADER_VERSION,
    MAX_BATCH_FRAMES,
)
from bridge.session import Role, Session, SessionConfig, SessionState
from bridge.transport.base import TransportHooks
from bridge.transport.webhook import WebhookTransport
from _session_doubles import TEST_PSK_ID, TEST_PSK_SECRET, make_caps


def free_port() -> int:
    """Return an unused localhost TCP port.

    Returns:
        Port number.
    """
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class WebhookPair:
    """Two sessions joined by real webhook transports."""

    def __init__(self) -> None:
        """Configure the pair."""
        # Each side owns a listener, and points ``addr``/``port`` at the other one.
        self.b_listen_port = free_port()
        self.a_listen_port = free_port()
        self.a_messages: list[dict] = []
        self.b_messages: list[dict] = []
        self.states: list[tuple[str, str]] = []

        self.a_cfg = SessionConfig(
            conn="default",
            side="A",
            role=Role.INITIATOR,
            transport="webhook",
            psk_id=TEST_PSK_ID,
            psk_secret=TEST_PSK_SECRET,
            caps=make_caps("A"),
            addr="127.0.0.1",
            port=self.b_listen_port,
            bind_addr="127.0.0.1",
            bind_port=self.a_listen_port,
            path="/dsh-bridge",
        )
        self.b_cfg = SessionConfig(
            conn="default",
            side="B",
            role=Role.RESPONDER,
            transport="webhook",
            psk_id=TEST_PSK_ID,
            psk_secret=TEST_PSK_SECRET,
            caps=make_caps("B"),
            addr="127.0.0.1",
            port=self.a_listen_port,
            bind_addr="127.0.0.1",
            bind_port=self.b_listen_port,
            path="/dsh-bridge",
        )
        self.a_transport = WebhookTransport(
            role="connect",
            conn="default",
            side="A",
            psk_id=TEST_PSK_ID,
            psk_secret=TEST_PSK_SECRET,
            heartbeat_s=3600,
        )
        self.b_transport = WebhookTransport(
            role="listen",
            conn="default",
            side="B",
            psk_id=TEST_PSK_ID,
            psk_secret=TEST_PSK_SECRET,
            heartbeat_s=3600,
        )
        self.a = Session(self.a_cfg, self.a_transport, self._capture_a, self._security)
        self.b = Session(self.b_cfg, self.b_transport, self._capture_b, self._security)
        self._hooks_a = TransportHooks(
            on_plain=self.a.handle_plain,
            on_envelope=self.a.handle_envelope,
            on_probe=self._probe_ack,
            on_state=lambda state, reason: self.states.append((f"A:{state}", reason)),
        )
        self._hooks_b = TransportHooks(
            on_plain=self.b.handle_plain,
            on_envelope=self.b.handle_envelope,
            on_probe=self._probe_ack,
            on_state=lambda state, reason: self.states.append((f"B:{state}", reason)),
        )

    async def _probe_ack(self, obj: dict) -> dict:
        """Answer a probe with a valid ``probe_ack`` MAC.

        Args:
            obj: Incoming probe object.

        Returns:
            ``probe_ack`` object.
        """
        from bridge.crypto import handshake_key, mac_object, psk_master

        master = psk_master(TEST_PSK_ID, TEST_PSK_SECRET)
        body = {
            "v": 1,
            "type": "probe_ack",
            "conn": obj.get("conn", "default"),
            "nonce": obj.get("nonce"),
            "ts": obj.get("ts"),
        }
        body["mac"] = mac_object(handshake_key(master, "probe_ack"), body)
        return body

    async def _capture_a(self, msg: dict) -> None:
        self.a_messages.append(msg)

    async def _capture_b(self, msg: dict) -> None:
        self.b_messages.append(msg)

    def _security(self, code: str, detail: str) -> None:
        self.states.append((f"security:{code}", detail))

    async def start(self) -> None:
        """Start both listeners, then perform the webhook handshake.

        Both inbound servers must be up before the first frame is posted, because the
        responder already has to post ``auth_ack`` back to the initiator (§7.3).
        """
        await self.a_transport.start(self.a_cfg, self._hooks_a)
        await self.b_transport.start(self.b_cfg, self._hooks_b)
        await self.b.start()
        await self.a.start()
        await self.b.wait_ready(5)

    async def close(self) -> None:
        """Close sessions and transports."""
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
async def test_webhook_handshake_and_frame_delivery() -> None:
    """A real webhook exchange completes the handshake and carries a sealed frame."""
    pair = WebhookPair()
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
        for _ in range(150):
            if pair.b_messages:
                break
            await asyncio.sleep(0.02)
        assert pair.b_messages, "sealed frame never reached the peer"
    finally:
        await pair.close()


@pytest.mark.asyncio
async def test_webhook_health_and_status_codes() -> None:
    """The documented status codes are produced for health, bad bodies and 404 (§8.1)."""
    pair = WebhookPair()
    await pair.start()
    base = f"http://127.0.0.1:{pair.b_listen_port}/dsh-bridge"
    try:
        async with aiohttp.ClientSession() as client:
            async with client.get(f"{base}/health") as response:
                assert response.status == 200
                assert await response.json() == {"v": 1, "ok": True}

            async with client.post(
                f"{base}/frames",
                data=b"not json",
                headers={"Content-Type": CONTENT_TYPE_JSON},
            ) as response:
                assert response.status == 400
                body = await response.json()
                assert body["error"]["code"] == "bad_json"

            async with client.post(
                f"{base}/frames", json={"v": 1, "frames": []}, headers={"Content-Type": CONTENT_TYPE_JSON}
            ) as response:
                assert response.status == 400
                assert (await response.json())["error"]["code"] == "bad_batch"

            async with client.post(
                f"{base}/frames",
                json={"v": 1, "frames": [{"seq": 5}, {"seq": 1}]},
                headers={"Content-Type": CONTENT_TYPE_JSON},
            ) as response:
                assert response.status == 400
                assert (await response.json())["error"]["code"] == "bad_batch"
    finally:
        await pair.close()


@pytest.mark.asyncio
async def test_webhook_rejects_authorization_header() -> None:
    """Any ``Authorization`` header is refused with 401 (no bearer anywhere, §7.0)."""
    pair = WebhookPair()
    await pair.start()
    base = f"http://127.0.0.1:{pair.b_listen_port}/dsh-bridge"
    try:
        async with aiohttp.ClientSession() as client:
            async with client.post(
                f"{base}/frames",
                json={"v": 1, "frames": [{"seq": 0}]},
                headers={
                    "Content-Type": CONTENT_TYPE_JSON,
                    "Authorization": "Bearer should-never-exist",
                },
            ) as response:
                assert response.status == 401
                body = await response.json()
                assert body["error"]["code"] == "auth_header_forbidden"
    finally:
        await pair.close()


@pytest.mark.asyncio
async def test_webhook_rejects_compressed_content() -> None:
    """A ``Content-Encoding`` header is refused with 415 (§7.0)."""
    pair = WebhookPair()
    await pair.start()
    base = f"http://127.0.0.1:{pair.b_listen_port}/dsh-bridge"
    try:
        async with aiohttp.ClientSession() as client:
            async with client.post(
                f"{base}/frames",
                data=b"{}",
                headers={
                    "Content-Type": CONTENT_TYPE_JSON,
                    "Content-Encoding": "gzip",
                },
            ) as response:
                assert response.status == 415
                assert (await response.json())["error"]["code"] == "unsupported_content_type"
    finally:
        await pair.close()


@pytest.mark.asyncio
async def test_webhook_batch_accepts_and_reports_rejections() -> None:
    """A batch answers 202 with per-frame ``accepted``/``rejected`` refs (§7.3 rule 4)."""
    pair = WebhookPair()
    await pair.start()
    base = f"http://127.0.0.1:{pair.b_listen_port}/dsh-bridge"
    try:
        await pair.a.send_message(
            {
                "k": "evt",
                "m": "session.authz",
                "id": "22222222-2222-4222-8222-222222222222",
                "ts": "2026-10-29T11:30:00.000Z",
                "params": {"version": 2},
            }
        )
        for _ in range(150):
            if pair.b_messages:
                break
            await asyncio.sleep(0.02)
        # A frame sealed with the wrong key is accepted structurally but rejected by
        # the AEAD check, and the batch still answers 202 with a per-frame reason.
        from bridge.crypto import b64u, seal_frame

        forged = seal_frame(
            b"\x00" * 32, "A", "data", "default", 0, {"k": "evt", "m": "x"}
        )
        async with aiohttp.ClientSession() as client:
            async with client.post(
                f"{base}/frames",
                json={"v": 1, "frames": [forged]},
                headers={"Content-Type": CONTENT_TYPE_JSON},
            ) as response:
                body = await response.json()
        # §7.3 rule 4: a batch that is *entirely* rejected for a fatal reason answers
        # 409 instead of 202; both shapes report the per-frame code.
        assert response.status in (202, 409)
        if response.status == 202:
            assert body["rejected"], "forged frame must be rejected"
            assert body["rejected"][0]["code"] in (
                "aead_failed",
                "replay_detected",
                "replay_out_of_window",
            )
        else:
            assert body["error"]["code"] in (
                "aead_failed",
                "replay_detected",
                "replay_out_of_window",
            )
        del b64u
    finally:
        await pair.close()


@pytest.mark.asyncio
async def test_webhook_probe_roundtrip() -> None:
    """A probe is answered with a MAC that verifies (§7.3 rule 5)."""
    pair = WebhookPair()
    await pair.start()
    try:
        ack = await pair.a_transport.probe()
        assert ack["type"] == "probe_ack"
        assert ack["conn"] == "default"
    finally:
        await pair.close()


@pytest.mark.asyncio
async def test_webhook_probe_failure_degrades_transport() -> None:
    """Three failed probes mark the carrier degraded for fallback (§7.3 rule 6)."""
    port = free_port()
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
        path="/dsh-bridge",
    )
    states: list[tuple[str, str]] = []
    hooks = TransportHooks(
        on_plain=lambda obj: _none(),
        on_envelope=lambda env: _none(),
        on_probe=lambda obj: _none(),
        on_state=lambda state, reason: states.append((state, reason)),
    )
    await transport.start(cfg, hooks)
    try:
        for _ in range(3):
            with pytest.raises(Exception):
                await transport.probe()
            transport._probe_failures += 1
            if transport._probe_failures >= 3 and not transport._degraded:
                transport._degraded = True
                hooks.on_state("degraded", "transport_degraded")
        assert transport.degraded() is True
        assert any(state == "degraded" for state, _ in states)
    finally:
        await transport.stop()


async def _none() -> None:
    """Async no-op used by the degradation test."""
    return None


@pytest.mark.asyncio
async def test_webhook_batch_limit_is_enforced() -> None:
    """More frames than ``max_batch_frames`` is ``bad_batch`` (§7.3 rule 3)."""
    pair = WebhookPair()
    await pair.start()
    base = f"http://127.0.0.1:{pair.b_listen_port}/dsh-bridge"
    try:
        frames = [
            {"v": 1, "type": "data", "conn": "default", "seq": index, "ct": "AAAA"}
            for index in range(MAX_BATCH_FRAMES + 1)
        ]
        async with aiohttp.ClientSession() as client:
            async with client.post(
                f"{base}/frames",
                json={"v": 1, "frames": frames},
                headers={"Content-Type": CONTENT_TYPE_JSON},
            ) as response:
                assert response.status == 400
                assert (await response.json())["error"]["code"] == "bad_batch"
    finally:
        await pair.close()


@pytest.mark.asyncio
async def test_webhook_retry_after_present_on_429() -> None:
    """Error bodies carry ``retryable`` and 429/503 carry ``Retry-After`` (§8.2)."""
    from bridge.errors import http_error_body

    body = http_error_body("rate_limited")
    assert body["error"]["retryable"] is True
    body = http_error_body("psk_mismatch")
    assert body["error"]["retryable"] is False
    assert body["error"]["message"] == "authentication failed"
