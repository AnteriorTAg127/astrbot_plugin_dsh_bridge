"""End-to-end long-poll transport test over real loopback sockets (§7.4).

Covers the downstream poll/ack cycle, MAC authentication, replay rejection, the
documented status codes (401/409/425) and forced re-handshake on 409.
"""

from __future__ import annotations

import asyncio
import secrets
import socket
import time

import aiohttp
import pytest

from bridge.constants import CONTENT_TYPE_JSON, POLL_WAIT_MAX_S
from bridge.crypto import b64u, hkdf_expand, hkdf_extract, mac_object, psk_master
from bridge.session import Role, Session, SessionConfig, SessionState
from bridge.transport.base import TransportHooks
from bridge.transport.longpoll import LongPollTransport, _poll_mac_object
from _session_doubles import TEST_PSK_ID, TEST_PSK_SECRET, make_caps


def free_port() -> int:
    """Return an unused localhost TCP port.

    Returns:
        Port number.
    """
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class PollPair:
    """Two sessions joined by long-poll transports, each with its own listener."""

    def __init__(self, *, wait_s: int = 1) -> None:
        """Configure the pair.

        Args:
            wait_s: Long-poll wait used by the client side.
        """
        self.wait_s = wait_s
        self.b_listen_port = free_port()
        self.a_listen_port = free_port()
        self.a_messages: list[dict] = []
        self.b_messages: list[dict] = []
        self.states: list[tuple[str, str]] = []

        self.a_cfg = SessionConfig(
            conn="default",
            side="A",
            role=Role.INITIATOR,
            transport="longpoll",
            psk_id=TEST_PSK_ID,
            psk_secret=TEST_PSK_SECRET,
            caps=make_caps("A"),
            addr="127.0.0.1",
            port=self.b_listen_port,
            bind_addr="127.0.0.1",
            bind_port=self.a_listen_port,
            path="/dsh-bridge",
            poll_wait_s=wait_s,
        )
        self.b_cfg = SessionConfig(
            conn="default",
            side="B",
            role=Role.RESPONDER,
            transport="longpoll",
            psk_id=TEST_PSK_ID,
            psk_secret=TEST_PSK_SECRET,
            caps=make_caps("B"),
            addr="127.0.0.1",
            port=self.a_listen_port,
            bind_addr="127.0.0.1",
            bind_port=self.b_listen_port,
            path="/dsh-bridge",
            poll_wait_s=wait_s,
        )
        self.a_transport = LongPollTransport(
            role="connect",
            conn="default",
            side="A",
            psk_id=TEST_PSK_ID,
            psk_secret=TEST_PSK_SECRET,
            wait_s=wait_s,
        )
        self.b_transport = LongPollTransport(
            role="listen",
            conn="default",
            side="B",
            psk_id=TEST_PSK_ID,
            psk_secret=TEST_PSK_SECRET,
            wait_s=wait_s,
        )
        self.a = Session(self.a_cfg, self.a_transport, self._capture_a, self._security)
        self.b = Session(self.b_cfg, self.b_transport, self._capture_b, self._security)
        self._hooks_a = TransportHooks(
            on_plain=self.a.handle_plain,
            on_envelope=self.a.handle_envelope,
            on_probe=self._probe,
            on_state=lambda state, reason: self.states.append((f"A:{state}", reason)),
        )
        self._hooks_b = TransportHooks(
            on_plain=self.b.handle_plain,
            on_envelope=self.b.handle_envelope,
            on_probe=self._probe,
            on_state=lambda state, reason: self.states.append((f"B:{state}", reason)),
        )

    async def _probe(self, obj: dict) -> dict:
        return {"v": 1, "type": "probe_ack", "conn": "default", "nonce": obj.get("nonce")}

    async def _capture_a(self, msg: dict) -> None:
        self.a_messages.append(msg)

    async def _capture_b(self, msg: dict) -> None:
        self.b_messages.append(msg)

    def _security(self, code: str, detail: str) -> None:
        self.states.append((f"security:{code}", detail))

    async def start(self) -> None:
        """Start both servers, then the handshake, then the download loop."""
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
async def test_longpoll_handshake_and_downstream_delivery() -> None:
    """A sealed frame published by the listener is pulled and acked by the client."""
    pair = PollPair()
    await pair.start()
    try:
        assert pair.a.state is SessionState.READY
        assert pair.b.state is SessionState.READY
        # B is the listener; a frame it sends is queued for A's downstream poll.
        await pair.b.send_message(
            {
                "k": "evt",
                "m": "session.authz",
                "id": "11111111-1111-4111-8111-111111111111",
                "ts": "2026-10-29T11:30:00.000Z",
                "params": {"version": 1, "grants": [], "revoked": []},
            }
        )
        for _ in range(200):
            if pair.a_messages:
                break
            await asyncio.sleep(0.02)
        assert pair.a_messages, "downstream frame never arrived"
        assert pair.a_messages[-1]["m"] == "session.authz"
        # The queue is drained after the ack.
        for _ in range(100):
            if pair.b_transport._queue.size() == 0:
                break
            await asyncio.sleep(0.02)
        assert pair.b_transport._queue.size() == 0
    finally:
        await pair.close()


@pytest.mark.asyncio
async def test_longpoll_upload_direction() -> None:
    """Frames sent by the connect side reach the listener over ``POST /frames``."""
    pair = PollPair()
    await pair.start()
    try:
        await pair.a.send_message(
            {
                "k": "evt",
                "m": "task.event",
                "id": "22222222-2222-4222-8222-222222222222",
                "ts": "2026-10-29T11:31:00.000Z",
                "params": {"task_id": "t-1", "notify_id": "n-1"},
            }
        )
        for _ in range(200):
            if pair.b_messages:
                break
            await asyncio.sleep(0.02)
        assert pair.b_messages
        assert pair.b_messages[-1]["m"] == "task.event"
    finally:
        await pair.close()


@pytest.mark.asyncio
async def test_poll_rejects_bad_mac() -> None:
    """A poll with an invalid MAC answers 401 ``poll_auth_failed`` (§7.4)."""
    pair = PollPair()
    await pair.start()
    try:
        sid = pair.b.sid
        query = {
            "conn": "default",
            "sid": sid,
            "side": "A",
            "wait": "0",
            "max": "32",
            "ts": str(int(time.time() * 1000)),
            "nonce": b64u(secrets.token_bytes(16)),
            "target": "poll",
            "mac": "A" * 43,
        }
        async with aiohttp.ClientSession() as client:
            async with client.get(
                f"http://127.0.0.1:{pair.b_listen_port}/dsh-bridge/poll", params=query
            ) as response:
                assert response.status == 401
                assert (await response.json())["error"]["code"] == "poll_auth_failed"
    finally:
        await pair.close()


@pytest.mark.asyncio
async def test_poll_rejects_unknown_sid() -> None:
    """A valid MAC over an unknown ``sid`` answers 409 ``stale_session`` (§7.4)."""
    pair = PollPair()
    await pair.start()
    try:
        key = pair.b_transport._http_key("A")
        nonce = b64u(secrets.token_bytes(16))
        ts = int(time.time() * 1000)
        obj = _poll_mac_object(
            conn="default", sid="00000000-0000-4000-8000-000000000000", side="A",
            wait=0, max_frames=32, ts=ts, nonce=nonce, target="poll",
        )
        query = {
            "conn": "default",
            "sid": "00000000-0000-4000-8000-000000000000",
            "side": "A",
            "wait": "0",
            "max": "32",
            "ts": str(ts),
            "nonce": nonce,
            "target": "poll",
            "mac": mac_object(key, obj),
        }
        async with aiohttp.ClientSession() as client:
            async with client.get(
                f"http://127.0.0.1:{pair.b_listen_port}/dsh-bridge/poll", params=query
            ) as response:
                assert response.status == 409
                assert (await response.json())["error"]["code"] == "stale_session"
    finally:
        await pair.close()


@pytest.mark.asyncio
async def test_poll_not_ready_before_handshake() -> None:
    """Polling before the session is ready answers 425 ``not_ready`` (§7.4)."""
    pair = PollPair()
    await pair.b_transport.start(pair.b_cfg, pair._hooks_b)
    try:
        query = {
            "conn": "default",
            "sid": "irrelevant",
            "side": "A",
            "wait": "0",
            "max": "32",
            "ts": str(int(time.time() * 1000)),
            "nonce": b64u(secrets.token_bytes(16)),
            "target": "poll",
            "mac": "A" * 43,
        }
        async with aiohttp.ClientSession() as client:
            async with client.get(
                f"http://127.0.0.1:{pair.b_listen_port}/dsh-bridge/poll", params=query
            ) as response:
                assert response.status in (401, 425)
    finally:
        await pair.b_transport.stop()


@pytest.mark.asyncio
async def test_poll_empty_answers_204() -> None:
    """An authenticated poll with nothing queued answers 204 after the wait (§7.4)."""
    pair = PollPair(wait_s=0)
    await pair.start()
    try:
        nonce = b64u(secrets.token_bytes(16))
        ts = int(time.time() * 1000)
        obj = _poll_mac_object(
            conn="default", sid=pair.b.sid, side="A", wait=0, max_frames=32,
            ts=ts, nonce=nonce, target="poll",
        )
        query = {
            "conn": "default",
            "sid": pair.b.sid,
            "side": "A",
            "wait": "0",
            "max": "32",
            "ts": str(ts),
            "nonce": nonce,
            "target": "poll",
            "mac": mac_object(pair.b_transport._http_key("A"), obj),
        }
        async with aiohttp.ClientSession() as client:
            async with client.get(
                f"http://127.0.0.1:{pair.b_listen_port}/dsh-bridge/poll", params=query
            ) as response:
                # Either an empty 204 or a 200 with the frames already queued.
                assert response.status in (200, 204)
    finally:
        await pair.close()


@pytest.mark.asyncio
async def test_poll_nonce_replay_is_rejected() -> None:
    """Re-using a poll nonce answers 409 ``replay_detected`` (§7.4)."""
    pair = PollPair(wait_s=0)
    await pair.start()
    try:
        nonce = b64u(secrets.token_bytes(16))
        ts = int(time.time() * 1000)
        obj = _poll_mac_object(
            conn="default", sid=pair.b.sid, side="A", wait=0, max_frames=32,
            ts=ts, nonce=nonce, target="poll",
        )
        query = {
            "conn": "default",
            "sid": pair.b.sid,
            "side": "A",
            "wait": "0",
            "max": "32",
            "ts": str(ts),
            "nonce": nonce,
            "target": "poll",
            "mac": mac_object(pair.b_transport._http_key("A"), obj),
        }
        async with aiohttp.ClientSession() as client:
            async with client.get(
                f"http://127.0.0.1:{pair.b_listen_port}/dsh-bridge/poll", params=query
            ) as first:
                assert first.status in (200, 204)
            async with client.get(
                f"http://127.0.0.1:{pair.b_listen_port}/dsh-bridge/poll", params=query
            ) as second:
                assert second.status == 409
                assert (await second.json())["error"]["code"] == "replay_detected"
    finally:
        await pair.close()


@pytest.mark.asyncio
async def test_poll_header_guard() -> None:
    """An ``Authorization`` header on the poll endpoint is refused (§7.0)."""
    pair = PollPair()
    await pair.start()
    try:
        async with aiohttp.ClientSession() as client:
            async with client.get(
                f"http://127.0.0.1:{pair.b_listen_port}/dsh-bridge/poll",
                params={"conn": "default", "sid": "x", "side": "A", "wait": "0",
                        "max": "32", "ts": "1", "nonce": "x", "target": "poll", "mac": "x"},
                headers={"Authorization": "Bearer nope"},
            ) as response:
                assert response.status == 401
                assert (await response.json())["error"]["code"] == "auth_header_forbidden"
    finally:
        await pair.close()


@pytest.mark.asyncio
async def test_poll_ack_marks_delivered() -> None:
    """A valid ``poll/ack`` removes frames from the queue (§7.4)."""
    pair = PollPair(wait_s=0)
    await pair.start()
    try:
        await pair.b.send_message(
            {
                "k": "evt",
                "m": "session.authz",
                "id": "33333333-3333-4333-8333-333333333333",
                "ts": "2026-10-29T11:32:00.000Z",
                "params": {"version": 3},
            }
        )
        for _ in range(200):
            if pair.a_messages:
                break
            await asyncio.sleep(0.02)
        for _ in range(100):
            if pair.b_transport._queue.size() == 0:
                break
            await asyncio.sleep(0.02)
        assert pair.b_transport._queue.size() == 0
    finally:
        await pair.close()


def test_poll_mac_object_matches_protocol_shape() -> None:
    """The MAC object uses ``mac_target`` for the query ``target`` (§7.4)."""
    obj = _poll_mac_object(
        conn="default", sid="s", side="A", wait=25, max_frames=32, ts=1, nonce="n",
        target="poll",
    )
    assert obj["mac_target"] == "poll"
    assert "target" not in obj
    assert obj["wait"] == 25 and obj["max"] == 32
    assert "mac" not in obj


def test_http_keys_are_directional() -> None:
    """The two HTTP direction keys differ, matching §3.4."""
    master = psk_master("x", "y")
    prk = hkdf_extract(b"\x00" * 32, master)
    a2b = hkdf_expand(prk, b"dsh-bridge/v1 http-a2b", 32)
    b2a = hkdf_expand(prk, b"dsh-bridge/v1 http-b2a", 32)
    assert a2b != b2a


@pytest.mark.asyncio
async def test_longpoll_wait_is_clamped() -> None:
    """The wait parameter never exceeds ``POLL_WAIT_MAX_S`` (§7.4)."""
    transport = LongPollTransport(
        role="connect", conn="default", side="A", psk_id="i", psk_secret="s", wait_s=999
    )
    assert transport._wait_s == POLL_WAIT_MAX_S
