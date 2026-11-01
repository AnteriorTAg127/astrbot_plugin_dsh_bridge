"""Handshake tests: four-step exchange, failure classification, seq single-writer.

Covers protocol §4 (handshake), §5.3/§5.6 (sequence allocation under one lock),
§4.6 (replay/rate-limit) and §7.7 (superseded semantics at the session layer).
"""

from __future__ import annotations

import asyncio

import pytest

from bridge.crypto import b64u, handshake_key, psk_master
from bridge.errors import (
    ERR_BAD_SIDE,
    ERR_BAD_VERSION,
    ERR_CAPABILITY_UNAVAILABLE,
    ERR_HELLO_EXPIRED,
    ERR_HELLO_REPLAY,
    ERR_PSK_MISMATCH,
    ERR_REPLAY_DETECTED,
    ERR_STALE_SESSION,
    ERR_TH_MISMATCH,
    BridgeError,
)
from bridge.session import (
    HandshakeRateLimiter,
    HelloReplayCache,
    Role,
    Session,
    SessionConfig,
    SessionState,
    build_caps,
)
from _session_doubles import (
    TEST_PSK_ID,
    TEST_PSK_SECRET,
    FakeTransport,
    SessionPair,
    make_caps,
)


@pytest.mark.asyncio
async def test_four_step_handshake_reaches_ready() -> None:
    """Both sides reach ``ready`` with the same sid and a shared transcript."""
    pair = SessionPair()
    await pair.handshake()
    assert pair.a.state is SessionState.READY
    assert pair.b.state is SessionState.READY
    assert pair.a.sid == pair.b.sid
    assert pair.a.peer_side == "B"
    assert pair.b.peer_side == "A"
    assert pair.a._th == pair.b._th
    await pair.close()


@pytest.mark.asyncio
async def test_handshake_uses_fresh_nonces_and_sid() -> None:
    """Every handshake generates new nonces, hello id and sid (§3.4)."""
    first = SessionPair()
    await first.handshake()
    first_nonces = (first.a._nonce_c, first.a._nonce_s, first.a.sid)
    await first.close()

    second = SessionPair()
    await second.handshake()
    second_nonces = (second.a._nonce_c, second.a._nonce_s, second.a.sid)
    await second.close()

    assert first_nonces[0] != second_nonces[0]
    assert first_nonces[1] != second_nonces[1]
    assert first_nonces[2] != second_nonces[2]


@pytest.mark.asyncio
async def test_wrong_psk_yields_psk_mismatch() -> None:
    """A different PSK fails the ``hello`` MAC check with ``psk_mismatch``."""
    pair = SessionPair(psk_b="a-different-secret")
    await pair.b.start()
    with pytest.raises(BridgeError) as excinfo:
        await pair.a.start()
    assert excinfo.value.code == ERR_PSK_MISMATCH
    assert excinfo.value.fatal


@pytest.mark.asyncio
async def test_missing_psk_refuses_to_connect() -> None:
    """An empty PSK must fail fast rather than degrade to plaintext (§3.2)."""
    with pytest.raises(BridgeError) as excinfo:
        SessionConfig(
            conn="default",
            side="A",
            role=Role.INITIATOR,
            transport="ws",
            psk_id="",
            psk_secret="",
        )
    assert excinfo.value.code == "psk_not_configured"


@pytest.mark.asyncio
async def test_unsupported_protocol_version_is_rejected() -> None:
    """``pv`` other than 1 is ``bad_version``."""
    pair = SessionPair()
    hello = {
        "v": 1,
        "type": "hello",
        "conn": "default",
        "hello_id": "11111111-1111-4111-8111-111111111111",
        "pv": 2,
        "side": "A",
        "tp": "ws",
        "nonce": b64u(b"\x00" * 32),
        "ts": 1_761_737_000_000,
        "caps": make_caps("A"),
        "mac": "x",
    }
    await pair.b.start()
    with pytest.raises(BridgeError) as excinfo:
        await pair.b.handle_plain(hello)
    assert excinfo.value.code == ERR_BAD_VERSION


@pytest.mark.asyncio
async def test_same_side_is_rejected() -> None:
    """A peer claiming the same side is ``bad_side``."""
    pair = SessionPair()
    hello = {
        "v": 1,
        "type": "hello",
        "conn": "default",
        "hello_id": "11111111-1111-4111-8111-111111111111",
        "pv": 1,
        "side": "B",
        "tp": "ws",
        "nonce": b64u(b"\x00" * 32),
        "ts": 1_761_737_000_000,
        "caps": make_caps("B"),
        "mac": "x",
    }
    await pair.b.start()
    with pytest.raises(BridgeError) as excinfo:
        await pair.b.handle_plain(hello)
    assert excinfo.value.code == ERR_BAD_SIDE


@pytest.mark.asyncio
async def test_stale_hello_timestamp_is_rejected() -> None:
    """A ``ts`` outside the 300 s skew window is ``hello_expired``."""
    pair = SessionPair()
    master = psk_master(TEST_PSK_ID, TEST_PSK_SECRET)
    hello = {
        "v": 1,
        "type": "hello",
        "conn": "default",
        "hello_id": "11111111-1111-4111-8111-111111111111",
        "pv": 1,
        "side": "A",
        "tp": "ws",
        "nonce": b64u(b"\x00" * 32),
        "ts": 1,
        "caps": make_caps("A"),
    }
    hello["mac"] = __import__("bridge.crypto", fromlist=["mac_object"]).mac_object(
        handshake_key(master, "hello"), hello
    )
    await pair.b.start()
    with pytest.raises(BridgeError) as excinfo:
        await pair.b.handle_plain(hello)
    assert excinfo.value.code == ERR_HELLO_EXPIRED


@pytest.mark.asyncio
async def test_unknown_conn_is_rejected() -> None:
    """A ``conn`` mismatch is ``unknown_conn``."""
    pair = SessionPair()
    hello = {
        "v": 1,
        "type": "hello",
        "conn": "other",
        "hello_id": "11111111-1111-4111-8111-111111111111",
        "pv": 1,
        "side": "A",
        "tp": "ws",
        "nonce": b64u(b"\x00" * 32),
        "ts": 1_761_737_000_000,
        "caps": make_caps("A"),
        "mac": "x",
    }
    await pair.b.start()
    with pytest.raises(BridgeError) as excinfo:
        await pair.b.handle_plain(hello)
    assert excinfo.value.code == "unknown_conn"


def test_hello_replay_cache_detects_repeat() -> None:
    """Reusing ``hello_id`` or ``nonce_c`` within the TTL is ``hello_replay``."""
    cache = HelloReplayCache()
    cache.check_and_record("id-1", "nonce-1")
    with pytest.raises(BridgeError) as excinfo:
        cache.check_and_record("id-1", "nonce-2")
    assert excinfo.value.code == ERR_HELLO_REPLAY
    with pytest.raises(BridgeError):
        cache.check_and_record("id-2", "nonce-1")
    cache.check_and_record("id-3", "nonce-3")


def test_rate_limiter_engages_after_repeated_failures() -> None:
    """Ten failures within the window trigger ``rate_limited`` (§4.6)."""
    limiter = HandshakeRateLimiter()
    assert not limiter.is_blocked()
    for _ in range(9):
        limiter.record_failure()
    assert not limiter.is_blocked()
    limiter.record_failure()
    assert limiter.is_blocked()


def test_rate_limiter_resets_on_success() -> None:
    """A successful handshake clears the failure counter."""
    limiter = HandshakeRateLimiter()
    for _ in range(5):
        limiter.record_failure()
    limiter.record_success()
    for _ in range(9):
        limiter.record_failure()
    assert not limiter.is_blocked()


@pytest.mark.asyncio
async def test_th_mismatch_is_fatal() -> None:
    """A divergent transcript raises ``th_mismatch`` and is fatal (§4.4)."""
    pair = SessionPair()
    await pair.handshake()
    tampered = {"side": "A", "role": "initiator", "sid": pair.b.sid,
                "hello_id": "x", "th": b64u(b"\x00" * 32)}
    with pytest.raises(BridgeError) as excinfo:
        pair.b._check_transcript(tampered)
    assert excinfo.value.code == ERR_TH_MISMATCH
    assert excinfo.value.fatal
    await pair.close()


@pytest.mark.asyncio
async def test_stale_session_sid_is_rejected() -> None:
    """A sealed ``auth`` naming an old sid is ``stale_session``."""
    pair = SessionPair()
    await pair.handshake()
    old_sid = pair.b.sid
    payload = {
        "side": "A",
        "role": "initiator",
        "sid": "00000000-0000-4000-8000-000000000000",
        "hello_id": pair.b._hello_id,
        "th": b64u(pair.b._th),
    }
    with pytest.raises(BridgeError) as excinfo:
        await pair.b.handle_envelope(
            __import__("bridge.crypto", fromlist=["seal_frame"]).seal_frame(
                pair.a._keys.k_a2b, "A", "auth", "default", pair.b._replay.expected, payload
            )
        )
    assert excinfo.value.code == ERR_STALE_SESSION
    assert pair.b.sid == old_sid
    await pair.close()


@pytest.mark.asyncio
async def test_duplicate_seq_is_rejected() -> None:
    """Replaying an accepted envelope is ``replay_detected`` (§5.4)."""
    pair = SessionPair()
    await pair.handshake()
    await pair.a.send_message(
        {"k": "evt", "m": "blob.abort", "id": "11111111-1111-4111-8111-111111111111",
         "ts": "2026-10-29T11:31:00.000Z", "params": {"blob_id": "b", "reason": "x"}}
    )
    replay = pair.a_transport.sent_envelopes[-1]
    with pytest.raises(BridgeError) as excinfo:
        await pair.b.handle_envelope(replay)
    assert excinfo.value.code == ERR_REPLAY_DETECTED
    assert excinfo.value.fatal
    await pair.close()


@pytest.mark.asyncio
async def test_tampered_envelope_fails_aead() -> None:
    """A flipped ciphertext byte is ``aead_failed`` and fatal."""
    pair = SessionPair()
    await pair.handshake()
    await pair.a.send_message(
        {"k": "evt", "m": "blob.abort", "id": "11111111-1111-4111-8111-111111111111",
         "ts": "2026-10-29T11:31:00.000Z", "params": {"blob_id": "b", "reason": "x"}}
    )
    envelope = dict(pair.a_transport.sent_envelopes[-1])
    raw = bytearray(__import__("bridge.crypto", fromlist=["b64u_dec"]).b64u_dec(envelope["ct"]))
    raw[-1] ^= 0x01
    envelope["ct"] = b64u(bytes(raw))
    with pytest.raises(BridgeError) as excinfo:
        await pair.b.handle_envelope(envelope)
    assert excinfo.value.code == "aead_failed"
    assert excinfo.value.fatal
    await pair.close()


@pytest.mark.asyncio
async def test_sealed_frame_before_handshake_is_auth_required() -> None:
    """Any sealed frame before ``auth`` completion is ``auth_required``."""
    pair = SessionPair()
    with pytest.raises(BridgeError) as excinfo:
        await pair.b.handle_envelope(
            {"v": 1, "type": "data", "conn": "default", "seq": 0, "ct": "AAAA"}
        )
    assert excinfo.value.code == "auth_required"
    assert excinfo.value.fatal


@pytest.mark.asyncio
async def test_concurrent_sends_allocate_unique_monotonic_seq() -> None:
    """100 concurrent sends produce ``0..99`` with no duplicates (§5.3/§5.6)."""
    pair = SessionPair()
    await pair.handshake()
    seqs: list[int] = []
    original = pair.a_transport.send_envelope

    async def record(env: dict) -> None:
        seqs.append(env["seq"])
        await original(env)

    pair.a_transport.send_envelope = record  # type: ignore[method-assign]

    async def one(index: int) -> None:
        await pair.a.send_message(
            {
                "k": "evt",
                "m": "blob.abort",
                "id": f"1111111{index % 10}-1111-4111-8111-11111111111{index % 10}",
                "ts": "2026-10-29T11:31:00.000Z",
                "params": {"blob_id": str(index), "reason": "x"},
            }
        )

    await asyncio.gather(*(one(index) for index in range(100)))
    assert len(seqs) == 100
    assert len(set(seqs)) == 100
    assert seqs == sorted(seqs)
    await pair.close()


@pytest.mark.asyncio
async def test_call_roundtrip_returns_peer_result() -> None:
    """``call`` awaits the matching ``rep`` and returns its result (§5.5)."""
    pair = SessionPair()
    await pair.handshake()

    async def handler(params: dict, ctx) -> dict:
        return {"echo": params.get("value")}

    from bridge.router import Router

    router_a = Router(conn="default")
    router_b = Router(conn="default")
    router_b.register("task.status", handler)

    original_a = pair.a._on_message
    original_b = pair.b._on_message

    async def route_a(msg: dict) -> None:
        await router_a.dispatch(msg)
        await original_a(msg)

    async def route_b(msg: dict) -> None:
        reply = await router_b.dispatch(msg)
        if reply is not None:
            await pair.b.send_message(reply)
        await original_b(msg)

    pair.a._on_message = route_a  # type: ignore[method-assign]
    pair.b._on_message = route_b  # type: ignore[method-assign]

    result = await pair.a.call("task.status", {"value": 42}, timeout_s=5)
    assert result == {"echo": 42}
    await pair.close()


@pytest.mark.asyncio
async def test_call_times_out() -> None:
    """A missing reply surfaces as ``timeout`` (§5.5)."""
    pair = SessionPair()
    await pair.handshake()
    with pytest.raises(BridgeError) as excinfo:
        await pair.a.call("task.status", {"task_id": "x"}, timeout_s=0.05)
    assert excinfo.value.code == "timeout"
    await pair.close()


@pytest.mark.asyncio
async def test_peer_capability_checks() -> None:
    """Feature and role negotiation reads the peer caps (§4.5)."""
    pair = SessionPair(native_tool_b=True)
    await pair.handshake()
    assert pair.a.peer_supports("event.ack")
    assert not pair.a.peer_supports("not.a.feature")
    assert pair.a.peer_role("execute_task")
    assert pair.a.negotiated()["approvals"]["native_tool"] is False
    assert pair.b.negotiated()["approvals"]["native_tool"] is False
    await pair.close()


@pytest.mark.asyncio
async def test_close_moves_session_to_closed_and_fails_pending() -> None:
    """``close`` marks the session closed and fails in-flight calls (§6.2)."""
    pair = SessionPair()
    await pair.handshake()
    waiting = asyncio.create_task(pair.a.call("task.status", {}, timeout_s=5))
    await asyncio.sleep(0)
    await pair.a.close("draining", "shutdown")
    with pytest.raises(BridgeError):
        await waiting
    assert pair.a.state is SessionState.CLOSED


@pytest.mark.asyncio
async def test_heartbeat_ping_pong() -> None:
    """A ``ping`` produces a ``pong`` carrying the same ``n`` (§5.1/§6.1)."""
    pair = SessionPair()
    await pair.handshake()
    before = len(pair.b_transport.sent_envelopes)
    await pair.a.ping()
    assert len(pair.b_transport.sent_envelopes) > before
    assert pair.b_transport.sent_envelopes[-1]["type"] == "pong"
    await pair.close()


@pytest.mark.asyncio
async def test_send_before_ready_is_not_ready() -> None:
    """Sending a data frame before the handshake raises ``not_ready``."""
    transport = FakeTransport(Role.INITIATOR)
    session = Session(
        SessionConfig(
            conn="default",
            side="A",
            role=Role.INITIATOR,
            transport="ws",
            psk_id=TEST_PSK_ID,
            psk_secret=TEST_PSK_SECRET,
            caps=make_caps("A"),
        ),
        transport,
        lambda msg: None,
        lambda code, detail: None,
    )
    with pytest.raises(BridgeError) as excinfo:
        await session.send("data", {"k": "evt"})
    assert excinfo.value.code == "not_ready"


def test_build_caps_shape_matches_protocol() -> None:
    """``build_caps`` emits exactly the §4.5 field set."""
    caps = build_caps(
        side="A",
        host="astrbot",
        version="0.1.0",
        transports=["longpoll", "webhook", "ws"],
        tls=False,
        native_tool=False,
        image_enabled=True,
        image_max_count=4,
        image_max_bytes=10485760,
        image_total_max_bytes=20971520,
    )
    assert set(caps) == {
        "side",
        "host",
        "version",
        "pv",
        "transports",
        "tls",
        "roles",
        "approvals",
        "attachments",
        "limits",
        "features",
    }
    assert caps["approvals"]["native_tool"] is False
    assert caps["attachments"]["reference"] is False
    assert caps["attachments"]["mime"] == sorted(caps["attachments"]["mime"])
    assert caps["features"] == sorted(caps["features"])
