"""Cross-language WS acceptance: both role directions over a real socket.

Covers TC-WS-01 (both role combinations), the four-step handshake verified from
real bytes, a Chinese request/reply, notification + ack, 100 concurrent sends
with unique ``seq``, wrong-PSK rejection and nonce freshness on reconnect.

Every test carries ``@pytest.mark.cross_transport``; the very first transport
combination is also asserted end-to-end (``ready`` on both sides), so a broken
carrier fails loudly instead of being reported as blocked.
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest
from tests.integration.cross_transport import harness as H

pytestmark = pytest.mark.cross_transport

#: Both role combinations required by protocol §4.1 / §7.1.
ROLE_MATRIX = [("listen", "connect"), ("connect", "listen")]


def _types(snapshot: dict[str, Any]) -> list[str]:
    """Return the plain-objects a peer sent, for handshake ordering checks.

    Args:
        snapshot: Peer snapshot dict.

    Returns:
        List of ``type`` values in send order.
    """
    return [item.get("type") for item in snapshot.get("sent_plain", [])]


@pytest.mark.parametrize(("a_mode", "b_mode"), ROLE_MATRIX)
def test_ws_both_roles_reach_ready(pair_factory, record_property, a_mode, b_mode):
    """TC-WS-01: both role combinations complete the handshake over real TCP.

    Args:
        pair_factory: Fixture spawning an A/B pair.
        record_property: pytest metadata hook.
        a_mode: A's mode for this parameter set.
        b_mode: Expected B mode (checked for consistency with ``a_mode``).
    """
    assert b_mode == ("connect" if a_mode == "listen" else "listen")
    pair = pair_factory("ws", a_mode)
    pair.require_ready("WS handshake did not complete")

    assert pair.a_ready is not None and pair.b_ready is not None
    assert pair.a_ready["state"] == "ready", pair.a_ready
    assert pair.b_ready["state"] == "ready", pair.b_ready
    # The responder owns `sid` (§4.3): both sides must agree on it.
    assert pair.a_ready["sid"] == pair.b_ready["sid"]
    assert pair.a_ready["peer_caps_side"] == "B"
    assert pair.b_ready["peer_caps_side"] == "A"
    record_property("sid", pair.a_ready["sid"])


@pytest.mark.parametrize(("a_mode", "b_mode"), ROLE_MATRIX)
def test_ws_four_step_handshake_from_real_bytes(pair_factory, a_mode, b_mode):
    """§4.1: verify the four handshake objects on the wire, in order.

    The assertion deliberately reads the objects each peer actually received
    rather than re-deriving them, so a shared bug in a helper cannot hide.

    Args:
        pair_factory: Fixture spawning an A/B pair.
        a_mode: A's mode.
        b_mode: B's mode.
    """
    assert b_mode == ("connect" if a_mode == "listen" else "listen")
    pair = pair_factory("ws", a_mode)
    pair.require_ready("handshake unavailable")

    responder = pair.a if a_mode == "listen" else pair.b
    initiator = pair.b if a_mode == "listen" else pair.a

    responder_snap = responder.request(10, op="snapshot")
    initiator_snap = initiator.request(10, op="snapshot")

    # Step 1/2: initiator sends `hello`, responder answers `hello_ack`. The
    # responder returns the ack from `handle_plain` to the carrier, so it shows
    # up in `replied_plain` rather than in `sent_plain`.
    assert "hello" in _types(initiator_snap), _types(initiator_snap)
    assert responder_snap["received_plain_types"][:1] == ["hello"]
    acks = [
        item
        for item in responder_snap["replied_plain"]
        if item.get("type") == "hello_ack"
    ]
    assert acks, f"responder never built hello_ack: {responder_snap['replied_plain']}"

    hello = responder_snap["received_plain"][0]
    ack = acks[0]
    for field in (
        "v",
        "type",
        "conn",
        "hello_id",
        "pv",
        "side",
        "tp",
        "nonce",
        "ts",
        "caps",
        "mac",
    ):
        assert field in hello, f"hello missing {field}"
    for field in (
        "v",
        "type",
        "conn",
        "hello_id",
        "sid",
        "pv",
        "side",
        "tp",
        "nonce",
        "ts",
        "caps",
        "mac",
    ):
        assert field in ack, f"hello_ack missing {field}"
    assert hello["hello_id"] == ack["hello_id"]
    assert hello["v"] == ack["v"] == 1
    assert hello["pv"] == ack["pv"] == 1
    assert hello["side"] != ack["side"]
    assert hello["tp"] == ack["tp"] == "ws"
    # Nonces are 32 raw bytes in base64url (43 chars, unpadded).
    assert len(hello["nonce"]) == 43 and "=" not in hello["nonce"]
    assert len(ack["nonce"]) == 43 and "=" not in ack["nonce"]
    assert hello["nonce"] != ack["nonce"]

    # Step 3/4: `auth` (seq 0) then `auth_ack` (seq 0 of the other direction).
    initiator_envelopes = initiator_snap["sent_envelopes"]
    responder_envelopes = responder_snap["sent_envelopes"]
    assert initiator_envelopes[0]["type"] == "auth"
    assert initiator_envelopes[0]["seq"] == 0
    assert responder_envelopes[0]["type"] == "auth_ack"
    assert responder_envelopes[0]["seq"] == 0
    # A sealed envelope is exactly the §5.1 field set: no plaintext leaks.
    assert set(initiator_envelopes[0]) == {"v", "type", "conn", "seq", "ct"}


@pytest.mark.parametrize(("a_mode", "b_mode"), ROLE_MATRIX)
def test_ws_chinese_request_reply_both_directions(pair_factory, a_mode, b_mode):
    """A UTF-8 request/reply survives the AEAD path unchanged in both directions.

    Args:
        pair_factory: Fixture spawning an A/B pair.
        a_mode: A's mode.
        b_mode: B's mode.
    """
    assert b_mode == ("connect" if a_mode == "listen" else "listen")
    pair = pair_factory("ws", a_mode)
    pair.require_ready("handshake unavailable")

    chinese = "请为这个函数写单元测试。"
    emoji = "完成 ✅"
    params = {"task_id": "t-中文-1", "purpose": chinese, "note": emoji}

    to_a = pair.b.request(20, op="call", m="task.status", params=params, timeout_s=10)
    assert to_a["ok"] is True, to_a
    assert to_a["result"]["handled_by"] == "A"
    assert to_a["result"]["echo"] == params, "UTF-8 payload changed on the B→A path"

    to_b = pair.a.request(20, op="call", m="task.status", params=params, timeout_s=10)
    assert to_b["ok"] is True, to_b
    assert to_b["result"]["handled_by"] == "B"
    assert to_b["result"]["echo"] == params, "UTF-8 payload changed on the A→B path"


@pytest.mark.parametrize(("a_mode", "b_mode"), ROLE_MATRIX)
def test_ws_task_event_and_event_ack(pair_factory, a_mode, b_mode):
    """A notification is delivered as an ``evt`` and acked with a ``req``.

    This asserts *transport* delivery of the §11.1 pair only; it does not claim
    task execution.

    Args:
        pair_factory: Fixture spawning an A/B pair.
        a_mode: A's mode.
        b_mode: B's mode.
    """
    assert b_mode == ("connect" if a_mode == "listen" else "listen")
    pair = pair_factory("ws", a_mode)
    pair.require_ready("handshake unavailable")

    notify_id = "11111111-2222-4333-8444-555555555555"
    event = {
        "task_id": "task-1",
        "root_task_id": "task-1",
        "eseq": 1,
        "event": "completed",
        "status": "succeeded",
        "notify_id": notify_id,
        "result": {"summary": "ok", "text": "完成 ✅", "attachments": []},
        "error": None,
        "decision": None,
        "approval": None,
    }
    pair.b.request(15, op="emit", m="task.event", id_value="evt-1", params=event)
    received = pair.a.request(20, op="wait_messages", count=1, timeout_s=15)
    assert received["count"] >= 1, received
    delivered = received["messages"][0]
    assert delivered["k"] == "evt"
    assert delivered["m"] == "task.event"
    assert delivered["params"]["notify_id"] == notify_id
    assert delivered["params"]["result"]["text"] == "完成 ✅"

    ack = {
        "notify_id": notify_id,
        "task_id": "task-1",
        "root_task_id": "task-1",
        "outcome": "processed",
    }
    reply = pair.a.request(20, op="call", m="event.ack", params=ack, timeout_s=10)
    assert reply["ok"] is True, reply
    assert reply["result"]["echo"]["notify_id"] == notify_id
    assert reply["result"]["handled_by"] == "B"


@pytest.mark.parametrize(("a_mode", "b_mode"), ROLE_MATRIX)
def test_ws_hundred_concurrent_sends_have_unique_seq(pair_factory, a_mode, b_mode):
    """§5.6: 100 concurrent ``call()``s allocate 100 distinct, ascending ``seq``.

    Args:
        pair_factory: Fixture spawning an A/B pair.
        a_mode: A's mode.
        b_mode: B's mode.
    """
    assert b_mode == ("connect" if a_mode == "listen" else "listen")
    pair = pair_factory("ws", a_mode)
    pair.require_ready("handshake unavailable")

    burst = pair.b.request(180, op="burst", count=100, m="task.status")
    assert burst["failures"] == [], burst["failures"]
    assert burst["count"] == 100

    seqs = burst["seqs"]
    types = burst["types"]
    # `auth`/`auth_ack`/`ping` are handshake/keepalive frames; the burst itself is
    # `data` only, so the last 100 data frames are exactly this burst.
    data_seqs = [seq for seq, kind in zip(seqs, types) if kind == "data"]
    assert len(data_seqs) >= 100, f"only {len(data_seqs)} data frames were sent"
    burst_seqs = data_seqs[-100:]
    assert len(set(burst_seqs)) == len(burst_seqs), "duplicate seq observed"
    assert burst_seqs == sorted(burst_seqs), "seq must be monotonically allocated"
    # And the whole sequence the peer allocated must be strictly increasing.
    assert seqs == sorted(seqs), "seq allocation went backwards"
    assert len(set(seqs)) == len(seqs), "duplicate seq observed across the session"


def test_ws_rejects_wrong_psk():
    """A wrong PSK must fail the handshake and never produce a session."""
    credentials = H.Credentials.synthetic()
    wrong = H.Credentials(
        conn=credentials.conn, psk_id=credentials.psk_id, psk_secret="00" * 32
    )
    listen_port = H.free_port()
    reply_port = H.free_port()
    a = H.spawn_a(
        transport="ws",
        mode="listen",
        peer_port=reply_port,
        bind_port=listen_port,
        credentials=credentials,
    )
    try:
        assert H.wait_port_open(listen_port, 30.0), "responder never bound its port"
        b = H.spawn_b(
            transport="ws",
            mode="connect",
            peer_port=listen_port,
            bind_port=reply_port,
            credentials=wrong,
        )
        deadline = time.monotonic() + 40
        outcome: dict[str, Any] | None = None
        while time.monotonic() < deadline:
            for event in b.drain_events():
                if event.get("event") == "ready":
                    pytest.fail(f"wrong PSK produced a ready session: {_dump(event)}")
                if event.get("event") == "start_error":
                    outcome = event
                    break
            if outcome is not None:
                break
            if b.returncode is not None and not b.unsolicited:
                outcome = {"event": "start_error", "code": "<process exited>"}
                break
            time.sleep(0.1)
        assert outcome is not None, (
            f"wrong PSK did not terminate the handshake: {b.stdout_tail(2000)}"
        )

        # The responder must never report a live session for this attempt.
        responder_events = a.drain_events()
        assert all(event.get("event") != "ready" for event in responder_events), (
            responder_events
        )
    finally:
        a.stop()
        b.stop()


def test_ws_reconnect_uses_fresh_nonce_and_sid(pair_factory):
    """A fresh handshake must use a new ``nonce_c`` and a new ``sid`` (§3.4, §4.6).

    The pair is torn down and rebuilt, which is what a reconnect is for the
    session layer: a session object owns exactly one ``sid`` and one nonce pair,
    so a reconnect allocates both anew.

    Args:
        pair_factory: Fixture spawning an A/B pair.
    """
    first_pair = pair_factory("ws", "listen")
    first_pair.require_ready("first handshake failed")
    first_nonce = first_pair.b_ready["sent_plain"][0]["nonce"]
    first_sid = first_pair.b_ready["sid"]
    first_pair.close()
    time.sleep(0.5)

    second_pair = pair_factory("ws", "listen")
    second_pair.require_ready("second handshake failed")
    second_nonce = second_pair.b_ready["sent_plain"][0]["nonce"]
    second_sid = second_pair.b_ready["sid"]

    assert first_nonce != second_nonce, "a new handshake reused nonce_c (nonce reuse)"
    assert sids_are_distinct(first_sid, second_sid), "a new handshake reused sid"


def sids_are_distinct(first: str | None, second: str | None) -> bool:
    """Whether two session identifiers differ (both present).

    Args:
        first: First ``sid``.
        second: Second ``sid``.

    Returns:
        ``True`` when both exist and differ.
    """
    return bool(first) and bool(second) and first != second


def _dump(event: dict[str, Any]) -> str:
    """Render one event for assertion messages.

    Args:
        event: Event object.

    Returns:
        Compact JSON text.
    """
    return json.dumps(event, ensure_ascii=False)[:400]
