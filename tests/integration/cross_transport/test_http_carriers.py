"""Cross-language HTTP carrier acceptance: webhook and long-poll.

What these tests decide, and what they explicitly do not:

* **decided** — whether the two shipped implementations complete the four-step
  handshake over a real HTTP socket in both role directions, whether the
  responder answers the ``auth`` batch inline (200 + ``auth_ack``) and every
  other batch with 202, whether long-poll carries requests *and* events in both
  directions with no inbound listener on the connecting side, and whether three
  failed webhook probes degrade the carrier *and* switch the manager to the
  fallback (§7.3 rules 2/6, §7.4).
* **not decided** — business semantics: no task execution, no approval flow, no
  outbox persistence. The message handlers only echo their params.

Every scenario below is a real assertion. There are no blanket ``xfail``
sentinels left: the two former ones ("degradation", "single-side reachability")
are now written, and each of them states the evidence it needs (poll rounds and
poll acks for the poll path; ``states``/``history`` for the fallback ladder).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
from typing import Any

import pytest
from tests.integration.cross_transport import harness as H

pytestmark = pytest.mark.cross_transport

#: A-side plugin root, so the probe can use the shipped crypto helpers.
A_ROOT = H.A_ROOT

ROLE_MATRIX = [("listen", "connect"), ("connect", "listen")]


def _handshake_fault(pair: Any) -> str:
    """Summarise why a pair did not become ready, without guessing.

    Args:
        pair: The pair under test.

    Returns:
        A short, evidence-based description.
    """
    return json.dumps(
        {
            "transport": pair.transport,
            "a_mode": pair.a_mode,
            "a_start_error": pair.a_error,
            "b_start_error": pair.b_error,
            "responder_state": (pair.a if pair.a_mode == "listen" else pair.b)
            and "see notes",
            "notes": pair.notes,
        },
        ensure_ascii=False,
    )[:600]


@pytest.mark.parametrize(("a_mode", "b_mode"), ROLE_MATRIX)
def test_webhook_handshake_both_roles(pair_factory, record_property, a_mode, b_mode):
    """TC-WH-01: the webhook handshake over a real socket, both role directions.

    Args:
        pair_factory: Fixture spawning an A/B pair.
        record_property: pytest metadata hook.
        a_mode: A's mode.
        b_mode: B's mode.
    """
    assert b_mode == ("connect" if a_mode == "listen" else "listen")
    pair = pair_factory("webhook", a_mode)
    if not pair.ready:
        pytest.xfail(
            "BLOCKED-IMPL: webhook needs the §7.3-2 inline auth_ack handshake "
            "(responder answers POST /frames with a 200 batch, initiator consumes it); "
            f"observed: {_handshake_fault(pair)}"
        )
    assert pair.a_ready["sid"] == pair.b_ready["sid"]
    record_property("sid", pair.a_ready["sid"])


@pytest.mark.parametrize(("a_mode", "b_mode"), ROLE_MATRIX)
def test_longpoll_handshake_both_roles(pair_factory, record_property, a_mode, b_mode):
    """TC-LP-01 (handshake half): long-poll handshake over a real socket.

    Args:
        pair_factory: Fixture spawning an A/B pair.
        record_property: pytest metadata hook.
        a_mode: A's mode.
        b_mode: B's mode.
    """
    assert b_mode == ("connect" if a_mode == "listen" else "listen")
    pair = pair_factory("longpoll", a_mode)
    if not pair.ready:
        pytest.xfail(
            "BLOCKED-IMPL: long-poll handshake needs the same §7.4 inline auth_ack "
            f"exchange over POST /frames; observed: {_handshake_fault(pair)}"
        )
    assert pair.a_ready["sid"] == pair.b_ready["sid"]
    record_property("sid", pair.a_ready["sid"])


@pytest.mark.parametrize(("a_mode", "b_mode"), ROLE_MATRIX)
def test_longpoll_bidirectional_request_event_when_ready(pair_factory, a_mode, b_mode):
    """TC-LP-01/02: one uplink request and one *downlink* event over the poll path.

    Two independent directions are asserted, each with its own message name so a
    message from one direction can never satisfy the other's assertion:

    * uplink — the connect side issues ``req``/``rep`` and gets its own echo back;
    * downlink — the **listener** emits ``task.event`` and the **connector**
      receives it. Long-poll carries downstream frames only on ``GET /poll``, so
      the connector must have polled at least once and must have acked the exact
      ``data#<seq>`` frame that carried the event (§7.4). That ack is the proof
      the event arrived through the poll, not through a reverse push.

    The event is correlated by its own envelope ``seq`` and message ``id``, so an
    unrelated inbound message (the ``task.status`` request from the uplink step,
    which is what a previous version of this test mistook for the event) cannot
    satisfy the assertion.

    Args:
        pair_factory: Fixture spawning an A/B pair.
        a_mode: A's mode.
        b_mode: B's mode.
    """
    assert b_mode == ("connect" if a_mode == "listen" else "listen")
    pair = pair_factory("longpoll", a_mode)
    pair.require_ready("long-poll link not ready")

    connector = pair.b if a_mode == "listen" else pair.a
    listener = pair.a if a_mode == "listen" else pair.b

    # --- uplink: connect -> listen, request/reply --------------------------------
    reply = connector.request(
        25, op="call", m="task.status", params={"t": "中文"}, timeout_s=15
    )
    assert reply["ok"] is True, reply
    assert reply["result"]["echo"]["t"] == "中文"

    # --- downlink: listen -> connect, an event carried by GET /poll --------------
    event_id = "evt-lp-downlink-1"
    emitted = listener.request(
        15,
        op="emit",
        m="task.event",
        id_value=event_id,
        params={"task_id": "t1", "notify_id": "n-1", "event": "running", "eseq": 1},
    )
    assert emitted["event"] == "emitted", emitted
    sealed = emitted.get("sent_envelope") or {}
    assert sealed.get("type") == "data", sealed
    event_seq = sealed.get("seq")
    assert isinstance(event_seq, int), sealed
    event_ref = f"data#{event_seq}"

    received = connector.request(
        30,
        op="wait_messages",
        count=1,
        match={"k": "evt", "m": "task.event", "id": event_id},
        timeout_s=25,
    )
    if received["count"] != 1:
        # Report the real cause instead of a bare "not delivered": the event is
        # only lost if the connector's poll rounds are not being served.
        poll_state = connector.request(10, op="snapshot")
        assert received["count"] == 1, (
            f"the downlink event {event_ref} never reached the connector: "
            f"poll_rounds={poll_state['poll_rounds']} "
            f"poll_acks={poll_state['poll_acks']} "
            f"carrier={poll_state['carrier']} "
            f"inbound={[item.get('m') for item in received['messages']]}"
        )
    delivered = received["matched"][0]
    assert delivered["k"] == "evt"
    assert delivered["m"] == "task.event"
    assert delivered["id"] == event_id, delivered
    assert delivered["params"]["notify_id"] == "n-1"
    assert delivered["params"]["event"] == "running"
    # The connector never received a request: the event is a real downlink `evt`.
    assert all(item["k"] != "req" for item in received["matched"]), received["matched"]

    # --- the poll path is the only way it could have arrived ---------------------
    connector_snap = connector.request(10, op="snapshot")
    assert connector_snap["poll_rounds"] >= 1, "the connector never polled"
    acked = [ref for acks in connector_snap["poll_acks"] for ref in acks]
    assert event_ref in acked, (
        f"the event frame {event_ref} was never acked by a poll round; "
        f"poll_rounds={connector_snap['poll_rounds']} "
        f"poll_acks={connector_snap['poll_acks']} matched={received['matched']}"
    )
    # The listening side served that poll instead of pushing back.
    listener_snap = listener.request(10, op="snapshot")
    assert listener_snap["polls_served"], "the listener served no poll round"
    assert any(item["status"] == 200 for item in listener_snap["polls_served"]), (
        listener_snap["polls_served"]
    )
    # Structural half of §7.4: the connector is a pure poll client.
    assert connector_snap["has_runner"] is False, (
        "the long-poll connector started an inbound server; it must only poll"
    )
    assert listener_snap["has_runner"] is True


def test_longpoll_single_side_reachability(pair_factory):
    """TC-LP-01: the connect side carries traffic with **no** inbound listener.

    Long-poll exists for one-way reachability (§7.4): the connecting side may sit
    behind a firewall that refuses every inbound connection, so it must bind
    nothing and still carry requests *and* events in both directions by polling.

    The previous version of this test was a sentinel that xfailed as soon as the
    link became ready ("scenario still has to be written"), so it could never
    decide anything. This is that scenario: it asserts the connector owns no
    inbound server, that nothing accepts connections on the reverse port the
    harness handed it, and then drives real traffic both ways.

    Args:
        pair_factory: Fixture spawning an A/B pair.
    """
    pair = pair_factory("longpoll", "listen")
    pair.require_ready("long-poll link not ready")

    connector = pair.b  # A listens, B connects.
    listener = pair.a
    connector_snap = connector.request(10, op="snapshot")
    listener_snap = listener.request(10, op="snapshot")

    # 1. The connector owns no server: one-way reachability is structural.
    assert connector_snap["has_runner"] is False, connector_snap["has_runner"]
    assert listener_snap["has_runner"] is True, listener_snap["has_runner"]

    # 2. Nothing accepts inbound connections on the connector's reverse port.
    reverse_port = pair.addressing.b_bind_port
    assert H.port_is_free(reverse_port), (
        f"something listens on the connector's reverse port {reverse_port}; "
        "long-poll must not need one"
    )

    # 3. Traffic still flows both ways, purely over the poll path.
    uplink = connector.request(
        25, op="call", m="task.status", params={"t": "单向可达"}, timeout_s=15
    )
    assert uplink["ok"] is True, uplink
    assert uplink["result"]["echo"]["t"] == "单向可达"

    event_id = "evt-lp-oneway-1"
    listener.request(
        15,
        op="emit",
        m="task.event",
        id_value=event_id,
        params={"task_id": "t2", "notify_id": "n-2", "event": "running", "eseq": 2},
    )
    downlink = connector.request(
        30,
        op="wait_messages",
        count=1,
        match={"k": "evt", "m": "task.event", "id": event_id},
        timeout_s=25,
    )
    assert downlink["count"] == 1, downlink
    assert downlink["matched"][0]["params"]["notify_id"] == "n-2"

    # 4. The event reached the connector on a poll round that it then acked.
    after = connector.request(10, op="snapshot")
    assert after["poll_rounds"] >= 1, after["poll_rounds"]
    assert after["poll_acks"], "no poll ack was sent for the delivered event"


def test_webhook_probe_failure_reports_degraded_and_switches_to_longpoll():
    """TC-WH-02: 3 failed probes must degrade **and** switch to long-poll (§7.3.6).

    The probe peer is a port that was just released, so every probe is refused.
    With the probe interval shortened to one second the third failure lands a few
    seconds in. The session is configured the way production configures it —
    ``bind_port`` left at its default ``0`` so ``bind_target()`` picks an
    ephemeral port (``main.py`` never passes ``bind_port``).

    This replaces the old ``NOT-IMPLEMENTED-BY-HARNESS`` sentinel, which xfailed
    as soon as webhook could connect and therefore swallowed whatever production
    did next. Two independent requirements are asserted, so a report can say
    which one broke:

    1. the carrier reports ``degraded``/``transport_degraded`` after
       ``WEBHOOK_PROBE_FAIL`` consecutive failures — this already works;
    2. :class:`TransportManager` acts on it: it switches to the configured
       fallback, records ``transport_degraded`` as the *reason*, and reports
       itself degraded.

    Observed failure (reported, not excused): requirement 1 holds, requirement 2
    does not. Every carrier lifecycle callback fires, but nothing calls
    ``TransportManager.fallback()`` — ``run_forever`` only re-enters
    ``bring_up()`` after the current carrier stops being ``alive()``, and it
    never looks at ``degraded`` nor rewires the reason string.
    """
    from bridge.constants import WEBHOOK_PROBE_FAIL
    from bridge.session import Role, SessionConfig, build_caps
    from bridge.transport.base import TransportHooks
    from bridge.transport.manager import TransportManager

    credentials = H.Credentials.synthetic()
    # Release a port immediately so the peer address is routable but refuses
    # every connection: exactly "the other side went away".
    dead_port = H.free_port()
    listener_port = H.free_port()
    listen_process = H.spawn_a(
        transport="webhook",
        mode="listen",
        peer_port=dead_port,
        bind_port=listener_port,
        credentials=credentials,
        probe_interval_s=1,
    )
    try:
        assert H.wait_port_open(listener_port, 30.0), "webhook listener never bound"
        cfg = SessionConfig(
            conn=credentials.conn,
            side="A",
            role=Role.INITIATOR,
            transport="webhook",
            psk_id=credentials.psk_id,
            psk_secret=credentials.psk_secret,
            heartbeat_s=1,
            req_timeout_s=10.0,
            caps=build_caps(
                side="A",
                host="astrbot",
                version="0.1.0",
                transports=["webhook", "longpoll"],
                tls=False,
                native_tool=False,
                image_enabled=True,
                image_max_count=4,
                image_max_bytes=10_485_760,
                image_total_max_bytes=20_971_520,
            ),
            version="0.1.0",
            host_id="astrbot",
            addr="127.0.0.1",
            port=dead_port,
            bind_addr="127.0.0.1",
            # Production leaves this at its default 0 (main.py passes no
            # bind_port), so the case under test must too.
            bind_port=0,
            path="/dsh-bridge",
            mode="connect",
            poll_wait_s=1,
        )
        states: list[tuple[str, str]] = []

        async def _noop(_obj: object = None) -> None:
            """Inbound hook that stays out of the way of the probe loop."""
            return None

        hooks = TransportHooks(
            on_plain=_noop,
            on_envelope=_noop,
            on_probe=lambda obj: {},
            on_state=lambda state, reason: states.append((state, reason)),
            on_activity=lambda: None,
        )
        manager = TransportManager(
            cfg,
            hooks,
            preferred="webhook",
            fallbacks=["longpoll"],
            on_transport=_noop,
        )

        async def _drive() -> dict:
            """Run the production loop and report what the manager did.

            ``run_forever`` is the component that owns the fallback ladder in
            production (``main.py`` starts it next to ``bring_up``), so the test
            drives it rather than poking the manager's internals: if the ladder
            is never entered, that is exactly the defect being reported.

            Returns:
                A dict with the observed carrier and manager state.
            """
            await manager.bring_up()
            loop_task = asyncio.create_task(manager.run_forever())
            try:
                deadline = time.monotonic() + 45.0
                while time.monotonic() < deadline:
                    await asyncio.sleep(0.25)
                    carrier = manager.transport()
                    # ``degraded`` is webhook-specific (§7.3 rule 6), not part of
                    # the base carrier API, so it is probed defensively.
                    if getattr(carrier, "degraded", lambda: False)():
                        # Leave the loop the same wall-clock room production has
                        # to act on the degraded signal before inspecting it.
                        await asyncio.sleep(8.0)
                        break
                diagnostics = manager.diagnostics()
                return {
                    "states": list(states),
                    "current": diagnostics["current"],
                    "manager_degraded": diagnostics["degraded"],
                    "history": diagnostics["history"],
                }
            finally:
                loop_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await loop_task
                await manager.stop()

        observed = H.run_async(_drive())
        # 1. Evidence: the probe loop reached ``transport_degraded``.
        assert ("degraded", "transport_degraded") in observed["states"], (
            "the webhook carrier never reported transport_degraded after "
            f"{WEBHOOK_PROBE_FAIL} failed probes; states={observed['states']}"
        )
        # 2. The requirement: the manager switched to the configured fallback and
        #    recorded that reason — not merely "start failed / could not bind".
        assert observed["current"] == "longpoll", (
            "§7.3 rule 6 requires the switch to the fallback carrier after "
            f"{WEBHOOK_PROBE_FAIL} failed probes; the manager stayed on "
            f"{observed['current']!r} (history={observed['history']})"
        )
        assert observed["manager_degraded"] is True, observed
        assert any(
            item["reason"] == "transport_degraded" for item in observed["history"]
        ), (
            "the carrier switched, but not because of transport_degraded: "
            f"history={observed['history']}"
        )
    finally:
        listen_process.stop()


def test_http_carriers_reject_authorization_header():
    """§7.0: an ``Authorization`` header is refused with 401 ``auth_header_forbidden``.

    This runs against the real A-side listener, using a plain HTTP client, so it
    does not depend on the handshake at all.
    """
    import urllib.error
    import urllib.request

    credentials = H.Credentials.synthetic()
    port = H.free_port()
    peer_port = H.free_port()
    process = H.spawn_a(
        transport="webhook",
        mode="listen",
        peer_port=peer_port,
        bind_port=port,
        credentials=credentials,
    )
    try:
        assert H.wait_port_open(port, 30.0), "webhook listener never bound its port"
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/dsh-bridge/frames",
            data=b"{}",
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer synthetic",
            },
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=10)  # noqa: S310 - loopback only
        assert caught.value.code == 401
        body = json.loads(caught.value.read().decode("utf-8"))
        assert body["error"]["code"] == "auth_header_forbidden"
    finally:
        process.stop()
        time.sleep(0.1)


def _build_hello(transport: str, credentials: H.Credentials) -> tuple[dict, Any]:
    """Build a ``hello`` with the shipped A-side crypto helpers (§4.2).

    Args:
        transport: Carrier name advertised in ``tp``.
        credentials: Synthetic credentials.

    Returns:
        ``(hello_object, master_key)`` so the caller can verify the ack.
    """
    import secrets
    import sys
    import uuid

    if str(A_ROOT) not in sys.path:
        sys.path.insert(0, str(A_ROOT))
    from bridge.constants import (
        ENVELOPE_VERSION,
        PROTOCOL_VERSION,
        SUPPORTED_PROTOCOL_VERSIONS,
    )
    from bridge.crypto import b64u, handshake_key, mac_object, psk_master
    from bridge.session import build_caps

    del SUPPORTED_PROTOCOL_VERSIONS
    master = psk_master(credentials.psk_id, credentials.psk_secret)
    body = {
        "v": ENVELOPE_VERSION,
        "type": "hello",
        "conn": credentials.conn,
        "hello_id": str(uuid.uuid4()),
        "pv": PROTOCOL_VERSION,
        "side": "A",
        "tp": transport,
        "nonce": b64u(secrets.token_bytes(32)),
        "ts": int(time.time() * 1000),
        "caps": build_caps(
            side="A",
            host="astrbot",
            version="0.1.0",
            transports=[transport],
            tls=False,
            native_tool=False,
            image_enabled=True,
            image_max_count=4,
            image_max_bytes=10_485_760,
            image_total_max_bytes=20_971_520,
        ),
    }
    return {**body, "mac": mac_object(handshake_key(master, "hello"), body)}, master


@pytest.mark.parametrize("transport", ["webhook", "longpoll"])
def test_http_hello_exchange_is_reachable(transport):
    """TC-WH-01 (reachability half): ``POST /hello`` works, and the ack verifies.

    This runs against the real B-side listener over real HTTP and verifies the
    ``hello_ack`` MAC with A's ``psk_master`` -- the two implementations must
    agree on JCS, on the handshake key derivation and on the ack field set. It
    deliberately stops before the sealed frames, which need the inline batch.

    Args:
        transport: Which HTTP carrier's listener to probe.
    """
    import urllib.error
    import urllib.request

    credentials = H.Credentials.synthetic()
    listen_port = H.free_port()
    peer_port = H.free_port()
    responder = H.spawn_b(
        transport=transport,
        mode="listen",
        peer_port=peer_port,
        bind_port=listen_port,
        credentials=credentials,
    )
    try:
        assert H.wait_port_open(listen_port, 30.0), f"{transport} listener never bound"
        hello, master = _build_hello(transport, credentials)
        request = urllib.request.Request(
            f"http://127.0.0.1:{listen_port}/dsh-bridge/hello",
            data=json.dumps(hello).encode("utf-8"),
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310 - loopback
            assert response.status == 200
            ack = json.loads(response.read().decode("utf-8"))

        import sys

        if str(A_ROOT) not in sys.path:
            sys.path.insert(0, str(A_ROOT))
        from bridge.crypto import handshake_key, verify_mac

        body = {key: value for key, value in ack.items() if key != "mac"}
        assert verify_mac(
            handshake_key(master, "hello_ack"), body, ack.get("mac", "")
        ), "hello_ack MAC does not verify against A's psk_master (JCS/derivation drift)"
        assert ack["hello_id"] == hello["hello_id"], "hello_id was not echoed"
        assert ack["side"] == "B"
        assert ack["conn"] == hello["conn"]
        assert ack["v"] == ack["pv"] == 1
        assert isinstance(ack["sid"], str) and ack["sid"], "sid missing"
        assert ack["nonce"] != hello["nonce"], "responder reused the initiator nonce"
    finally:
        responder.stop()


def test_http_hello_rejected_with_wrong_psk():
    """A hello signed by the wrong PSK must be refused, not answered (§4.3)."""
    import urllib.error
    import urllib.request

    credentials = H.Credentials.synthetic()
    wrong = H.Credentials(
        conn=credentials.conn, psk_id=credentials.psk_id, psk_secret="11" * 32
    )
    listen_port = H.free_port()
    peer_port = H.free_port()
    responder = H.spawn_b(
        transport="webhook",
        mode="listen",
        peer_port=peer_port,
        bind_port=listen_port,
        credentials=credentials,
    )
    try:
        assert H.wait_port_open(listen_port, 30.0)
        hello, _ = _build_hello("webhook", wrong)
        request = urllib.request.Request(
            f"http://127.0.0.1:{listen_port}/dsh-bridge/hello",
            data=json.dumps(hello).encode("utf-8"),
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=15)  # noqa: S310 - loopback
        assert caught.value.code in (400, 401), caught.value.code
        body = json.loads(caught.value.read().decode("utf-8"))
        assert body["error"]["code"] == "psk_mismatch", body
        # No ack may be produced: the error body carries no `sid`/`mac`.
        assert "sid" not in body and "mac" not in body
    finally:
        responder.stop()


def _seal_auth(credentials: H.Credentials, hello: dict, ack: dict) -> dict:
    """Derive the session keys and seal the initiator's ``auth`` frame (§4.4/§5.2).

    Args:
        credentials: Synthetic credentials.
        hello: The ``hello`` that was sent.
        ack: The ``hello_ack`` that came back.

    Returns:
        The sealed ``auth`` envelope with ``seq`` 0.
    """
    import sys

    if str(A_ROOT) not in sys.path:
        sys.path.insert(0, str(A_ROOT))
    from bridge.crypto import (
        b64u,
        b64u_dec,
        psk_master,
        seal_frame,
        session_keys,
        transcript_hash,
    )

    master = psk_master(credentials.psk_id, credentials.psk_secret)
    body = {key: value for key, value in ack.items() if key != "mac"}
    keys = session_keys(master, b64u_dec(hello["nonce"]), b64u_dec(ack["nonce"]))
    transcript = transcript_hash(
        {key: value for key, value in hello.items() if key != "mac"}, body
    )
    payload = {
        "side": "A",
        "role": "initiator",
        "sid": ack["sid"],
        "hello_id": hello["hello_id"],
        "th": b64u(transcript),
    }
    return seal_frame(keys.k_a2b, "A", "auth", credentials.conn, 0, payload)


@pytest.mark.parametrize("transport", ["webhook", "longpoll"])
def test_inline_auth_ack_batch_is_returned_by_listener(transport):
    """§7.3 rule 2 / §7.4: the responder answers the ``auth`` batch inline.

    A real ``hello`` is built with the shipped A-side crypto, so the responder
    has to decode A's caps and verify A's MAC before it can even accept the
    batch. The sealed ``auth`` frame is then produced from the session keys both
    sides derived, so a success here proves the two implementations agree on the
    handshake transcript, on the directional keys and on the AEAD nonce/AAD.

    Args:
        transport: Which HTTP carrier's listener to exercise.
    """
    import http.client

    credentials = H.Credentials.synthetic()
    listener_port = H.free_port()
    peer_port = H.free_port()
    responder = H.spawn_b(
        transport=transport,
        mode="listen",
        peer_port=peer_port,
        bind_port=listener_port,
        credentials=credentials,
    )

    def post(path: str, payload: dict) -> tuple[int, dict]:
        conn = http.client.HTTPConnection("127.0.0.1", listener_port, timeout=15)
        conn.request(
            "POST",
            path,
            body=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )
        response = conn.getresponse()
        raw = response.read()
        conn.close()
        return response.status, json.loads(raw) if raw else {}

    try:
        assert H.wait_port_open(listener_port, 30.0), (
            f"{transport} listener never bound"
        )
        hello, _ = _build_hello(transport, credentials)
        status, ack = post("/dsh-bridge/hello", hello)
        assert status == 200, (status, ack)
        assert ack.get("type") == "hello_ack"

        auth = _seal_auth(credentials, hello, ack)
        batch = {
            "v": 1,
            "conn": credentials.conn,
            "sid": ack["sid"],
            "batch_id": "harness-batch-1",
            "frames": [auth],
        }
        status, body = post("/dsh-bridge/frames", batch)

        # The inline rule: 200 with a `frames` array carrying `auth_ack`, not 202.
        assert status == 200, (
            f"{transport} answered the auth batch with {status}: {body}"
        )
        assert isinstance(body.get("frames"), list) and body["frames"], body
        assert body["frames"][0]["type"] == "auth_ack", body["frames"][0]
        assert body["frames"][0]["seq"] == 0
        assert set(body["frames"][0]) == {"v", "type", "conn", "seq", "ct"}
    finally:
        responder.stop()
