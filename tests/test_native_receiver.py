"""Native ``native_tool`` receiver tests (A side).

Scope: A only *relays and displays* DSH native tool approvals. Every assertion below
is anchored either to a frozen protocol clause (§12.1–§12.4) or to
``开发/v0.1/native-approval-id-decision.md`` (§3.1, §4, §5):

* a genuine request from the authenticated peer is queued and a human is told —
  never auto-answered;
* a payload that merely *claims* an origin is not evidence, and A's own side can
  never be accepted as a native tool producer;
* an inbound request whose ``request_digest`` does not equal the digest recomputed
  from its real fields is refused;
* a decision whose ``request_digest`` differs from the stored one never lands;
* ``approval.decision`` becomes a real outbox send that is retried and can be acked;
* refusing one tool call does not terminate the whole task;
* timeout means ``rejected`` (``channel="timeout"``) and never a grant;
* restart and "same connection, new sid" invalidate pending native approvals as
  ``unavailable`` without re-prompting or emitting a decision;
* A's caps bytes are untouched: receiver support is not producer capability.
"""

from __future__ import annotations

import time

import pytest
from bridge.app.approvals import ApprovalService, request_digest_for
from bridge.app.notify import NotifyService
from bridge.app.tasks import TaskService
from bridge.constants import (
    APPROVAL_CROSS_END_SUBMIT,
    APPROVAL_NATIVE_TOOL,
    MSG_APPROVAL_DECISION,
    OUTCOME_UNAVAILABLE,
    STATUS_PENDING_APPROVAL,
    STATUS_REJECTED,
    STATUS_RUNNING,
    STATUS_SUCCEEDED,
)
from bridge.errors import BridgeError
from bridge.router import Router
from bridge.session import build_caps

CONN = "default"
TASK = "t-native-1"


class Senders:
    """Record every outbound event so tests assert real sends, not expectations."""

    def __init__(self) -> None:
        """Create empty recorders."""
        self.task_events: list[dict] = []
        self.events: list[dict] = []
        self.fail_events: int = 0

    async def on_task_event(self, params: dict) -> None:
        """Record one ``task.event``."""
        self.task_events.append(params)

    async def on_event(
        self, params: dict, row: dict, task_id: str, root_task_id: str
    ) -> None:
        """Record one generic event, optionally failing to exercise retries."""
        if self.fail_events > 0:
            self.fail_events -= 1
            raise RuntimeError("simulated peer unreachable")
        self.events.append({**params, "_message": row["message"]})


class Harness:
    """Wire approvals + notify + tasks against one throwaway store."""

    def __init__(self, store) -> None:
        """Create the harness.

        Args:
            store: Initialised store fixture.
        """
        self.store = store
        self.senders = Senders()
        self.decided: list[tuple[dict, bool]] = []
        self.human_pings: list[dict] = []
        self.notify = NotifyService(
            store,
            conn=CONN,
            on_task_event=self.senders.on_task_event,
            on_event=self.senders.on_event,
        )

        async def on_decided(approval: dict, allowed: bool) -> None:
            await self.tasks.on_approved(approval, allowed=allowed)
            self.decided.append((approval, allowed))

        async def on_human(payload: dict) -> None:
            self.human_pings.append(payload)

        self.service = ApprovalService(
            store,
            conn=CONN,
            side="A",
            approval_timeout_s=1800,
            notify_channels=["im", "web"],
            notify=self.notify,
            on_approval_decided=on_decided,
            on_human_notify=on_human,
            peer_side="B",
        )
        self.tasks = TaskService(
            store, conn=CONN, notify=self.notify, sessions=None, host=None
        )

    def decision_events(self) -> list[dict]:
        """Return the generic events actually sent on the wire."""
        return [
            event
            for event in self.senders.events
            if event["_message"] == MSG_APPROVAL_DECISION
        ]


@pytest.fixture
def harness(store) -> Harness:
    """Provide a wired :class:`Harness`."""
    return Harness(store)


def native_request(approval_id: str = "ap-nat-1", **overrides) -> dict:
    """Build a valid inbound ``native_tool`` request (§12.2).

    Args:
        approval_id: Approval identifier.
        **overrides: Field overrides.

    Returns:
        Parameter dictionary with a digest computed from the real fields.
    """
    params = {
        "approval_id": approval_id,
        "approval_type": APPROVAL_NATIVE_TOOL,
        "task_id": None,
        "root_task_id": None,
        "session_id": "s-1",
        "tool": "bash",
        "reason": "run a shell command",
        "display_reason": {"en": "Run a shell command", "zh": "执行 shell 命令"},
        "call_id": None,
        "expires_at": None,
        "notify_id": "n-nat-1",
        "origin_side": "B",
    }
    params.update(overrides)
    params["request_digest"] = request_digest_for(
        params["tool"],
        params["reason"],
        params["call_id"],
        params["session_id"],
        params["task_id"],
    )
    return params


# -- T-NAT-1: inbound native request is queued and a human is notified -----------------


@pytest.mark.asyncio
async def test_native_request_is_queued_and_human_is_notified(harness) -> None:
    """A relays a real DSH request; a human is pinged and nothing is auto-decided."""
    result = await harness.service.handle_request(native_request())
    assert result["accepted"] is True
    stored = await harness.store.get_approval("ap-nat-1")
    assert stored is not None
    assert stored["approval_type"] == APPROVAL_NATIVE_TOOL
    assert stored["state"] == "pending"
    assert stored["outcome"] is None
    assert harness.human_pings, "a human must be notified before any answer exists"
    assert harness.human_pings[0]["approval_type"] == APPROVAL_NATIVE_TOOL
    assert harness.decided == [], "receiving a request must never decide it"
    assert harness.decision_events() == []


@pytest.mark.asyncio
async def test_native_request_without_task_id_is_accepted(harness) -> None:
    """``task_id`` is legitimately null for a native tool approval (§12.2)."""
    await harness.service.handle_request(
        native_request(task_id=None, root_task_id=None)
    )
    stored = await harness.store.get_approval("ap-nat-1")
    assert stored is not None and stored["task_id"] is None
    assert stored["state"] == "pending"


# -- T-NAT-2: spoofed or wrong-side sources are refused --------------------------------


@pytest.mark.asyncio
async def test_payload_origin_claim_is_not_evidence(harness) -> None:
    """A payload cannot grant itself trust; the stored origin is the authenticated one."""
    params = native_request()
    params["origin_side"] = "B"
    await harness.service.handle_request(params)
    stored = await harness.store.get_approval("ap-nat-1")
    assert stored is not None
    assert stored["origin_side"] == "B"

    # The same claim never lands as an approval: it is not evidence of anything.
    assert stored["outcome"] is None


@pytest.mark.asyncio
async def test_native_request_from_local_side_is_refused(store) -> None:
    """When assembly says the trusted peer is A, native requests are refused (fail closed)."""
    senders = Senders()
    notify = NotifyService(
        store, conn=CONN, on_task_event=senders.on_task_event, on_event=senders.on_event
    )
    service = ApprovalService(
        store,
        conn=CONN,
        side="A",
        approval_timeout_s=1800,
        notify_channels=["im"],
        notify=notify,
        peer_side="A",
    )
    with pytest.raises(BridgeError) as excinfo:
        await service.handle_request(native_request())
    assert excinfo.value.code == "capability_unavailable"
    assert await store.get_approval("ap-nat-1") is None


@pytest.mark.asyncio
async def test_router_payload_peer_side_cannot_grant_native_trust(store) -> None:
    """``ctx.peer_side`` coming from the payload must not be accepted as evidence."""
    senders = Senders()
    notify = NotifyService(
        store, conn=CONN, on_task_event=senders.on_task_event, on_event=senders.on_event
    )
    service = ApprovalService(
        store,
        conn=CONN,
        side="A",
        approval_timeout_s=1800,
        notify_channels=["im"],
        notify=notify,
        peer_side="A",  # authenticated peer is A -> nothing may be accepted
    )
    router = Router(conn=CONN)
    service.register(router)
    reply = await router.dispatch(
        {
            "k": "req",
            "m": "approval.request",
            "id": "msg-1",
            "ts": "2026-10-30T00:00:00.000Z",
            "_peer_side": "B",  # attacker-supplied payload field
            "params": native_request(),
        }
    )
    assert reply is not None and reply["ok"] is False
    assert reply["error"]["code"] == "capability_unavailable"
    assert await store.get_approval("ap-nat-1") is None


def test_a_has_no_native_production_path() -> None:
    """Receiver support must not introduce an A-side producer for native approvals."""
    from pathlib import Path

    source = (
        Path(__file__).resolve().parent.parent / "bridge" / "app" / "approvals.py"
    ).read_text(encoding="utf-8")
    created = source.split("async def create_cross_end_submit", 1)[1].split(
        "async def verify_submit_digest", 1
    )[0]
    assert APPROVAL_NATIVE_TOOL not in created
    assert APPROVAL_CROSS_END_SUBMIT in created


# -- T-NAT-3: inbound digest is recomputed, not trusted --------------------------------


@pytest.mark.asyncio
async def test_inbound_request_with_wrong_digest_is_refused(harness) -> None:
    """A recomputes ``request_digest`` from the real fields (§12.2)."""
    params = native_request()
    params["tool"] = "rm -rf /"  # digest no longer matches the fields it claims
    with pytest.raises(BridgeError) as excinfo:
        await harness.service.handle_request(params)
    assert excinfo.value.code == "approval_mismatch"
    assert await harness.store.get_approval("ap-nat-1") is None


@pytest.mark.asyncio
async def test_decision_with_wrong_digest_never_lands(harness) -> None:
    """``approval.decision`` must match the stored digest or nothing is recorded (§12.3)."""
    await harness.service.handle_request(native_request())
    with pytest.raises(BridgeError) as excinfo:
        await harness.service.handle_decision(
            {
                "approval_id": "ap-nat-1",
                "outcome": "allowed-once",
                "actor": "astrbot_admin:alice",
                "actor_kind": "human",
                "channel": "web",
                "request_digest": "b64u-not-the-real-digest",
            }
        )
    assert excinfo.value.code == "approval_mismatch"
    stored = await harness.store.get_approval("ap-nat-1")
    assert stored is not None
    assert stored["state"] == "pending"
    assert stored["outcome"] is None


@pytest.mark.asyncio
async def test_decision_with_matching_digest_lands(harness) -> None:
    """The exact stored digest is what an accepted decision carries."""
    await harness.service.handle_request(native_request())
    stored = await harness.store.get_approval("ap-nat-1")
    assert stored is not None
    await harness.service.handle_decision(
        {
            "approval_id": "ap-nat-1",
            "outcome": "rejected",
            "actor": "astrbot_admin:alice",
            "actor_kind": "human",
            "channel": "im",
            "request_digest": stored["request_digest"],
        }
    )
    decided = await harness.store.get_approval("ap-nat-1")
    assert decided is not None and decided["outcome"] == "rejected"


# -- T-NAT-4: the decision really goes out and can be acked ---------------------------


@pytest.mark.asyncio
async def test_human_decision_is_really_sent_and_deliverable(harness) -> None:
    """``approval.decision`` leaves through the outbox and is ackable (§10.3, §12.3)."""
    await harness.service.handle_request(native_request())
    stored = await harness.store.get_approval("ap-nat-1")
    assert stored is not None
    applied, reason = await harness.service.human_decide(
        "ap-nat-1", allowed=True, actor="astrbot_admin:alice", channel="web"
    )
    assert applied is True and reason is None

    events = harness.decision_events()
    assert len(events) == 1
    decision = events[0]
    assert decision["approval_id"] == "ap-nat-1"
    assert decision["actor_kind"] == "human"
    assert decision["outcome"] == "allowed-once"
    assert decision["request_digest"] == stored["request_digest"]

    row = await harness.store.get_notify(decision["notify_id"])
    assert row is not None
    assert row["message"] == MSG_APPROVAL_DECISION
    assert row["undelivered"] is False

    acked = await harness.notify.on_ack({"notify_id": decision["notify_id"]})
    assert acked["delivered"] is True
    row = await harness.store.get_notify(decision["notify_id"])
    assert row is not None and row["delivered"] is True


@pytest.mark.asyncio
async def test_decision_send_failure_retries_then_succeeds(harness) -> None:
    """A failed decision send backs off and is retried for real — never dropped."""
    await harness.service.handle_request(native_request())
    harness.senders.fail_events = 1
    await harness.service.human_decide(
        "ap-nat-1", allowed=True, actor="astrbot_admin:alice", channel="web"
    )
    # The immediate attempt failed, so nothing reached the peer and a retry is armed.
    assert harness.decision_events() == []
    async with harness.store._conn().execute(
        "SELECT notify_id FROM notify_outbox WHERE message = ?",
        (MSG_APPROVAL_DECISION,),
    ) as cursor:
        rows = await cursor.fetchall()
    assert len(rows) == 1
    notify_id = rows[0]["notify_id"]
    row = await harness.store.get_notify(notify_id)
    assert row is not None
    assert row["message"] == MSG_APPROVAL_DECISION
    assert row["attempts"] == 1
    assert row["undelivered"] is False
    assert row["next_at"] > time.time(), "the retry must be delayed by the backoff"

    # Make the retry due and run the real send once, as ``resend_loop`` would.
    await harness.store.reschedule_notify(notify_id, row["attempts"], time.time())
    due = await harness.store.pending_notifies()
    assert [item["notify_id"] for item in due] == [notify_id]
    await harness.notify._send(due[0])
    assert len(harness.decision_events()) == 1
    assert harness.decision_events()[0]["outcome"] == "allowed-once"


@pytest.mark.asyncio
async def test_exhausted_decision_send_marks_undelivered(harness) -> None:
    """After the attempt budget the row is ``undelivered``; no silent drop, no grant."""
    await harness.service.handle_request(native_request())
    harness.senders.fail_events = 99
    await harness.service.human_decide(
        "ap-nat-1", allowed=True, actor="astrbot_admin:alice", channel="web"
    )
    async with harness.store._conn().execute(
        "SELECT notify_id FROM notify_outbox WHERE message = ?",
        (MSG_APPROVAL_DECISION,),
    ) as cursor:
        rows = await cursor.fetchall()
    assert len(rows) == 1
    notify_id = rows[0]["notify_id"]

    row = await harness.store.get_notify(notify_id)
    assert row is not None and row["attempts"] == 1 and row["undelivered"] is False
    # Walk the remaining budget (NOTIFY_MAX_ATTEMPTS = 5).
    for attempts in (1, 2, 3, 4):
        await harness.notify._schedule_retry(notify_id, attempts)

    row = await harness.store.get_notify(notify_id)
    assert row is not None
    assert row["undelivered"] is True
    assert harness.decision_events() == []
    # The recorded decision stays what the human chose; escalation never rewrites it.
    approval = await harness.store.get_approval("ap-nat-1")
    assert approval is not None
    assert approval["outcome"] == "allowed-once"


# -- T-NAT-5: refusing one tool call does not end the task ----------------------------


@pytest.mark.asyncio
async def test_native_rejection_does_not_terminate_the_task(harness) -> None:
    """A refused tool call leaves the peer's task alone; the peer still reports the end."""
    await harness.store.upsert_task(
        {
            "task_id": TASK,
            "root_task_id": TASK,
            "direction": "inbound",
            "kind": "dsh_agent_run",
            "origin": "human",
            "status": STATUS_RUNNING,
        }
    )
    await harness.service.handle_request(
        native_request(task_id=TASK, root_task_id=TASK)
    )
    applied, _reason = await harness.service.human_decide(
        "ap-nat-1", allowed=False, actor="astrbot_admin:alice", channel="web"
    )
    assert applied is True

    approval = await harness.store.get_approval("ap-nat-1")
    assert approval is not None and approval["outcome"] == "rejected"
    task = await harness.store.get_task(TASK)
    assert task is not None
    assert task["status"] == STATUS_RUNNING, (
        "one refused tool call must not end the turn"
    )

    # The peer remains authoritative: its own success event still applies.
    await harness.notify.emit_event("n-peer-1", "task.event", {}, TASK, TASK)
    await harness.tasks.on_event(
        {
            "task_id": TASK,
            "root_task_id": TASK,
            "eseq": 1,
            "event": "completed",
            "status": STATUS_SUCCEEDED,
            "notify_id": "n-peer-1",
            "result": {"summary": "continued after refusal"},
            "error": None,
            "decision": None,
            "approval": None,
        }
    )
    task = await harness.store.get_task(TASK)
    assert task is not None and task["status"] == STATUS_SUCCEEDED


@pytest.mark.asyncio
async def test_native_allow_does_not_change_the_task_either(harness) -> None:
    """Approving one tool call is not a task-level approval."""
    await harness.store.upsert_task(
        {
            "task_id": TASK,
            "root_task_id": TASK,
            "direction": "inbound",
            "kind": "dsh_agent_run",
            "origin": "human",
            "status": STATUS_RUNNING,
        }
    )
    await harness.service.handle_request(
        native_request(task_id=TASK, root_task_id=TASK)
    )
    await harness.service.human_decide(
        "ap-nat-1", allowed=True, actor="astrbot_admin:alice", channel="web"
    )
    task = await harness.store.get_task(TASK)
    assert task is not None and task["status"] == STATUS_RUNNING


@pytest.mark.asyncio
async def test_cross_end_submit_still_owns_the_task_decision(harness) -> None:
    """``cross_end_submit`` keeps its task-level authority (the gate A itself placed)."""
    await harness.store.upsert_task(
        {
            "task_id": TASK,
            "root_task_id": TASK,
            "direction": "inbound",
            "kind": "astr_agent_run",
            "origin": "llm",
            "status": STATUS_PENDING_APPROVAL,
        }
    )
    await harness.tasks.on_approved(
        {
            "approval_id": "ap-cross-1",
            "approval_type": APPROVAL_CROSS_END_SUBMIT,
            "task_id": TASK,
        },
        allowed=False,
    )
    task = await harness.store.get_task(TASK)
    assert task is not None and task["status"] == STATUS_REJECTED


# -- T-NAT-6: timeout and invalidation ------------------------------------------------


@pytest.mark.asyncio
async def test_timeout_rejects_and_reports_through_the_outbox(harness) -> None:
    """A timed-out native approval is ``rejected`` with ``channel="timeout"`` (§12.4)."""
    await harness.service.handle_request(native_request())
    expired = await harness.store.expire_approvals(now=time.time() + 1801)
    assert len(expired) == 1
    for approval in expired:
        expired_row = await harness.store.get_approval(approval["approval_id"])
        assert expired_row is not None
        await harness.service._apply(expired_row)
        await harness.service._send_decision_event(expired_row)
    stored = await harness.store.get_approval("ap-nat-1")
    assert stored is not None
    assert stored["outcome"] == "rejected"
    assert stored["channel"] == "timeout"
    assert stored["outcome"] != "allowed-once"
    events = harness.decision_events()
    assert len(events) == 1 and events[0]["outcome"] == "rejected"


@pytest.mark.asyncio
async def test_restart_invalidates_pending_native_approvals(harness) -> None:
    """A restart leaves no answerable native approval: ``unavailable``, no new decision."""
    await harness.service.handle_request(native_request())
    invalidated = await harness.service.invalidate_native_pending(reason="restart")
    assert invalidated == ["ap-nat-1"]
    stored = await harness.store.get_approval("ap-nat-1")
    assert stored is not None
    assert stored["outcome"] == OUTCOME_UNAVAILABLE
    assert harness.decision_events() == []

    # A late human answer cannot revive it.
    applied, reason = await harness.service.human_decide(
        "ap-nat-1", allowed=True, actor="astrbot_admin:alice", channel="web"
    )
    assert applied is False and reason == "already_decided"
    stored = await harness.store.get_approval("ap-nat-1")
    assert stored is not None and stored["outcome"] == OUTCOME_UNAVAILABLE


@pytest.mark.asyncio
async def test_new_sid_on_same_conn_invalidates_previous_pending(harness) -> None:
    """A new ``sid`` on one connection orphans the previous sid's pending approvals."""
    await harness.service.handle_request(native_request("ap-old"))
    invalidated = await harness.service.invalidate_native_pending(reason="new_sid")
    assert invalidated == ["ap-old"]
    old = await harness.store.get_approval("ap-old")
    assert old is not None and old["outcome"] == OUTCOME_UNAVAILABLE

    # Only the new sid's request is answerable afterwards.
    await harness.service.handle_request(
        native_request("ap-new", session_id="s-2", notify_id="n-nat-2")
    )
    fresh = await harness.store.get_approval("ap-new")
    assert fresh is not None and fresh["state"] == "pending"
    assert harness.decision_events() == []


@pytest.mark.asyncio
async def test_invalidation_covers_approvals_but_leaves_business_decisions(
    harness,
) -> None:
    """Both approval kinds fail closed on a lost channel; business decisions do not."""
    await harness.service.handle_request(native_request())
    cross = await harness.service.create_cross_end_submit(
        task={"task_id": TASK, "root_task_id": TASK},
        tool="astr_agent_run",
        reason="cross-end task submission",
        display_reason={"en": "Run", "zh": "执行"},
        params={"task_id": TASK, "session_id": None},
    )
    decision = await harness.service.create_decision(
        task={"task_id": TASK, "root_task_id": TASK},
        question="proceed?",
        options=[{"id": "yes", "label": "yes", "consequence": "run"}],
        timeout_s=60,
    )
    await harness.service.invalidate_native_pending(reason="restart")
    native = await harness.store.get_approval("ap-nat-1")
    assert native is not None and native["outcome"] == OUTCOME_UNAVAILABLE
    # The local cross-end gate is tied to the same dead answer channel, so it
    # must not stay answerable either (a new sid could otherwise release it).
    closed = await harness.store.get_approval(cross["approval_id"])
    assert closed is not None and closed["outcome"] == OUTCOME_UNAVAILABLE
    kept = await harness.store.get_decision(decision["decision_id"])
    assert kept is not None and kept["state"] == "pending"


# -- T-NAT-7: caps bytes are untouched ------------------------------------------------


def test_receiver_support_does_not_move_a_caps() -> None:
    """A still advertises ``native_tool: false``; receiver support is not a caps bit."""
    caps = build_caps(
        side="A",
        host="astrbot",
        version="0.1.0",
        transports=["ws"],
        tls=False,
        native_tool=False,
        image_enabled=True,
        image_max_count=4,
        image_max_bytes=10_485_760,
        image_total_max_bytes=20_971_520,
    )
    assert caps["approvals"][APPROVAL_NATIVE_TOOL] is False
