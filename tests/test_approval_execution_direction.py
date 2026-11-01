"""Approval outcome vs. execution direction (``TaskService.on_approved``).

A ``cross_end_submit`` approval is used by both ends, but it only *owns* a task on
the side that accepted the submission:

* **inbound** — this side placed the gate, so a human decision releases or
  rejects its own task here;
* **outbound** — the row is a mirror of the peer's gate for a task this side
  submitted. The peer is the executor, so a local decision must not transition
  the task, must not emit a local terminal ``task.event`` and must never start a
  local run. The answer still travels back as ``approval.decision``.

These tests use a real :class:`Store`, a real ``NotifyService``, a real
``ApprovalService`` and a real ``TaskService``; only the host adapter and the
peer-facing session call are stubbed.
"""

from __future__ import annotations

import asyncio

import pytest
from bridge.app.approvals import ApprovalService, request_digest_for
from bridge.app.notify import NotifyService
from bridge.app.sessions import SessionService
from bridge.app.tasks import TaskService
from bridge.constants import (
    APPROVAL_CROSS_END_SUBMIT,
    MSG_APPROVAL_DECISION,
    STATUS_ACCEPTED,
    STATUS_PENDING_APPROVAL,
    STATUS_REJECTED,
    STATUS_SUCCEEDED,
)
from bridge.store import Store

CONN = "default"
INBOUND_TASK = "11111111-1111-4111-8111-111111111111"
OUTBOUND_TASK = "22222222-2222-4222-8222-222222222222"
FUTURE = "2099-01-01T00:00:00.000Z"


class StubHost:
    """Host adapter double counting how often a local agent run really started."""

    def __init__(self) -> None:
        """Create the stub with a zeroed counter."""
        self.calls = 0

    async def run_agent(self, *, task: dict) -> dict:
        """Simulate one agent run.

        Args:
            task: Task row.

        Returns:
            Result dictionary.
        """
        self.calls += 1
        return {"summary": "ok", "text": "done", "attachments": []}


class StubPeerSession:
    """Peer session double: the peer answers ``task.submit`` with a status."""

    def __init__(self, status: str) -> None:
        """Store the status the peer will report.

        Args:
            status: Status the peer returns for ``task.submit``.
        """
        self.status = status
        self.calls = 0

    async def call(self, message: str, params: dict, timeout_s: float = 0) -> dict:
        """Answer one outbound request.

        Args:
            message: Message name.
            params: Request parameters.
            timeout_s: Ignored.

        Returns:
            The peer's submit reply.
        """
        self.calls += 1
        assert message == "task.submit", message
        return {
            "task_id": params["task_id"],
            "status": self.status,
            "root_task_id": params["root_task_id"],
            "session_id": None,
            "poll_hint_ms": 10,
        }


class Harness:
    """Bundle the real services used by every case here."""

    def __init__(self) -> None:
        """Create empty recorders."""
        self.store: Store
        self.host = StubHost()
        self.task_events: list[dict] = []
        self.events: list[dict] = []
        self.human_pings: list[dict] = []
        self.approvals: ApprovalService
        self.tasks: TaskService

    def terminal_events(self) -> list[dict]:
        """Return the local ``task.event`` rows that claim a terminal status.

        Returns:
            Matching recorded events.
        """
        return [
            event
            for event in self.task_events
            if event["status"] in (STATUS_SUCCEEDED, STATUS_REJECTED, "failed")
        ]

    def decision_events(self) -> list[dict]:
        """Return the ``approval.decision`` messages actually emitted.

        Returns:
            Matching recorded events.
        """
        return [
            event for event in self.events if event["_message"] == MSG_APPROVAL_DECISION
        ]


async def build_harness(tmp_path, *, peer_status: str = STATUS_PENDING_APPROVAL):
    """Wire a real store, notify, approval and task service.

    Args:
        tmp_path: pytest temporary directory.
        peer_status: Status the peer reports for an outbound submission.

    Returns:
        The harness and the peer session double.
    """
    harness = Harness()
    store = Store()
    await store.init(tmp_path / "bridge.db")
    harness.store = store
    peer = StubPeerSession(peer_status)

    async def on_task_event(params: dict) -> None:
        harness.task_events.append(params)

    async def on_event(
        params: dict, row: dict, task_id: str, root_task_id: str
    ) -> None:
        harness.events.append({**params, "_message": row["message"]})

    notify = NotifyService(
        store,
        conn=CONN,
        on_task_event=on_task_event,
        on_event=on_event,
    )
    sessions = SessionService(store, conn=CONN)
    await sessions.init()

    async def on_decided(approval: dict, allowed: bool) -> None:
        await harness.tasks.on_approved(approval, allowed=allowed)

    async def on_human(payload: dict) -> None:
        harness.human_pings.append(payload)

    approvals = ApprovalService(
        store,
        conn=CONN,
        side="A",
        approval_timeout_s=1800,
        notify_channels=["web"],
        notify=notify,
        on_approval_decided=on_decided,
        on_human_notify=on_human,
    )
    harness.approvals = approvals
    harness.tasks = TaskService(
        store,
        conn=CONN,
        notify=notify,
        sessions=sessions,
        host=harness.host,
        approvals=approvals,
    )
    return harness, peer


def inbound_params(task_id: str = INBOUND_TASK, **overrides) -> dict:
    """Build a valid inbound ``task.submit`` parameter set.

    Args:
        task_id: Task identifier.
        **overrides: Field overrides.

    Returns:
        Parameter dictionary with every required field present.
    """
    params = {
        "task_id": task_id,
        "root_task_id": task_id,
        "kind": "astr_agent_run",
        "origin": "llm",
        "input_parts": [{"type": "text", "text": "请把用户表导出到对端"}],
        "attachments": [],
        "tool_hints": [],
        "session_id": None,
        "purpose": "export",
        "timeout_s": 60,
        "meta": {},
        "approval_ref": None,
    }
    params.update(overrides)
    return params


async def pending_approval_id(harness: Harness, task_id: str) -> str:
    """Return the pending ``cross_end_submit`` approval id bound to ``task_id``.

    Args:
        harness: Wired harness.
        task_id: Task the approval must belong to.

    Returns:
        The approval id.

    Raises:
        AssertionError: When no pending approval exists for the task.
    """
    rows = await harness.store.list_approvals(state="pending", limit=50)
    for row in rows:
        if row["task_id"] == task_id:
            return row["approval_id"]
    raise AssertionError(f"no pending approval for task {task_id}: {rows}")


async def mirror_peer_gate(harness: Harness, task_id: str) -> str:
    """Queue the peer's ``cross_end_submit`` question for an outbound task.

    This is exactly what the peer sends when it holds an inbound submission:
    an ``approval.request`` of type ``cross_end_submit`` carrying the task id.

    Args:
        harness: Wired harness.
        task_id: Outbound task the peer's gate belongs to.

    Returns:
        The approval id the peer asked about.
    """
    approval_id = f"peer-approval-{task_id}"
    params = {
        "approval_id": approval_id,
        "approval_type": APPROVAL_CROSS_END_SUBMIT,
        "task_id": task_id,
        "root_task_id": task_id,
        "session_id": None,
        "tool": "astr_agent_run",
        "reason": "cross-end task submission",
        "display_reason": {"en": "Run", "zh": "执行跨端任务"},
        "call_id": None,
        "request_digest": request_digest_for(
            "astr_agent_run",
            "cross-end task submission",
            None,
            None,
            task_id,
        ),
        "expires_at": FUTURE,
        "notify_id": f"notify-{task_id}",
        "origin_side": "B",
    }
    await harness.approvals.handle_request(params)
    return approval_id


# -- inbound: this side owns the gate, so it owns the execution ------------------------


@pytest.mark.asyncio
async def test_inbound_allowed_executes_once_locally(tmp_path) -> None:
    """An allowed inbound ``cross_end_submit`` releases exactly one local run."""
    harness, _peer = await build_harness(tmp_path)
    try:
        result = await harness.tasks.submit(inbound_params())
        assert result["status"] == STATUS_PENDING_APPROVAL, result
        await asyncio.sleep(0.05)
        assert harness.host.calls == 0
        # A held task has no acceptance to report: emitting `accepted` here
        # would both lie and consume event sequence 1 that the real acceptance
        # needs after the human answers.
        assert harness.task_events == [], harness.task_events

        approval_id = await pending_approval_id(harness, INBOUND_TASK)
        applied, reason = await harness.approvals.human_decide(
            approval_id, allowed=True, actor="astrbot_admin:alice", channel="web"
        )
        assert applied is True, reason

        await asyncio.sleep(0.1)
        stored = await harness.store.get_task(INBOUND_TASK)
        assert stored is not None and stored["status"] == STATUS_SUCCEEDED, stored
        assert harness.host.calls == 1
        accepted = [
            event for event in harness.task_events if event["event"] == "accepted"
        ]
        assert len(accepted) == 1, harness.task_events
        assert accepted[0]["eseq"] == 1, harness.task_events

        # A repeated decision changes nothing: the durable status is the latch.
        again, again_reason = await harness.approvals.human_decide(
            approval_id, allowed=True, actor="astrbot_admin:alice", channel="web"
        )
        assert again is False and again_reason == "already_decided"
        await asyncio.sleep(0.1)
        assert harness.host.calls == 1
        # A locally opened gate is decided locally: nothing is echoed back as
        # ``approval.decision`` to a peer that never asked.
        assert harness.decision_events() == []
    finally:
        await harness.tasks.stop()
        await harness.store.close()


@pytest.mark.asyncio
async def test_inbound_spent_gate_executes_nothing(tmp_path) -> None:
    """A gate already consumed by another task can never release this one."""
    harness, _peer = await build_harness(tmp_path)
    try:
        result = await harness.tasks.submit(inbound_params())
        assert result["status"] == STATUS_PENDING_APPROVAL, result
        approval_id = await pending_approval_id(harness, INBOUND_TASK)
        # Simulate a replay/second task that already spent the human decision.
        claimed = await harness.store.claim_approval_consumption(
            approval_id, "another-task"
        )
        assert claimed is True

        applied, reason = await harness.approvals.human_decide(
            approval_id, allowed=True, actor="astrbot_admin:alice", channel="web"
        )
        assert applied is True, reason
        await asyncio.sleep(0.1)
        stored = await harness.store.get_task(INBOUND_TASK)
        assert stored is not None and stored["status"] == "needs_human", stored
        assert harness.host.calls == 0
        assert not [
            event for event in harness.task_events if event["event"] == "accepted"
        ], harness.task_events
    finally:
        await harness.tasks.stop()
        await harness.store.close()


# -- outbound: the peer owns the gate and the execution -------------------------------


@pytest.mark.asyncio
async def test_outbound_allowed_never_executes_locally(tmp_path) -> None:
    """Allowing a mirrored gate leaves the outbound task alone and runs nothing."""
    harness, peer = await build_harness(tmp_path)
    try:
        submitted = await harness.tasks.submit_outbound(
            session=peer,
            input_parts=[{"type": "text", "text": "请对端导出用户表"}],
            purpose="export",
            timeout_s=60,
        )
        assert submitted["task_id"] == OUTBOUND_TASK or submitted["status"]
        task_id = submitted["task_id"]
        stored = await harness.store.get_task(task_id)
        assert stored is not None
        assert stored["direction"] == "outbound", stored
        # The peer reported its own gate, so this mirror's task is pending here.
        assert stored["status"] == STATUS_PENDING_APPROVAL, stored
        events_before = len(harness.task_events)

        approval_id = await mirror_peer_gate(harness, task_id)
        applied, reason = await harness.approvals.human_decide(
            approval_id, allowed=True, actor="astrbot_admin:alice", channel="web"
        )
        assert applied is True, reason

        await asyncio.sleep(0.1)
        # The answer still returns to the peer, which is what actually releases it.
        decisions = harness.decision_events()
        assert len(decisions) == 1, decisions
        assert decisions[0]["outcome"] == "allowed-once", decisions[0]

        # ... and nothing local moved: no execution, no transition, no task.event.
        assert harness.host.calls == 0
        after = await harness.store.get_task(task_id)
        assert after is not None
        assert after["status"] == STATUS_PENDING_APPROVAL, after
        assert after["eseq"] == stored["eseq"], after
        assert len(harness.task_events) == events_before, harness.task_events
        assert harness.terminal_events() == []
    finally:
        await harness.tasks.stop()
        await harness.store.close()


@pytest.mark.asyncio
async def test_outbound_rejected_never_executes_locally(tmp_path) -> None:
    """Rejecting a mirrored gate is not a local terminal state either."""
    harness, peer = await build_harness(tmp_path)
    try:
        submitted = await harness.tasks.submit_outbound(
            session=peer,
            input_parts=[{"type": "text", "text": "请对端导出用户表"}],
            purpose="export",
            timeout_s=60,
        )
        task_id = submitted["task_id"]
        stored = await harness.store.get_task(task_id)
        assert stored is not None and stored["status"] == STATUS_PENDING_APPROVAL
        events_before = len(harness.task_events)

        approval_id = await mirror_peer_gate(harness, task_id)
        applied, reason = await harness.approvals.human_decide(
            approval_id, allowed=False, actor="astrbot_admin:alice", channel="web"
        )
        assert applied is True, reason

        await asyncio.sleep(0.1)
        decisions = harness.decision_events()
        assert len(decisions) == 1, decisions
        assert decisions[0]["outcome"] == "rejected", decisions[0]

        assert harness.host.calls == 0
        after = await harness.store.get_task(task_id)
        assert after is not None
        # A refusal closes the mirror locally as ``needs_human`` so the task does
        # not look pending forever; it still never runs here and never emits a
        # local terminal task.event (the peer owns that task's status).
        assert after["status"] == "needs_human", after
        assert after["needs_human"] is True
        assert after["error"]["code"] == "approval_rejected"
        assert len(harness.task_events) == events_before, harness.task_events
        assert harness.terminal_events() == []
    finally:
        await harness.tasks.stop()
        await harness.store.close()


@pytest.mark.asyncio
async def test_outbound_repeated_decision_is_idempotent(tmp_path) -> None:
    """A second local decision neither runs nor re-emits anything."""
    harness, peer = await build_harness(tmp_path)
    try:
        submitted = await harness.tasks.submit_outbound(
            session=peer,
            input_parts=[{"type": "text", "text": "请对端导出用户表"}],
            purpose="export",
            timeout_s=60,
        )
        task_id = submitted["task_id"]
        approval_id = await mirror_peer_gate(harness, task_id)

        first, first_reason = await harness.approvals.human_decide(
            approval_id, allowed=True, actor="astrbot_admin:alice", channel="web"
        )
        assert first is True, first_reason
        await asyncio.sleep(0.1)
        decisions = harness.decision_events()
        assert len(decisions) == 1, decisions

        second, second_reason = await harness.approvals.human_decide(
            approval_id, allowed=True, actor="astrbot_admin:alice", channel="web"
        )
        assert second is False and second_reason == "already_decided"

        await asyncio.sleep(0.1)
        assert len(harness.decision_events()) == 1
        assert harness.host.calls == 0
        after = await harness.store.get_task(task_id)
        assert after is not None and after["status"] == STATUS_PENDING_APPROVAL
        assert harness.terminal_events() == []
    finally:
        await harness.tasks.stop()
        await harness.store.close()


@pytest.mark.asyncio
async def test_outbound_accepted_task_is_also_left_alone(tmp_path) -> None:
    """Even a non-gated outbound task must never be run by a local decision."""
    harness, peer = await build_harness(tmp_path, peer_status=STATUS_ACCEPTED)
    try:
        submitted = await harness.tasks.submit_outbound(
            session=peer,
            input_parts=[{"type": "text", "text": "请对端导出用户表"}],
            purpose="export",
            timeout_s=60,
        )
        task_id = submitted["task_id"]
        stored = await harness.store.get_task(task_id)
        assert stored is not None and stored["status"] == STATUS_ACCEPTED
        events_before = len(harness.task_events)

        approval_id = await mirror_peer_gate(harness, task_id)
        applied, reason = await harness.approvals.human_decide(
            approval_id, allowed=True, actor="astrbot_admin:alice", channel="web"
        )
        assert applied is True, reason

        await asyncio.sleep(0.1)
        assert harness.host.calls == 0
        after = await harness.store.get_task(task_id)
        assert after is not None and after["status"] == STATUS_ACCEPTED
        assert after["eseq"] == stored["eseq"], after
        assert len(harness.task_events) == events_before, harness.task_events
        assert len(harness.decision_events()) == 1
    finally:
        await harness.tasks.stop()
        await harness.store.close()
