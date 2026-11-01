"""Fail-closed lifecycle for ``cross_end_submit`` approvals (§12.5).

The gate is only evidence while the connection that asked is still alive and the
submitted content is the content the human approved. These cases pin the three
ways that evidence used to be missing:

* a pending gate survives a restart and could later release an old task;
* a mirrored peer gate is treated as a local approval;
* a row persisted before the approved ``submit_digest`` existed is accepted.

Every test drives the real ``Store`` / ``NotifyService`` / ``ApprovalService`` /
``TaskService``; only the host adapter is a counter.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from bridge.app.approvals import (
    ApprovalService,
    compute_submit_digest,
    request_digest_for,
)
from bridge.app.notify import NotifyService
from bridge.app.sessions import SessionService
from bridge.app.tasks import TaskService
from bridge.constants import (
    APPROVAL_CROSS_END_SUBMIT,
    EVENT_ACCEPTED,
    EVENT_NEEDS_HUMAN,
    STATUS_ACCEPTED,
    STATUS_NEEDS_HUMAN,
    STATUS_PENDING_APPROVAL,
    STATUS_SUCCEEDED,
)
from bridge.errors import (
    ERR_APPROVAL_DIGEST_MISMATCH,
)
from bridge.store import Store

CONN = "default"
SID = "22222222-2222-4222-8222-222222222222"
FUTURE = "2099-01-01T00:00:00.000Z"
INBOUND = "11111111-1111-4111-8111-111111111111"
OTHER = "99999999-9999-4999-8999-999999999999"


async def wait_status(store: Store, task_id: str, timeout_s: float = 3.0) -> dict:
    """Wait until one task leaves ``pending_approval`` (or time out).

    Args:
        store: Open store.
        task_id: Task identifier.
        timeout_s: Maximum wait.

    Returns:
        The final task row (possibly still pending).
    """
    deadline = time.monotonic() + timeout_s
    task = await store.get_task(task_id)
    while time.monotonic() < deadline:
        task = await store.get_task(task_id)
        if task is not None and task["status"] != STATUS_PENDING_APPROVAL:
            return task
        await asyncio.sleep(0.01)
    return task or {}


class StubHost:
    """Count local agent runs."""

    def __init__(self) -> None:
        """Start with no run."""
        self.calls = 0

    async def run_agent(self, *, task: dict) -> dict:
        """Record one local run.

        Args:
            task: Task row.

        Returns:
            A minimal success result.
        """
        self.calls += 1
        return {"summary": "ok", "text": "done", "attachments": []}


class StubPeer:
    """Peer session double answering ``task.submit`` with ``pending_approval``."""

    def __init__(self) -> None:
        """Create the double."""
        self.calls = 0

    async def call(self, message: str, params: dict, timeout_s: float = 0) -> dict:
        """Answer an outbound submit.

        Args:
            message: Message name (always ``task.submit``).
            params: Request parameters.
            timeout_s: Ignored.

        Returns:
            A pending-approval reply.
        """
        self.calls += 1
        return {
            "task_id": params["task_id"],
            "status": STATUS_PENDING_APPROVAL,
            "root_task_id": params["root_task_id"],
            "session_id": None,
            "poll_hint_ms": 10,
        }


class Fixture:
    """Bundle the real services used by each case."""

    def __init__(self) -> None:
        """Create the recorders."""
        self.store: Store
        self.host = StubHost()
        self.peer = StubPeer()
        self.events: list[dict] = []
        self.decisions: list[dict] = []
        self.approvals: ApprovalService
        self.tasks: TaskService


async def build(tmp_path) -> Fixture:
    """Wire the production services on a temporary database.

    Args:
        tmp_path: pytest temporary directory.

    Returns:
        The wired fixture.
    """
    fixture = Fixture()
    store = Store()
    await store.init(tmp_path / "bridge.db")
    fixture.store = store

    async def on_task_event(params: dict) -> None:
        fixture.events.append(params)

    async def on_event(
        params: dict, row: dict, task_id: str, root_task_id: str
    ) -> None:
        fixture.decisions.append({**params, "_message": row["message"]})

    notify = NotifyService(
        store, conn=CONN, on_task_event=on_task_event, on_event=on_event
    )
    sessions = SessionService(store, conn=CONN)
    await sessions.init()

    async def on_decided(approval: dict, allowed: bool) -> None:
        await fixture.tasks.on_approved(approval, allowed=allowed)

    approvals = ApprovalService(
        store,
        conn=CONN,
        side="A",
        approval_timeout_s=1800,
        notify_channels=["web"],
        notify=notify,
        on_approval_decided=on_decided,
    )
    approvals.bind_session(CONN, SID)
    fixture.approvals = approvals
    fixture.tasks = TaskService(
        store,
        conn=CONN,
        notify=notify,
        sessions=sessions,
        host=fixture.host,
        approvals=approvals,
    )
    return fixture


def submit_params(task_id: str = INBOUND, **overrides) -> dict:
    """Build a valid inbound submission.

    Args:
        task_id: Task identifier.
        **overrides: Field overrides.

    Returns:
        Parameter dictionary.
    """
    params = {
        "task_id": task_id,
        "root_task_id": task_id,
        "kind": "astr_agent_run",
        "origin": "llm",
        "input_parts": [{"type": "text", "text": "删除生产库"}],
        "attachments": [],
        "tool_hints": [],
        "session_id": None,
        "purpose": "deploy",
        "timeout_s": 60,
        "meta": {},
        "approval_ref": None,
    }
    params.update(overrides)
    return params


def ref_for(approval_id: str, params: dict, **overrides) -> dict:
    """Build an ``approval_ref`` for one submission.

    Args:
        approval_id: Approval identifier carried in the ref.
        params: Submission parameters.
        **overrides: Ref overrides.

    Returns:
        Reference dictionary.
    """
    ref = {
        "approval_id": approval_id,
        "submit_digest": compute_submit_digest(params),
        "actor": "astrbot_admin:alice",
        "actor_kind": "human",
        "decided_at": "2026-10-30T10:00:00.000Z",
        "expires_at": FUTURE,
    }
    ref.update(overrides)
    return ref


@pytest.mark.asyncio
async def test_restart_parks_pending_gate_and_never_releases_it(tmp_path) -> None:
    """A pending gate lost to a restart becomes unavailable and the task needs a human."""
    fixture = await build(tmp_path)
    try:
        result = await fixture.tasks.submit(submit_params())
        assert result["status"] == STATUS_PENDING_APPROVAL
        approval = await fixture.store.get_task_approval(
            INBOUND, APPROVAL_CROSS_END_SUBMIT
        )
        assert approval is not None and approval["state"] == "pending"

        invalidated = await fixture.approvals.invalidate_native_pending("restart")
        assert approval["approval_id"] in invalidated

        stored_approval = await fixture.store.get_approval(approval["approval_id"])
        assert stored_approval is not None
        assert stored_approval["state"] == "decided"
        assert stored_approval["outcome"] == "unavailable"
        assert stored_approval["actor_kind"] == "system"

        task = await fixture.store.get_task(INBOUND)
        assert task is not None and task["status"] == STATUS_NEEDS_HUMAN
        assert task["needs_human"] is True
        assert task["error"]["code"] == "approval_unavailable"
        assert any(
            event["event"] == EVENT_NEEDS_HUMAN and event["task_id"] == INBOUND
            for event in fixture.events
        ), fixture.events
        assert fixture.host.calls == 0

        applied, _reason = await fixture.approvals.human_decide(
            approval["approval_id"],
            allowed=True,
            actor="astrbot_admin:alice",
            channel="web",
        )
        assert applied is False
        await asyncio.sleep(0.05)
        assert fixture.host.calls == 0
    finally:
        await fixture.tasks.stop()
        await fixture.store.close()


@pytest.mark.asyncio
async def test_mirror_of_peer_gate_cannot_authorize_a_local_submission(
    tmp_path,
) -> None:
    """A peer-originated gate is not evidence for a submission accepted here."""
    fixture = await build(tmp_path)
    try:
        approval_id = "peer-gate-1"
        params = {
            "approval_id": approval_id,
            "approval_type": APPROVAL_CROSS_END_SUBMIT,
            "task_id": INBOUND,
            "root_task_id": INBOUND,
            "session_id": None,
            "tool": "astr_agent_run",
            "reason": "cross-end task submission",
            "display_reason": {"en": "Run", "zh": "执行"},
            "call_id": None,
            "request_digest": request_digest_for(
                "astr_agent_run", "cross-end task submission", None, None, INBOUND
            ),
            "expires_at": FUTURE,
            "notify_id": "n-peer",
            "origin_side": "B",
        }
        await fixture.approvals.handle_request(params)
        applied, reason = await fixture.approvals.human_decide(
            approval_id, allowed=True, actor="astrbot_admin:alice", channel="web"
        )
        assert applied is True, reason

        submission = submit_params()
        submission["approval_ref"] = ref_for(approval_id, submission)
        result = await fixture.tasks.submit(submission)
        assert result["status"] == STATUS_PENDING_APPROVAL
        task = await wait_status(fixture.store, INBOUND)
        assert task["status"] == "rejected", task
        assert task["error"]["code"] in (
            "approval_evidence_missing",
            "approval_lookup_failed",
        )
        await asyncio.sleep(0.05)
        assert fixture.host.calls == 0
    finally:
        await fixture.tasks.stop()
        await fixture.store.close()


@pytest.mark.asyncio
async def test_legacy_approval_without_submit_digest_is_refused(tmp_path) -> None:
    """An upgraded row with no persisted approved content is not evidence."""
    fixture = await build(tmp_path)
    try:
        params = submit_params()
        stored = await fixture.approvals.create_cross_end_submit(
            task={"task_id": INBOUND, "root_task_id": INBOUND},
            tool=params["kind"],
            reason="cross-end task submission",
            display_reason={"en": "Run", "zh": "执行"},
            params=params,
        )
        applied, reason = await fixture.approvals.human_decide(
            stored["approval_id"],
            allowed=True,
            actor="astrbot_admin:alice",
            channel="web",
        )
        assert applied is True, reason
        await fixture.store._conn().execute(
            "UPDATE approvals SET submit_digest = NULL WHERE approval_id = ?",
            (stored["approval_id"],),
        )
        await fixture.store._conn().commit()

        params["approval_ref"] = ref_for(stored["approval_id"], params)
        result = await fixture.tasks.submit(params)
        assert result["status"] == STATUS_PENDING_APPROVAL
        task = await wait_status(fixture.store, INBOUND)
        assert task["status"] == "rejected", task
        assert task["error"]["code"] in (
            "approval_evidence_missing",
            "approval_lookup_failed",
        )
        await asyncio.sleep(0.05)
        assert fixture.host.calls == 0
    finally:
        await fixture.tasks.stop()
        await fixture.store.close()


@pytest.mark.asyncio
async def test_local_release_consumes_the_gate_once(tmp_path) -> None:
    """The normal allow path spends the approval on its own task."""
    fixture = await build(tmp_path)
    try:
        await fixture.tasks.submit(submit_params(task_id=INBOUND))
        approval = await fixture.store.get_task_approval(
            INBOUND, APPROVAL_CROSS_END_SUBMIT
        )
        assert approval is not None

        applied, reason = await fixture.approvals.human_decide(
            approval["approval_id"],
            allowed=True,
            actor="astrbot_admin:alice",
            channel="web",
        )
        assert applied is True, reason
        await asyncio.sleep(0.1)

        task = await fixture.store.get_task(INBOUND)
        assert task is not None and task["status"] == STATUS_SUCCEEDED
        consumed = await fixture.store.get_approval(approval["approval_id"])
        assert consumed is not None
        assert consumed["consumed_by_task"] == INBOUND
        assert fixture.host.calls == 1
        # No decision event is emitted for a locally opened gate.
        assert all(
            event["_message"] != "approval.decision" for event in fixture.decisions
        ), fixture.decisions

        # The same human decision cannot be spent by another submission.
        other = submit_params(task_id=OTHER)
        other["approval_ref"] = ref_for(approval["approval_id"], other)
        result = await fixture.tasks.submit(other)
        assert result["status"] == STATUS_PENDING_APPROVAL
        other_task = await wait_status(fixture.store, OTHER)
        assert other_task["status"] == "rejected", other_task
        assert other_task["error"]["code"] in (
            ERR_APPROVAL_DIGEST_MISMATCH,
            "approval_already_decided",
            "approval_lookup_failed",
        )
        await asyncio.sleep(0.05)
        assert fixture.host.calls == 1
    finally:
        await fixture.tasks.stop()
        await fixture.store.close()


@pytest.mark.asyncio
async def test_session_bound_approval_cannot_authorize_another_session(
    tmp_path,
) -> None:
    """The approved content includes the target session, so another one cannot borrow it."""
    fixture = await build(tmp_path)
    try:
        for session_id in ("s1", "s2"):
            await fixture.store.grant_session(
                {
                    "session_id": session_id,
                    "purpose": "deploy",
                    "granted_by": "human",
                    "granted_by_id": "astrbot_admin:alice",
                    "created_by_task": None,
                }
            )
        owner = submit_params(session_id="s1")
        stored = await fixture.approvals.create_cross_end_submit(
            task={"task_id": INBOUND, "root_task_id": INBOUND},
            tool=owner["kind"],
            reason="cross-end task submission",
            display_reason={"en": "Run", "zh": "执行"},
            params=owner,
        )
        applied, reason = await fixture.approvals.human_decide(
            stored["approval_id"],
            allowed=True,
            actor="astrbot_admin:alice",
            channel="web",
        )
        assert applied is True, reason

        other = submit_params(task_id=OTHER, session_id="s2")
        other["approval_ref"] = ref_for(stored["approval_id"], other)
        result = await fixture.tasks.submit(other)
        assert result["status"] == STATUS_PENDING_APPROVAL
        other_task = await wait_status(fixture.store, OTHER)
        assert other_task["status"] == "rejected", other_task
        assert other_task["error"]["code"] in (
            ERR_APPROVAL_DIGEST_MISMATCH,
            "approval_lookup_failed",
        )
        await asyncio.sleep(0.05)
        assert fixture.host.calls == 0
    finally:
        await fixture.tasks.stop()
        await fixture.store.close()


@pytest.mark.asyncio
async def test_outbound_timeout_closes_mirror_without_running_anything(
    tmp_path,
) -> None:
    """A mirrored gate that times out parks locally and never executes here."""
    fixture = await build(tmp_path)
    try:
        submitted = await fixture.tasks.submit_outbound(
            session=fixture.peer,
            input_parts=[{"type": "text", "text": "请对端导出"}],
            timeout_s=60,
        )
        task_id = submitted["task_id"]
        approval_id = f"peer-{task_id}"
        await fixture.approvals.handle_request(
            {
                "approval_id": approval_id,
                "approval_type": APPROVAL_CROSS_END_SUBMIT,
                "task_id": task_id,
                "root_task_id": task_id,
                "session_id": None,
                "tool": "astr_agent_run",
                "reason": "cross-end task submission",
                "display_reason": {"en": "Run", "zh": "执行"},
                "call_id": None,
                "request_digest": request_digest_for(
                    "astr_agent_run",
                    "cross-end task submission",
                    None,
                    None,
                    task_id,
                ),
                "expires_at": FUTURE,
                "notify_id": f"n-{task_id}",
                "origin_side": "B",
            }
        )
        expired = await fixture.store.expire_approvals(now=time.time() + 10_000_000_000)
        assert any(row["approval_id"] == approval_id for row in expired)
        row = await fixture.store.get_approval(approval_id)
        assert row is not None
        await fixture.tasks.on_approved(row, allowed=False)

        task = await fixture.store.get_task(task_id)
        assert task is not None
        assert task["status"] == STATUS_NEEDS_HUMAN
        assert task["needs_human"] is True
        assert task["error"]["code"] == "approval_rejected"
        assert fixture.host.calls == 0
        assert all(event["task_id"] != task_id for event in fixture.events)
    finally:
        await fixture.tasks.stop()
        await fixture.store.close()


@pytest.mark.asyncio
async def test_local_gate_is_claimed_before_the_task_is_accepted(tmp_path) -> None:
    """The one-shot claim is durable before ``accepted`` is persisted or sent."""
    fixture = await build(tmp_path)
    try:
        params = submit_params()
        await fixture.tasks.submit(params)
        approval = await fixture.store.get_task_approval(
            params["task_id"], APPROVAL_CROSS_END_SUBMIT
        )
        assert approval is not None

        original = fixture.store.claim_approval_consumption
        observed: list[str] = []

        async def record_status(approval_id: str, task_id: str) -> bool:
            current = await fixture.store.get_task(task_id)
            assert current is not None
            observed.append(current["status"])
            return await original(approval_id, task_id)

        fixture.store.claim_approval_consumption = record_status
        applied, reason = await fixture.approvals.human_decide(
            approval["approval_id"],
            allowed=True,
            actor="astrbot_admin:alice",
            channel="web",
        )
        assert applied is True, reason
        # The claim saw the still-held task: acceptance cannot have been written
        # first, so a failed claim could never leave a durably accepted task.
        assert observed == [STATUS_PENDING_APPROVAL]
        accepted_events = [
            event
            for event in fixture.events
            if event["task_id"] == params["task_id"]
            and event["event"] == EVENT_ACCEPTED
        ]
        assert len(accepted_events) == 1
        task = await fixture.store.get_task(params["task_id"])
        assert task is not None
        assert task["status"] in (STATUS_ACCEPTED, "queued", "running", STATUS_SUCCEEDED)
        await asyncio.sleep(0.1)
        assert fixture.host.calls == 1
    finally:
        await fixture.tasks.stop()
        await fixture.store.close()


@pytest.mark.asyncio
async def test_consumption_refusal_parks_and_never_runs(tmp_path) -> None:
    """A gate that cannot be consumed exactly once produces no execution."""
    fixture = await build(tmp_path)
    try:
        params = submit_params()
        result = await fixture.tasks.submit(params)
        assert result["status"] == STATUS_PENDING_APPROVAL
        approval = await fixture.store.get_task_approval(
            params["task_id"], APPROVAL_CROSS_END_SUBMIT
        )
        assert approval is not None

        async def refuse(*_args, **_kwargs):
            return False

        fixture.store.claim_approval_consumption = refuse
        applied, reason = await fixture.approvals.human_decide(
            approval["approval_id"],
            allowed=True,
            actor="astrbot_admin:alice",
            channel="web",
        )
        assert applied is True, reason
        task = await fixture.store.get_task(params["task_id"])
        assert task is not None
        assert task["status"] == STATUS_NEEDS_HUMAN
        assert task["error"]["code"] == "approval_settlement_lost"
        assert fixture.host.calls == 0
        assert any(
            event["task_id"] == params["task_id"] and event["event"] == "needs_human"
            for event in fixture.events
        )
        assert not any(
            event["task_id"] == params["task_id"] and event["event"] == "accepted"
            for event in fixture.events
        )
    finally:
        await fixture.tasks.stop()
        await fixture.store.close()


@pytest.mark.asyncio
async def test_consumption_write_failure_is_not_swallowed(tmp_path) -> None:
    """A persistence failure while spending the gate must park, not execute."""
    fixture = await build(tmp_path)
    try:
        params = submit_params()
        await fixture.tasks.submit(params)
        approval = await fixture.store.get_task_approval(
            params["task_id"], APPROVAL_CROSS_END_SUBMIT
        )
        assert approval is not None

        async def explode(*_args, **_kwargs):
            raise RuntimeError("disk full")

        fixture.store.claim_approval_consumption = explode
        applied, reason = await fixture.approvals.human_decide(
            approval["approval_id"],
            allowed=True,
            actor="astrbot_admin:alice",
            channel="web",
        )
        assert applied is True, reason
        task = await fixture.store.get_task(params["task_id"])
        assert task is not None
        assert task["status"] == STATUS_NEEDS_HUMAN
        assert fixture.host.calls == 0
    finally:
        await fixture.tasks.stop()
        await fixture.store.close()


@pytest.mark.asyncio
async def test_two_human_answers_settle_exactly_one(tmp_path) -> None:
    """Concurrent human answers are serialized; the first durable one wins."""
    fixture = await build(tmp_path)
    try:
        params = submit_params()
        await fixture.tasks.submit(params)
        approval = await fixture.store.get_task_approval(
            params["task_id"], APPROVAL_CROSS_END_SUBMIT
        )
        assert approval is not None

        async def allow():
            return await fixture.store.decide_approval(
                approval["approval_id"],
                {
                    "outcome": "allowed-once",
                    "actor": "astrbot_admin:alice",
                    "actor_kind": "human",
                    "channel": "web",
                    "reason": None,
                },
                conn=CONN,
                sid=SID,
            )

        async def reject():
            return await fixture.store.decide_approval(
                approval["approval_id"],
                {
                    "outcome": "rejected",
                    "actor": "astrbot_admin:bob",
                    "actor_kind": "human",
                    "channel": "web",
                    "reason": None,
                },
                conn=CONN,
                sid=SID,
            )

        first, second = await asyncio.gather(allow(), reject())
        assert sum(1 for applied, _ in (first, second) if applied) == 1
        row = await fixture.store.get_approval(approval["approval_id"])
        assert row is not None
        assert row["state"] == "decided"
        assert row["actor"] in ("astrbot_admin:alice", "astrbot_admin:bob")
    finally:
        await fixture.tasks.stop()
        await fixture.store.close()


@pytest.mark.asyncio
async def test_human_answer_racing_timeout_cannot_win(tmp_path) -> None:
    """An expired row is settled by timeout only; a human answer loses cleanly."""
    fixture = await build(tmp_path)
    try:
        params = submit_params()
        await fixture.tasks.submit(params)
        approval = await fixture.store.get_task_approval(
            params["task_id"], APPROVAL_CROSS_END_SUBMIT
        )
        assert approval is not None
        await fixture.store._conn().execute(
            "UPDATE approvals SET expires_at = ? WHERE approval_id = ?",
            (time.time() - 10, approval["approval_id"]),
        )
        await fixture.store._conn().commit()

        expired = await fixture.store.expire_approvals()
        human = await fixture.store.decide_approval(
            approval["approval_id"],
            {
                "outcome": "allowed-once",
                "actor": "astrbot_admin:alice",
                "actor_kind": "human",
                "channel": "web",
                "reason": None,
            },
            conn=CONN,
            sid=SID,
        )
        assert human[0] is False
        assert human[1] == "expired"
        assert [row["approval_id"] for row in expired] == [approval["approval_id"]]
        row = await fixture.store.get_approval(approval["approval_id"])
        assert row is not None
        assert row["outcome"] == "rejected"
        assert row["channel"] == "timeout"
    finally:
        await fixture.tasks.stop()
        await fixture.store.close()


@pytest.mark.asyncio
async def test_pending_after_claim_is_parked_for_a_human(tmp_path) -> None:
    """A crash after the one-shot claim but before acceptance must not re-run."""
    fixture = await build(tmp_path)
    try:
        params = submit_params()
        await fixture.tasks.submit(params)
        approval = await fixture.store.get_task_approval(
            params["task_id"], APPROVAL_CROSS_END_SUBMIT
        )
        assert approval is not None
        assert await fixture.store.claim_approval_consumption(
            approval["approval_id"], params["task_id"]
        )
        summary = await fixture.tasks.recover_after_restart()
        assert params["task_id"] in summary["needs_human"]
        task = await fixture.store.get_task(params["task_id"])
        assert task is not None
        assert task["status"] == STATUS_NEEDS_HUMAN
        assert task["error"]["code"] == "approval_settlement_lost"
        assert fixture.host.calls == 0
    finally:
        await fixture.tasks.stop()
        await fixture.store.close()


@pytest.mark.asyncio
async def test_accepted_without_consumption_is_parked(tmp_path) -> None:
    """An accepted task whose gate was never spent is a lost settlement."""
    fixture = await build(tmp_path)
    try:
        params = submit_params()
        await fixture.tasks.submit(params)
        approval = await fixture.store.get_task_approval(
            params["task_id"], APPROVAL_CROSS_END_SUBMIT
        )
        assert approval is not None
        applied, reason = await fixture.store.decide_approval(
            approval["approval_id"],
            {
                "outcome": "allowed-once",
                "actor": "astrbot_admin:alice",
                "actor_kind": "human",
                "channel": "web",
                "reason": None,
            },
            conn=CONN,
            sid=SID,
        )
        assert applied is True, reason
        await fixture.store.transition(params["task_id"], "accepted", eseq=1)
        summary = await fixture.tasks.recover_after_restart()
        assert params["task_id"] in summary["needs_human"]
        task = await fixture.store.get_task(params["task_id"])
        assert task is not None
        assert task["status"] == STATUS_NEEDS_HUMAN
        assert fixture.host.calls == 0
    finally:
        await fixture.tasks.stop()
        await fixture.store.close()


@pytest.mark.asyncio
async def test_held_submit_emits_only_failed_with_first_sequence(tmp_path) -> None:
    """A held submission is never announced accepted; its refusal keeps eseq 1."""
    fixture = await build(tmp_path)
    try:
        params = submit_params()
        params["approval_ref"] = ref_for("never-seen", params)
        result = await fixture.tasks.submit(params)
        assert result["status"] == STATUS_PENDING_APPROVAL
        task = await wait_status(fixture.store, params["task_id"])
        assert task["status"] == "rejected", task
        accepted = [
            event
            for event in fixture.events
            if event["task_id"] == params["task_id"] and event["event"] == "accepted"
        ]
        failed = [
            event
            for event in fixture.events
            if event["task_id"] == params["task_id"] and event["event"] == "failed"
        ]
        assert accepted == []
        assert len(failed) == 1
        assert failed[0]["eseq"] == 1
        assert fixture.host.calls == 0
    finally:
        await fixture.tasks.stop()
        await fixture.store.close()


@pytest.mark.asyncio
async def test_initiator_mirror_accepts_first_peer_event(tmp_path) -> None:
    """An outbound mirror at eseq 0 must not drop the peer's first failed event."""
    fixture = await build(tmp_path)
    try:
        task_id = "77777777-7777-4777-8777-777777777777"
        await fixture.store.upsert_task(
            {
                "task_id": task_id,
                "root_task_id": task_id,
                "direction": "outbound",
                "kind": "astrbot_agent_run",
                "origin": "llm",
                "status": STATUS_PENDING_APPROVAL,
                "payload": {"approval_ref": {"approval_id": "ap-1"}},
                "session_id": None,
                "purpose": None,
                "request_hash": "hash",
            }
        )
        await fixture.tasks.on_event(
            {
                "task_id": task_id,
                "root_task_id": task_id,
                "notify_id": "notify-1",
                "event": "failed",
                "status": "rejected",
                "eseq": 1,
                "error": {
                    "code": "approval_lookup_failed",
                    "message": "x",
                    "details": None,
                },
            }
        )
        task = await fixture.store.get_task(task_id)
        assert task is not None
        assert task["status"] == "rejected"
        assert task["eseq"] == 1
    finally:
        await fixture.tasks.stop()
        await fixture.store.close()
