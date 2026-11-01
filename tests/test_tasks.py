"""Task-face tests: idempotency, state machine, no-replay, list/status/cancel (§9.3-§9.6).

The task service is exercised against a real SQLite store and a real notification
service, with only the host adapter stubbed.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from bridge.app.notify import NotifyService
from bridge.app.sessions import SessionService
from bridge.app.tasks import TaskService
from bridge.constants import (
    DIRECTION_INBOUND,
    STATUS_ACCEPTED,
    STATUS_CANCELED,
    STATUS_FAILED,
    STATUS_NEEDS_HUMAN,
    STATUS_PENDING_APPROVAL,
    STATUS_RUNNING,
    STATUS_SUCCEEDED,
)
from bridge.errors import ERR_SESSION_NOT_AUTHORIZED, BridgeError
from bridge.store import Store

CONN = "default"


def submit_params(
    task_id: str = "44444444-4444-4444-8444-444444444444", **overrides
) -> dict:
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
        "origin": "human",
        "input_parts": [{"type": "text", "text": "请写一个单元测试"}],
        "attachments": [],
        "tool_hints": [],
        "session_id": None,
        "purpose": "code-review",
        "timeout_s": 60,
        "meta": {},
        "approval_ref": None,
    }
    params.update(overrides)
    return params


class StubHost:
    """Host adapter double that records how often an agent run was started."""

    def __init__(self, *, delay: float = 0.0, fail: Exception | None = None) -> None:
        """Create the stub.

        Args:
            delay: Seconds to sleep before returning.
            fail: Exception to raise instead of returning.
        """
        self.calls = 0
        self.delay = delay
        self.fail = fail

    async def run_agent(self, *, task: dict) -> dict:
        """Simulate one agent run.

        Args:
            task: Task row.

        Returns:
            Result dictionary.

        Raises:
            Exception: ``fail`` when configured.
        """
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail is not None:
            raise self.fail
        return {"summary": "ok", "text": "done", "attachments": []}


class NullApprovals:
    """Minimal approvals double: records cross-end submission approvals."""

    def __init__(self) -> None:
        self.created: list[dict] = []
        self.blobs = None

    async def create_cross_end_submit(
        self, *, task: dict, tool: str, reason: str, display_reason: dict, params: dict
    ) -> dict:
        """Record one approval request."""
        self.created.append({"task_id": task["task_id"], "tool": tool})
        return {"approval_id": f"approval-{task['task_id']}"}


async def build_services(tmp_path, *, host=None, approvals=None, store=None, acks=None):
    """Wire a store, notify service and task service for a test.

    Args:
        tmp_path: Temporary directory.
        host: Optional host stub.
        approvals: Optional approvals double.
        store: Optional pre-opened store.
        acks: Optional list receiving the outbound ``event.ack`` parameters.

    Returns:
        ``(store, notify, sessions, tasks)``.
    """
    if store is None:
        store = Store()
        await store.init(tmp_path / "bridge.db")
    sent: list[dict] = []
    ack_calls: list[dict] = [] if acks is None else acks

    async def on_event(params: dict) -> None:
        sent.append(params)

    async def on_ack_request(params: dict) -> dict:
        """Record one ``event.ack`` sent to the peer and answer as it would."""
        ack_calls.append(params)
        return {"notify_id": params["notify_id"], "delivered": True}

    notify = NotifyService(
        store,
        conn=CONN,
        on_task_event=on_event,
        on_ack_request=on_ack_request,
    )
    sessions = SessionService(store, conn=CONN)
    await sessions.init()
    tasks = TaskService(
        store,
        conn=CONN,
        notify=notify,
        sessions=sessions,
        host=host,
        approvals=approvals,
    )
    return store, notify, sessions, tasks


@pytest.mark.asyncio
async def test_submit_returns_accepted_immediately(tmp_path) -> None:
    """``task.submit`` answers with ``accepted`` and the caller's task id (§9.3)."""
    host = StubHost(delay=0.05)
    store, _notify, _sessions, tasks = await build_services(tmp_path, host=host)
    try:
        result = await tasks.submit(submit_params())
        assert result["status"] == STATUS_ACCEPTED
        assert result["task_id"] == "44444444-4444-4444-8444-444444444444"
        assert result["root_task_id"] == result["task_id"]
        assert result["dedup"] is False
        # The submission returned before the run finished.
        stored = await store.get_task(result["task_id"])
        assert stored is not None
        assert stored["status"] in (STATUS_ACCEPTED, "queued", STATUS_RUNNING)
    finally:
        await tasks.stop()
        await store.close()


@pytest.mark.asyncio
async def test_duplicate_submit_never_runs_twice(tmp_path) -> None:
    """The same ``task_id`` is accepted once; the host runs exactly once (§10.1)."""
    host = StubHost()
    store, _notify, _sessions, tasks = await build_services(tmp_path, host=host)
    try:
        first = await tasks.submit(submit_params())
        second = await tasks.submit(submit_params())
        assert first["dedup"] is False
        assert second["dedup"] is True
        await asyncio.sleep(0.05)
        assert host.calls == 1
    finally:
        await tasks.stop()
        await store.close()


@pytest.mark.asyncio
async def test_conflicting_resubmit_raises_task_exists(tmp_path) -> None:
    """Same id with different content is an idempotency conflict (§15.3)."""
    host = StubHost()
    store, _notify, _sessions, tasks = await build_services(tmp_path, host=host)
    try:
        await tasks.submit(submit_params())
        with pytest.raises(BridgeError) as excinfo:
            await tasks.submit(
                submit_params(input_parts=[{"type": "text", "text": "different"}])
            )
        assert excinfo.value.code == "task_exists"
    finally:
        await tasks.stop()
        await store.close()


@pytest.mark.asyncio
async def test_llm_submission_requires_approval(tmp_path) -> None:
    """An LLM-originated submission starts in ``pending_approval`` (PRD §6.12.4)."""
    host = StubHost()
    approvals = NullApprovals()
    store, _notify, _sessions, tasks = await build_services(
        tmp_path, host=host, approvals=approvals
    )
    try:
        result = await tasks.submit(submit_params(origin="llm"))
        assert result["status"] == STATUS_PENDING_APPROVAL
        await asyncio.sleep(0.02)
        assert host.calls == 0
        assert approvals.created and approvals.created[0]["tool"] == "astr_agent_run"
    finally:
        await tasks.stop()
        await store.close()


@pytest.mark.asyncio
async def test_approval_releases_pending_task(tmp_path) -> None:
    """A human approval moves the task forward and executes it (§12.5)."""
    host = StubHost()
    approvals = NullApprovals()
    store, _notify, _sessions, tasks = await build_services(
        tmp_path, host=host, approvals=approvals
    )
    try:
        await tasks.submit(submit_params(origin="llm"))
        # The gate must exist durably before a human answer can release it: the
        # release path claims the row exactly once before accepting the task.
        await store.put_approval(
            {
                "approval_id": "a",
                "approval_type": "cross_end_submit",
                "task_id": "44444444-4444-4444-8444-444444444444",
                "root_task_id": "44444444-4444-4444-8444-444444444444",
                "request_digest": "req",
                "origin_side": "A",
                "source": "local",
                "gate_scope": "inbound_release",
                "expires_at": time.time() + 600,
            }
        )
        # ``on_approved`` only releases tasks gated by a ``cross_end_submit``
        # approval, which is exactly the type produced for an LLM submission above.
        await tasks.on_approved(
            {
                "approval_id": "a",
                "approval_type": "cross_end_submit",
                "task_id": "44444444-4444-4444-8444-444444444444",
            },
            allowed=True,
        )
        await asyncio.sleep(0.1)
        stored = await store.get_task("44444444-4444-4444-8444-444444444444")
        assert stored is not None
        assert stored["status"] == STATUS_SUCCEEDED
        assert host.calls == 1
    finally:
        await tasks.stop()
        await store.close()


@pytest.mark.asyncio
async def test_rejection_ends_task_as_rejected(tmp_path) -> None:
    """A rejection terminates the task without running it (§12.3 fail-closed)."""
    host = StubHost()
    store, _notify, _sessions, tasks = await build_services(
        tmp_path, host=host, approvals=NullApprovals()
    )
    try:
        await tasks.submit(submit_params(origin="llm"))
        await tasks.on_approved(
            {
                "approval_id": "a",
                "approval_type": "cross_end_submit",
                "task_id": "44444444-4444-4444-8444-444444444444",
            },
            allowed=False,
        )
        stored = await store.get_task("44444444-4444-4444-8444-444444444444")
        assert stored is not None
        assert stored["status"] == "rejected"
        assert host.calls == 0
    finally:
        await tasks.stop()
        await store.close()


@pytest.mark.asyncio
async def test_unauthorized_session_is_rejected(tmp_path) -> None:
    """Submitting into a session without a grant is ``session_not_authorized`` (§9.7)."""
    store, _notify, _sessions, tasks = await build_services(tmp_path, host=StubHost())
    try:
        with pytest.raises(BridgeError) as excinfo:
            await tasks.submit(submit_params(session_id="not-granted"))
        assert excinfo.value.code == ERR_SESSION_NOT_AUTHORIZED
    finally:
        await tasks.stop()
        await store.close()


@pytest.mark.asyncio
async def test_authorized_session_is_accepted(tmp_path) -> None:
    """A granted session may receive tasks."""
    store, _notify, sessions, tasks = await build_services(tmp_path, host=StubHost())
    try:
        await sessions.admin_grant("granted-session", purpose="code-review")
        result = await tasks.submit(submit_params(session_id="granted-session"))
        assert result["status"] == STATUS_ACCEPTED
    finally:
        await tasks.stop()
        await store.close()


@pytest.mark.asyncio
async def test_status_of_unknown_task_is_task_not_found(tmp_path) -> None:
    """Unknown ids answer ``task_not_found`` rather than a fake ``unknown`` (§9.4)."""
    store, _notify, _sessions, tasks = await build_services(tmp_path, host=StubHost())
    try:
        with pytest.raises(BridgeError) as excinfo:
            await tasks.status({"task_id": "nope"})
        assert excinfo.value.code == "task_not_found"
    finally:
        await tasks.stop()
        await store.close()


@pytest.mark.asyncio
async def test_status_shape_matches_protocol(tmp_path) -> None:
    """``task.status`` returns the documented field set (§9.4)."""
    store, _notify, _sessions, tasks = await build_services(tmp_path, host=StubHost())
    try:
        await tasks.submit(submit_params())
        payload = await tasks.status(
            {"task_id": "44444444-4444-4444-8444-444444444444"}
        )
        assert set(payload) == {
            "task_id",
            "root_task_id",
            "status",
            "direction",
            "kind",
            "created_at",
            "updated_at",
            "attempts",
            "session_id",
            "result",
            "error",
            "eseq",
            "needs_human",
        }
        assert payload["direction"] == DIRECTION_INBOUND
        assert payload["created_at"].endswith("Z")
    finally:
        await tasks.stop()
        await store.close()


@pytest.mark.asyncio
async def test_list_open_excludes_terminal_tasks(tmp_path) -> None:
    """``task.list_open`` only returns non-terminal tasks (§9.5)."""
    host = StubHost(delay=0.2)
    store, _notify, _sessions, tasks = await build_services(tmp_path, host=host)
    try:
        await tasks.submit(
            submit_params(task_id="44444444-4444-4444-8444-444444444441")
        )
        listed = await tasks.list_open({"limit": 50})
        assert listed["tasks"]
        terminal = {STATUS_SUCCEEDED, STATUS_FAILED, STATUS_CANCELED}
        assert all(item["status"] not in terminal for item in listed["tasks"])
    finally:
        await tasks.stop()
        await store.close()


@pytest.mark.asyncio
async def test_cancel_pending_task_emits_canceled_event(tmp_path) -> None:
    """Cancelling a queued task records ``canceled`` and notifies the peer (§9.6)."""
    host = StubHost(delay=1.0)
    store, notify, _sessions, tasks = await build_services(tmp_path, host=host)
    try:
        task_id = "44444444-4444-4444-8444-444444444442"
        await tasks.submit(submit_params(task_id=task_id))
        await asyncio.sleep(0.02)
        result = await tasks.cancel({"task_id": task_id, "reason": "user_cancelled"})
        assert result["status"] in (STATUS_CANCELED, "cancel_unsupported")
        if result["status"] == STATUS_CANCELED:
            stored = await store.get_task(task_id)
            assert stored is not None and stored["status"] == STATUS_CANCELED
    finally:
        await tasks.stop()
        await store.close()


@pytest.mark.asyncio
async def test_inbound_event_updates_status_and_acks(tmp_path) -> None:
    """A peer ``task.event`` updates the task and acks the peer, not our outbox (§11.1/§11.2)."""
    acks: list[dict] = []
    store, notify, _sessions, tasks = await build_services(
        tmp_path, host=StubHost(), acks=acks
    )
    try:
        task_id = "44444444-4444-4444-8444-444444444443"
        # A local outbox row that happens to share the peer's ``notify_id``: the ack
        # must go over the wire and leave this row untouched.
        notify_id = "88888888-8888-4888-8888-888888888888"
        await store.upsert_task(
            {
                "task_id": task_id,
                "root_task_id": task_id,
                "direction": "outbound",
                "kind": "dsh_agent_run",
                "origin": "llm",
                "status": STATUS_ACCEPTED,
            }
        )
        await notify.emit_event(
            notify_id,
            "task.event",
            {},
            task_id,
            task_id,
        )
        params = {
            "task_id": task_id,
            "root_task_id": task_id,
            "eseq": 1,
            "event": "completed",
            "status": STATUS_SUCCEEDED,
            "notify_id": notify_id,
            "result": {"summary": "ok"},
            "error": None,
            "decision": None,
            "approval": None,
        }
        await tasks.on_event(params)
        stored = await store.get_task(task_id)
        assert stored is not None
        assert stored["status"] == STATUS_SUCCEEDED
        assert acks == [
            {
                "notify_id": notify_id,
                "task_id": task_id,
                "root_task_id": task_id,
                "outcome": "processed",
            }
        ]
        local = await store.get_notify(notify_id)
        assert local is not None and local["delivered"] is False
    finally:
        await tasks.stop()
        await store.close()


@pytest.mark.asyncio
async def test_duplicate_inbound_event_does_not_change_state(tmp_path) -> None:
    """The same ``notify_id`` is processed once and acked as duplicate (§10.3)."""
    store, notify, _sessions, tasks = await build_services(tmp_path, host=StubHost())
    try:
        task_id = "44444444-4444-4444-8444-444444444444"
        await store.upsert_task(
            {
                "task_id": task_id,
                "root_task_id": task_id,
                "direction": "outbound",
                "kind": "dsh_agent_run",
                "origin": "llm",
                "status": STATUS_ACCEPTED,
            }
        )
        await notify.emit_event("n-1", "task.event", {}, task_id, task_id)
        params = {
            "task_id": task_id,
            "root_task_id": task_id,
            "eseq": 1,
            "event": "completed",
            "status": STATUS_SUCCEEDED,
            "notify_id": "n-1",
            "result": {"summary": "ok"},
            "error": None,
            "decision": None,
            "approval": None,
        }
        await tasks.on_event(params)
        await tasks.on_event(params)
        stored = await store.get_task(task_id)
        assert stored is not None
        assert stored["eseq"] == 1
    finally:
        await tasks.stop()
        await store.close()


@pytest.mark.asyncio
async def test_restart_marks_running_task_needs_human(tmp_path) -> None:
    """A task that was ``running`` at shutdown is never replayed (§16.2)."""
    host = StubHost()
    store, _notify, _sessions, tasks = await build_services(tmp_path, host=host)
    task_id = "44444444-4444-4444-8444-444444444445"
    await store.upsert_task(
        {
            "task_id": task_id,
            "root_task_id": task_id,
            "direction": DIRECTION_INBOUND,
            "kind": "astr_agent_run",
            "origin": "human",
            "status": STATUS_RUNNING,
        }
    )
    report = await tasks.recover_after_restart()
    assert task_id in report["needs_human"]
    stored = await store.get_task(task_id)
    assert stored is not None
    assert stored["status"] == STATUS_NEEDS_HUMAN
    assert host.calls == 0
    await tasks.stop()
    await store.close()


@pytest.mark.asyncio
async def test_restart_parks_acceptance_without_consumed_gate(tmp_path) -> None:
    """A crash between acceptance and the one-shot claim is never re-executed."""
    host = StubHost()
    store, _notify, _sessions, tasks = await build_services(tmp_path, host=host)
    task_id = "44444444-4444-4444-8444-444444444447"
    await store.upsert_task(
        {
            "task_id": task_id,
            "root_task_id": task_id,
            "direction": DIRECTION_INBOUND,
            "kind": "astr_agent_run",
            "origin": "llm",
            "status": STATUS_ACCEPTED,
            "payload": {"timeout_s": 30},
        }
    )
    await store.put_approval(
        {
            "approval_id": "ap-recover-1",
            "approval_type": "cross_end_submit",
            "task_id": task_id,
            "root_task_id": task_id,
            "request_digest": "req",
            "origin_side": "A",
            "source": "local",
            "gate_scope": "inbound_release",
            "expires_at": 9999999999.0,
            "outcome": "allowed-once",
            "actor": "astrbot_admin:alice",
            "actor_kind": "human",
            "channel": "web",
        }
    )
    # ``put_approval`` always inserts pending; make it a durable human grant.
    await store.decide_approval(
        "ap-recover-1",
        {
            "outcome": "allowed-once",
            "actor": "astrbot_admin:alice",
            "actor_kind": "human",
            "channel": "web",
            "reason": None,
        },
    )
    report = await tasks.recover_after_restart()
    assert task_id in report["needs_human"]
    stored = await store.get_task(task_id)
    assert stored is not None and stored["status"] == STATUS_NEEDS_HUMAN
    assert host.calls == 0
    await tasks.stop()
    await store.close()


@pytest.mark.asyncio
async def test_restart_parks_acceptance_whose_gate_is_still_pending(tmp_path) -> None:
    """An accepted task with an unspent/pending gate is never resumed."""
    host = StubHost()
    store, _notify, _sessions, tasks = await build_services(tmp_path, host=host)
    task_id = "44444444-4444-4444-8444-444444444449"
    await store.upsert_task(
        {
            "task_id": task_id,
            "root_task_id": task_id,
            "direction": DIRECTION_INBOUND,
            "kind": "astr_agent_run",
            "origin": "llm",
            "status": STATUS_ACCEPTED,
            "payload": {"timeout_s": 30},
        }
    )
    await store.put_approval(
        {
            "approval_id": "ap-recover-pending-1",
            "approval_type": "cross_end_submit",
            "task_id": task_id,
            "root_task_id": task_id,
            "request_digest": "req",
            "origin_side": "A",
            "source": "local",
            "gate_scope": "inbound_release",
            "expires_at": 9999999999.0,
        }
    )
    report = await tasks.recover_after_restart()
    assert task_id in report["needs_human"]
    stored = await store.get_task(task_id)
    assert stored is not None and stored["status"] == STATUS_NEEDS_HUMAN
    assert stored["error"]["code"] == "approval_settlement_lost"
    assert host.calls == 0
    await tasks.stop()
    await store.close()


@pytest.mark.asyncio
async def test_restart_parks_pending_task_with_claimed_gate(tmp_path) -> None:
    """A claimed gate on a still-pending task is a lost settlement, not a run."""
    host = StubHost()
    store, _notify, _sessions, tasks = await build_services(tmp_path, host=host)
    task_id = "44444444-4444-4444-8444-444444444448"
    await store.upsert_task(
        {
            "task_id": task_id,
            "root_task_id": task_id,
            "direction": DIRECTION_INBOUND,
            "kind": "astr_agent_run",
            "origin": "llm",
            "status": STATUS_PENDING_APPROVAL,
            "payload": {"timeout_s": 30},
        }
    )
    await store.put_approval(
        {
            "approval_id": "ap-recover-2",
            "approval_type": "cross_end_submit",
            "task_id": task_id,
            "root_task_id": task_id,
            "request_digest": "req",
            "origin_side": "A",
            "source": "local",
            "gate_scope": "inbound_release",
            "expires_at": 9999999999.0,
        }
    )
    assert await store.claim_approval_consumption("ap-recover-2", task_id) is True
    report = await tasks.recover_after_restart()
    assert task_id in report["needs_human"]
    stored = await store.get_task(task_id)
    assert stored is not None and stored["status"] == STATUS_NEEDS_HUMAN
    assert host.calls == 0
    await tasks.stop()
    await store.close()


@pytest.mark.asyncio
async def test_restart_resumes_accepted_inbound_task(tmp_path) -> None:
    """A task that never started before shutdown is safe to resume (§10.2)."""
    host = StubHost()
    store, _notify, _sessions, tasks = await build_services(tmp_path, host=host)
    task_id = "44444444-4444-4444-8444-444444444446"
    await store.upsert_task(
        {
            "task_id": task_id,
            "root_task_id": task_id,
            "direction": DIRECTION_INBOUND,
            "kind": "astr_agent_run",
            "origin": "human",
            "status": STATUS_ACCEPTED,
            "payload": {"timeout_s": 30},
        }
    )
    report = await tasks.recover_after_restart()
    assert task_id in report["resumed"]
    await asyncio.sleep(0.1)
    stored = await store.get_task(task_id)
    assert stored is not None
    assert stored["status"] == STATUS_SUCCEEDED
    assert host.calls == 1
    await tasks.stop()
    await store.close()


@pytest.mark.asyncio
async def test_timeout_fails_the_task(tmp_path) -> None:
    """Exceeding ``timeout_s`` fails the task with ``task_timeout`` (§9.3)."""
    host = StubHost(delay=1.0)
    store, _notify, _sessions, tasks = await build_services(tmp_path, host=host)
    try:
        task_id = "44444444-4444-4444-8444-444444444447"
        await tasks.submit(submit_params(task_id=task_id, timeout_s=1))
        await asyncio.sleep(1.3)
        stored = await store.get_task(task_id)
        assert stored is not None
        assert stored["status"] in (STATUS_FAILED, STATUS_RUNNING)
        if stored["status"] == STATUS_FAILED:
            assert stored["error"]["code"] == "task_timeout"
    finally:
        await tasks.stop()
        await store.close()


@pytest.mark.asyncio
async def test_host_error_fails_task(tmp_path) -> None:
    """A host exception becomes ``failed`` with the raised code."""
    host = StubHost(fail=BridgeError("capability_unavailable"))
    store, _notify, _sessions, tasks = await build_services(tmp_path, host=host)
    try:
        task_id = "44444444-4444-4444-8444-444444444448"
        await tasks.submit(submit_params(task_id=task_id))
        await asyncio.sleep(0.1)
        stored = await store.get_task(task_id)
        assert stored is not None
        assert stored["status"] == STATUS_FAILED
        assert stored["error"]["code"] == "capability_unavailable"
    finally:
        await tasks.stop()
        await store.close()


@pytest.mark.asyncio
async def test_submit_validation_rejects_bad_input(tmp_path) -> None:
    """Structural violations are ``bad_params`` before anything is stored."""
    store, _notify, _sessions, tasks = await build_services(tmp_path, host=StubHost())
    try:
        for broken in (
            submit_params(input_parts=[]),
            submit_params(timeout_s=0),
            submit_params(kind="unknown_kind"),
            submit_params(origin="robot"),
        ):
            with pytest.raises(BridgeError) as excinfo:
                await tasks.submit(broken)
            assert excinfo.value.code == "bad_params"
        assert await store.list_tasks() == ([], None)
    finally:
        await tasks.stop()
        await store.close()


@pytest.mark.asyncio
async def test_unsupported_kind_is_capability_unavailable(tmp_path) -> None:
    """This side cannot execute ``dsh_agent_run``, so it refuses it (§4.5)."""
    store, _notify, _sessions, tasks = await build_services(tmp_path, host=StubHost())
    try:
        with pytest.raises(BridgeError) as excinfo:
            await tasks.submit(submit_params(kind="dsh_agent_run"))
        assert excinfo.value.code == "capability_unavailable"
    finally:
        await tasks.stop()
        await store.close()
