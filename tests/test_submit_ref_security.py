"""Security tests for ``approval_ref`` handling on inbound ``task.submit`` (§12.5).

An ``approval_ref`` arrives from the peer and is therefore only a *claim*. These
tests pin the fail-closed behaviour of the submit gate: a ref that carries no id,
names an id this endpoint never approved, or reuses an already consumed approval
must never reach execution, while a genuinely approved and unconsumed local
``cross_end_submit`` row still releases exactly one task.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from bridge.app.approvals import ApprovalService, compute_submit_digest
from bridge.app.notify import NotifyService
from bridge.app.sessions import SessionService
from bridge.app.tasks import TaskService
from bridge.constants import (
    APPROVAL_CROSS_END_SUBMIT,
    STATUS_PENDING_APPROVAL,
)
from bridge.errors import (
    ERR_APPROVAL_DIGEST_MISMATCH,
    ERR_APPROVAL_EXPIRED,
    ERR_APPROVAL_MISMATCH,
    BridgeError,
)
from bridge.store import Store

CONN = "default"
SID = "22222222-2222-4222-8222-222222222222"
FUTURE = "2099-01-01T00:00:00.000Z"


class StubHost:
    """Host adapter double counting how often an agent run really started."""

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


def submit_params(task_id: str = "77777777-7777-4777-8777-777777777777", **over):
    """Build a valid inbound ``task.submit`` parameter set.

    Args:
        task_id: Task identifier.
        **over: Field overrides.

    Returns:
        Parameter dictionary with every required field present.
    """
    params = {
        "task_id": task_id,
        "root_task_id": task_id,
        "kind": "astr_agent_run",
        "origin": "human",
        "input_parts": [{"type": "text", "text": "删除生产库"}],
        "attachments": [],
        "tool_hints": [],
        "session_id": None,
        "purpose": "deploy",
        "timeout_s": 60,
        "meta": {},
        "approval_ref": None,
    }
    params.update(over)
    return params


class Harness:
    """Wire a real store, approvals service and task service together."""

    def __init__(
        self, store: Store, host: StubHost, approvals: ApprovalService
    ) -> None:
        """Store the collaborators.

        Args:
            store: Open store.
            host: Host stub.
            approvals: Real approval service backed by the same store.
        """
        self.store = store
        self.host = host
        self.approvals = approvals
        self.decided: list[tuple[dict, bool]] = []

    def ref(self, approval_id: str, params: dict, **over) -> dict:
        """Build an ``approval_ref`` for ``params``.

        Args:
            approval_id: Approval identifier carried in the ref.
            params: Submission parameters the digest is computed over.
            **over: Field overrides.

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
        ref.update(over)
        return ref


async def build_harness(tmp_path) -> Harness:
    """Build the wired harness used by every test here.

    Args:
        tmp_path: pytest temporary directory.

    Returns:
        The harness.
    """
    store = Store()
    await store.init(tmp_path / "bridge.db")
    host = StubHost()
    sent: list[dict] = []

    async def on_task_event(params: dict) -> None:
        sent.append(params)

    notify = NotifyService(store, conn=CONN, on_task_event=on_task_event)
    sessions = SessionService(store, conn=CONN)
    await sessions.init()

    harness_holder: dict[str, Harness] = {}

    async def on_decided(approval: dict, allowed: bool) -> None:
        harness_holder["h"].decided.append((approval, allowed))

    async def on_human(payload: dict) -> None:
        return None

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
    # Evidence is bound to the authenticated session (§12.7); without this the
    # decision would carry no conn/sid and could never be authoritative.
    approvals.bind_session(CONN, SID)
    tasks = TaskService(
        store,
        conn=CONN,
        notify=notify,
        sessions=sessions,
        host=host,
        approvals=approvals,
    )
    harness = Harness(store, host, approvals)
    harness.tasks = tasks
    harness_holder["h"] = harness
    return harness


@pytest.mark.asyncio
async def test_empty_ref_cannot_execute(tmp_path) -> None:
    """``approval_ref: {}`` is refused: it proves nothing and must not run (§12.5)."""
    harness = await build_harness(tmp_path)
    try:
        params = submit_params(approval_ref={})
        with pytest.raises(BridgeError) as excinfo:
            await harness.tasks.submit(params)
        assert excinfo.value.code == ERR_APPROVAL_MISMATCH
        await asyncio.sleep(0.05)
        assert harness.host.calls == 0
        assert await harness.store.get_task(params["task_id"]) is None
    finally:
        await harness.tasks.stop()
        await harness.store.close()


@pytest.mark.asyncio
async def test_unknown_approval_id_with_correct_digest_cannot_execute(
    tmp_path,
) -> None:
    """A self-consistent digest for an id this side never approved is not consent."""
    harness = await build_harness(tmp_path)
    try:
        params = submit_params()
        params["approval_ref"] = harness.ref("ap-never-seen", params)
        result = await harness.tasks.submit(params)
        assert result["status"] == STATUS_PENDING_APPROVAL
        task = await wait_status(harness.store, params["task_id"])
        assert task["status"] == "rejected", task
        assert task["error"]["code"] == "approval_lookup_failed", task
        await asyncio.sleep(0.05)
        assert harness.host.calls == 0
    finally:
        await harness.tasks.stop()
        await harness.store.close()


@pytest.mark.asyncio
async def test_local_human_approval_releases_exactly_one_task(tmp_path) -> None:
    """A decided, digest-bound, unconsumed ``cross_end_submit`` row releases one run."""
    harness = await build_harness(tmp_path)
    try:
        params = submit_params()
        # Mimic this endpoint's own gate: it opened the approval for this very task.
        stored = await harness.approvals.create_cross_end_submit(
            task={"task_id": params["task_id"], "root_task_id": params["root_task_id"]},
            tool=params["kind"],
            reason="cross-end task submission",
            display_reason={"en": "Run", "zh": "执行"},
            params=params,
        )
        applied, reason = await harness.approvals.human_decide(
            stored["approval_id"],
            allowed=True,
            actor="astrbot_admin:alice",
            channel="web",
        )
        assert applied is True, reason
        assert stored["approval_type"] == APPROVAL_CROSS_END_SUBMIT

        params["approval_ref"] = harness.ref(stored["approval_id"], params)
        result = await harness.tasks.submit(params)
        assert result["status"] == STATUS_PENDING_APPROVAL
        task = await wait_status(harness.store, params["task_id"])
        assert task["status"] != STATUS_PENDING_APPROVAL, task
        for _ in range(200):
            if harness.host.calls >= 1:
                break
            await asyncio.sleep(0.01)
        assert harness.host.calls == 1

        # The release consumed the approval for this task, durably, on the row.
        consumed = await harness.store.get_approval(stored["approval_id"])
        assert consumed is not None
        assert consumed["consumed_by_task"] == params["task_id"]
        assert consumed["consumed_at"] is not None
        await asyncio.sleep(0.05)
        assert harness.host.calls == 1
    finally:
        await harness.tasks.stop()
        await harness.store.close()


@pytest.mark.asyncio
async def test_consumed_approval_id_cannot_be_spent_again(tmp_path) -> None:
    """The durable consumption record wins even when the approval row still matches."""
    harness = await build_harness(tmp_path)
    try:
        params = submit_params()
        stored = await harness.approvals.create_cross_end_submit(
            task={"task_id": params["task_id"], "root_task_id": params["root_task_id"]},
            tool=params["kind"],
            reason="cross-end task submission",
            display_reason={"en": "Run", "zh": "执行"},
            params=params,
        )
        await harness.approvals.human_decide(
            stored["approval_id"],
            allowed=True,
            actor="astrbot_admin:alice",
            channel="web",
        )
        # Another submission already spent the approval. The durable row is the
        # authority, so the verifier refuses before the content is even compared.
        claimed = await harness.store.claim_approval_consumption(
            stored["approval_id"], "11111111-1111-4111-8111-111111111111"
        )
        assert claimed is True

        params["approval_ref"] = harness.ref(stored["approval_id"], params)
        result = await harness.tasks.submit(params)
        assert result["status"] == STATUS_PENDING_APPROVAL
        task = await wait_status(harness.store, params["task_id"])
        assert task["status"] == "rejected", task
        assert task["error"]["code"] in (
            "approval_already_decided",
            "approval_lookup_failed",
        )
        await asyncio.sleep(0.05)
        assert harness.host.calls == 0
    finally:
        await harness.tasks.stop()
        await harness.store.close()


@pytest.mark.asyncio
async def test_approval_for_another_task_is_refused(tmp_path) -> None:
    """A valid approval is bound to its task; another task id may not borrow it."""
    harness = await build_harness(tmp_path)
    try:
        owner = submit_params()
        stored = await harness.approvals.create_cross_end_submit(
            task={"task_id": owner["task_id"], "root_task_id": owner["root_task_id"]},
            tool=owner["kind"],
            reason="cross-end task submission",
            display_reason={"en": "Run", "zh": "执行"},
            params=owner,
        )
        await harness.approvals.human_decide(
            stored["approval_id"],
            allowed=True,
            actor="astrbot_admin:alice",
            channel="web",
        )

        other = submit_params(task_id="99999999-9999-4999-8999-999999999999")
        other["approval_ref"] = harness.ref(stored["approval_id"], other)
        result = await harness.tasks.submit(other)
        assert result["status"] == STATUS_PENDING_APPROVAL
        task = await wait_status(harness.store, other["task_id"])
        assert task["status"] == "rejected", task
        assert task["error"]["code"] == ERR_APPROVAL_DIGEST_MISMATCH
        await asyncio.sleep(0.05)
        assert harness.host.calls == 0
    finally:
        await harness.tasks.stop()
        await harness.store.close()


@pytest.mark.asyncio
async def test_rejected_local_approval_is_refused(tmp_path) -> None:
    """A refusal on the local approval never becomes an execution."""
    harness = await build_harness(tmp_path)
    try:
        params = submit_params()
        stored = await harness.approvals.create_cross_end_submit(
            task={"task_id": params["task_id"], "root_task_id": params["root_task_id"]},
            tool=params["kind"],
            reason="cross-end task submission",
            display_reason={"en": "Run", "zh": "执行"},
            params=params,
        )
        await harness.approvals.human_decide(
            stored["approval_id"],
            allowed=False,
            actor="astrbot_admin:alice",
            channel="web",
        )
        params["approval_ref"] = harness.ref(stored["approval_id"], params)
        result = await harness.tasks.submit(params)
        assert result["status"] == STATUS_PENDING_APPROVAL
        task = await wait_status(harness.store, params["task_id"])
        assert task["status"] == "rejected", task
        assert task["error"]["code"] == ERR_APPROVAL_MISMATCH
        await asyncio.sleep(0.05)
        assert harness.host.calls == 0
    finally:
        await harness.tasks.stop()
        await harness.store.close()


@pytest.mark.asyncio
async def test_expired_local_approval_is_refused(tmp_path) -> None:
    """An overdue local approval is ``approval_expired`` even if the ref claims a future."""
    harness = await build_harness(tmp_path)
    try:
        params = submit_params()
        stored = await harness.approvals.create_cross_end_submit(
            task={"task_id": params["task_id"], "root_task_id": params["root_task_id"]},
            tool=params["kind"],
            reason="cross-end task submission",
            display_reason={"en": "Run", "zh": "执行"},
            params=params,
        )
        await harness.approvals.human_decide(
            stored["approval_id"],
            allowed=True,
            actor="astrbot_admin:alice",
            channel="web",
        )
        # Only the stored row's deadline is authoritative for "still valid now".
        await harness.store._conn().execute(
            "UPDATE approvals SET expires_at = ? WHERE approval_id = ?",
            (time.time() - 10, stored["approval_id"]),
        )
        await harness.store._conn().commit()

        params["approval_ref"] = harness.ref(stored["approval_id"], params)
        result = await harness.tasks.submit(params)
        assert result["status"] == STATUS_PENDING_APPROVAL
        task = await wait_status(harness.store, params["task_id"])
        assert task["status"] == "rejected", task
        assert task["error"]["code"] == ERR_APPROVAL_EXPIRED
        await asyncio.sleep(0.05)
        assert harness.host.calls == 0
    finally:
        await harness.tasks.stop()
        await harness.store.close()


@pytest.mark.asyncio
async def test_missing_ref_still_opens_local_approval(tmp_path) -> None:
    """``null`` ref keeps the existing pending-approval behaviour (§12.5 point 5)."""
    harness = await build_harness(tmp_path)
    try:
        result = await harness.tasks.submit(submit_params(origin="llm"))
        assert result["status"] == STATUS_PENDING_APPROVAL
        await asyncio.sleep(0.05)
        assert harness.host.calls == 0
    finally:
        await harness.tasks.stop()
        await harness.store.close()
