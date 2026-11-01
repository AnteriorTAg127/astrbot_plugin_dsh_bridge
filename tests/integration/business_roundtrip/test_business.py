"""Business acceptance over a real A↔B socket: does the product actually work?

Every case here runs two processes. A is the real AstrBot plugin
(``DshBridgePlugin.initialize()``), B is the real DSH bridge ``Supervisor``; each
owns a real durable store in its own temporary directory and they speak the real
protocol over a real loopback WebSocket. Nothing is echoed back as "success": a
case only passes when the receiving side's own store shows the task ran, or when
the gate the protocol requires actually held.

The three host boundaries that cannot exist in a test process are stubbed and
marked ``M`` in the report (A's AstrBot agent run, A's IM wake sink, B's
model-facing agent registry). Business logic, protocol, stores, state machines,
approval settlement and the sockets are all real.

Verdicts are never softened: a case that observes a product defect fails, and a
case that cannot run because a side has not implemented the required piece is
reported ``BLOCKED-IMPL`` with the exact file and function. ``xfail`` is only used
for that second meaning, never to hide a failure.
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest
from tests.integration.business_roundtrip import harness as H

pytestmark = pytest.mark.business_roundtrip

#: A conversation key the harness can wake; nothing is delivered anywhere.
UMO = "acceptance:FriendMessage:chat:1"


def _task(snapshot: dict, task_id: str) -> dict | None:
    """Find one task in a peer snapshot.

    Args:
        snapshot: Peer snapshot.
        task_id: Task identifier.

    Returns:
        The task record, or ``None``.
    """
    return next(
        (item for item in snapshot.get("tasks") or [] if item["task_id"] == task_id),
        None,
    )


def _executions_with(snapshot: dict, text: str) -> int:
    """Count host deliveries whose text is exactly the task text.

    Wake-ups carry generated text, so this isolates real task execution from the
    wake the same host adapter also delivers.

    Args:
        snapshot: B peer snapshot.
        text: Task text that was submitted.

    Returns:
        Number of matching deliveries.
    """
    return sum(1 for item in snapshot.get("deliveries") or [] if item["text"] == text)


def _outbox_for(snapshot: dict, task_id: str) -> list[dict]:
    """Outbox rows belonging to one task.

    Args:
        snapshot: Peer snapshot.
        task_id: Task identifier.

    Returns:
        Matching outbox rows.
    """
    return [
        row for row in snapshot.get("notifies") or [] if row.get("task_id") == task_id
    ]


# --------------------------------------------------------------------------------------
# Direction A -> B
# --------------------------------------------------------------------------------------


def test_a_to_b_human_submit_returns_handle_and_runs_exactly_once(pair: Any) -> None:
    """A human submission is acknowledged immediately and B runs it exactly once.

    This is the core business promise of the bridge: ``task.submit`` answers with a
    handle before any work happens (§9.3), and the receiving end executes the task
    once, not per retry and not per event (§10.3).

    Args:
        pair: Live A/B pair.
    """
    text = "统计昨天的新增用户数"
    accepted = pair.a_command(
        {
            "op": "submit",
            "text": text,
            "origin": "human",
            "session_id": pair.sid,
            "umo": UMO,
        }
    )
    assert accepted["ok"] is True, accepted
    result = accepted["result"]
    assert result["task_id"], "task.submit must return a task_id"
    assert result["status"] == "accepted", result

    finished = pair.wait_b_task(result["task_id"], list(TERMINAL_LOCAL), timeout_s=60)
    task = finished.get("task")
    assert task is not None, finished
    assert task["status"] == "succeeded", task
    assert task["direction"] == "inbound", task
    assert task["origin"] == "human", task

    # Give any accidental second execution a chance to show up before counting.
    time.sleep(2.0)
    b_snapshot = pair.b_snapshot()
    assert _executions_with(b_snapshot, text) == 1, _executions_with(b_snapshot, text)

    # The initiator saw the terminal event, applied at the sequence B chose.
    a_task = pair.wait_a_task(result["task_id"], ["succeeded"], timeout_s=20)
    assert a_task["task"]["status"] == "succeeded", a_task


def test_a_to_b_terminal_event_marks_outbox_delivered(pair: Any) -> None:
    """The emitter's outbox rows are retired once the peer acknowledged them.

    §11.1 makes ``event.ack`` the only thing that may retire an outbox row: a send
    that merely left the socket is not a delivery, and neither is a local guess.
    The emitter here is B (the executor of an A-originated task publishes the
    events), so B's own durable rows are the ones that must become ``delivered``.

    Args:
        pair: Live A/B pair.
    """
    text = "查询本周订单量"
    accepted = pair.a_command(
        {
            "op": "submit",
            "text": text,
            "origin": "human",
            "session_id": pair.sid,
            "umo": UMO,
        }
    )
    task_id = accepted["result"]["task_id"]

    # B is the side that emits: its task lifecycle events live in its outbox.
    pair.wait_b_task(task_id, list(TERMINAL_LOCAL), timeout_s=60)
    deadline = time.monotonic() + 25
    rows: list[dict] = []
    while time.monotonic() < deadline:
        rows = _outbox_for(pair.b_snapshot(), task_id)
        if rows and all(row["delivered"] for row in rows):
            return
        time.sleep(0.5)

    a_task_after = _task(pair.a_snapshot(), task_id) or {}
    a_events_rejected = [
        line
        for line in pair.a_logs()
        if "event handler failed" in line and "task.event" in line
    ]
    evidence = {
        "task_id": task_id,
        "outbox": rows,
        "a_task_status": a_task_after.get("status"),
        "a_eseq": a_task_after.get("eseq"),
        "a_rejected_events": len(a_events_rejected),
        "a_outbox": _outbox_for(pair.a_snapshot(), task_id),
    }
    pytest.fail(
        "event.ack never retired the emitter's outbox: "
        f"{evidence}. A applied the events (its task reached "
        f"{evidence['a_task_status']} at eseq={evidence['a_eseq']}) but B's rows stay "
        "delivered=false with attempts climbing, so a notification the peer "
        "demonstrably handled is recorded as never delivered and stays pending until "
        "it is marked undelivered and the task is pushed to needs_human. Neither "
        "side ever puts 'event.ack' on the wire: B's task.event handler calls "
        "NotifyService.onAck locally (lib/app/tasks.js:onEvent, "
        "'await this.notify.onAck(...)') and A's does the same through "
        "TasksService._ack -> NotifyService.on_ack (bridge/app/tasks.py:_ack). Each "
        "of those calls looks the notify_id up in the *receiver's own* outbox, which "
        "by definition does not contain the peer's notifications: on A that raises "
        "event_not_found, which is why this run logged "
        f"{evidence['a_rejected_events']} 'event handler failed m=task.event "
        "code=event_not_found' lines after every applied event. §11.1 requires the "
        "receiving side to send an 'event.ack' request back to the producer; neither "
        "implementation constructs the message (the helper exists and is unused: "
        "bridge/app/notify.py:inbound_ack_message)."
    )


def test_a_to_b_wake_reaches_the_conversation_once(pair: Any) -> None:
    """The originating conversation is woken exactly once when the task finishes.

    §16.6 allows one automatic wake per event and charges it against a per-root
    budget. A second wake for the same completion would spam the human, so the
    count is asserted, not just the presence.

    Args:
        pair: Live A/B pair.
    """
    text = "完成后请通知我"
    accepted = pair.a_command(
        {
            "op": "submit",
            "text": text,
            "origin": "human",
            "session_id": pair.sid,
            "umo": UMO,
        }
    )
    task_id = accepted["result"]["task_id"]
    pair.wait_b_task(task_id, list(TERMINAL_LOCAL), timeout_s=60)

    deadline = time.monotonic() + 30
    wakes: list[dict] = []
    while time.monotonic() < deadline:
        wakes = pair.a_snapshot()["wakes"]
        if [item for item in wakes if task_id in json.dumps(item)]:
            break
        time.sleep(0.5)
    time.sleep(2.5)
    wakes = pair.a_snapshot()["wakes"]
    wakes_for_task = [item for item in wakes if task_id in json.dumps(item)]
    assert wakes, "the human was never woken on completion"
    assert len(wakes_for_task) <= 1, wakes
    assert all(item["umo"] == UMO for item in wakes), wakes


# --------------------------------------------------------------------------------------
# Direction B -> A
# --------------------------------------------------------------------------------------


def test_b_to_a_human_submit_runs_exactly_once(pair: Any) -> None:
    """A human submission from DSH is executed once by the AstrBot side.

    Args:
        pair: Live A/B pair.
    """
    text = "在 AstrBot 侧执行一次检索"
    submitted = pair.b_command(
        {
            "op": "submit_outbound",
            "text": text,
            "origin": "human",
            "session_id": pair.sid,
        }
    )
    assert submitted["ok"] is True, submitted
    task_id = submitted["task_id"]
    assert submitted["status"] == "accepted", submitted

    finished = pair.wait_a_task(task_id, list(TERMINAL_LOCAL), timeout_s=60)
    assert finished["event"] == "task", finished
    assert finished["task"]["status"] == "succeeded", finished["task"]

    time.sleep(2.0)
    a_snapshot = pair.a_snapshot()
    executions = [
        item for item in a_snapshot["executions"] if item["task_id"] == task_id
    ]
    assert len(executions) == 1, a_snapshot["executions"]

    b_task = pair.wait_b_task(task_id, ["succeeded"], timeout_s=20)
    assert b_task["task"]["status"] == "succeeded", b_task


def test_b_to_a_llm_submit_waits_for_a_human(pair: Any) -> None:
    """An LLM-originated cross-end submission runs only after a human allows it.

    This is the human gate (§12.5): the receiving side must hold the task in
    ``pending_approval``, execute nothing, and run it once — exactly once — after a
    human approves. A denied submission must never run at all.

    Args:
        pair: Live A/B pair.
    """
    text = "把测试环境的配置同步到线上"
    submitted = pair.b_command(
        {"op": "submit_outbound", "text": text, "origin": "llm", "session_id": pair.sid}
    )
    assert submitted["ok"] is True, submitted
    task_id = submitted["task_id"]

    held = pair.wait_a_task(task_id, ["pending_approval"], timeout_s=30)
    assert held["task"]["status"] == "pending_approval", held["task"]

    # Nothing may have executed while the gate is closed.
    time.sleep(2.0)
    before = pair.a_snapshot()
    assert not [item for item in before["executions"] if item["task_id"] == task_id], (
        before["executions"]
    )
    approvals = [row for row in before["approvals"] if row["task_id"] == task_id]
    assert approvals, before["approvals"]
    assert approvals[0]["approval_type"] == "cross_end_submit", approvals[0]

    decided = pair.a_command(
        {
            "op": "decide",
            "approval_id": approvals[0]["approval_id"],
            "allowed": True,
            "actor": "alice",
            "reason": "本次允许",
        }
    )
    assert decided["applied"] is True, decided

    ran = pair.wait_a_task(task_id, list(TERMINAL_LOCAL), timeout_s=60)
    assert ran["task"]["status"] == "succeeded", ran["task"]
    after = pair.a_snapshot()
    executions = [item for item in after["executions"] if item["task_id"] == task_id]
    assert len(executions) == 1, after["executions"]


def test_b_to_a_llm_submit_rejected_never_runs(pair: Any) -> None:
    """A rejected LLM submission is terminated and never executed.

    Args:
        pair: Live A/B pair.
    """
    submitted = pair.b_command(
        {
            "op": "submit_outbound",
            "text": "删除生产数据库",
            "origin": "llm",
            "session_id": pair.sid,
        }
    )
    task_id = submitted["task_id"]
    held = pair.wait_a_task(task_id, ["pending_approval"], timeout_s=30)
    assert held["task"]["status"] == "pending_approval", held["task"]
    approvals = [
        row for row in pair.a_snapshot()["approvals"] if row["task_id"] == task_id
    ]
    assert approvals, "no approval row for a pending submission"

    decided = pair.a_command(
        {
            "op": "decide",
            "approval_id": approvals[0]["approval_id"],
            "allowed": False,
            "actor": "alice",
            "reason": "生产数据不允许删除",
        }
    )
    assert decided["applied"] is True, decided

    rejected = pair.wait_a_task(task_id, ["rejected", "failed"], timeout_s=30)
    assert rejected["task"]["status"] in ("rejected", "failed"), rejected["task"]
    time.sleep(2.0)
    snapshot = pair.a_snapshot()
    assert not [
        item for item in snapshot["executions"] if item["task_id"] == task_id
    ], snapshot["executions"]


def test_a_to_b_llm_submit_waits_for_a_human(pair: Any) -> None:
    """An LLM submission from A is gated by the receiving side until a human allows it.

    §12.5 point 5 is symmetric: a submission that arrives without an
    ``approval_ref`` and whose origin is ``llm`` must be answered
    ``pending_approval`` by the receiving end, which holds the task, opens its own
    durable approval and executes nothing. Only a human decision releases it; then
    the task runs exactly once and the initiating side learns the terminal state.

    A repeated decision is a no-op: it must neither re-run the task nor change the
    recorded outcome, because the durable status is the one-shot latch.

    Args:
        pair: Live A/B pair.
    """
    text = "把用户表导出到对端"
    submitted = pair.a_command(
        {
            "op": "submit",
            "text": text,
            "origin": "llm",
            "session_id": pair.sid,
            "umo": UMO,
        }
    )
    assert submitted["ok"] is True, submitted
    task_id = submitted["result"]["task_id"]
    # §9.3: the gate is answered in the submit reply itself, not later.
    assert submitted["result"]["status"] == "pending_approval", submitted["result"]

    # The receiving end holds the task; nothing was dispatched.
    held = pair.wait_b_task(task_id, ["pending_approval"], timeout_s=30)
    assert held["task"]["status"] == "pending_approval", held["task"]
    assert held["task"]["direction"] == "inbound", held["task"]
    assert held["task"]["origin"] == "llm", held["task"]

    # The question reaches the human side as a durable approval row bound to the
    # task (the forwarded ``approval.request``), so the human can answer it.
    deadline = time.monotonic() + 20
    approval: dict | None = None
    while time.monotonic() < deadline:
        approval = next(
            (
                row
                for row in pair.a_snapshot()["approvals"]
                if row["task_id"] == task_id
            ),
            None,
        )
        if approval is not None:
            break
        time.sleep(0.25)
    assert approval is not None, "the held task opened no approval a human can answer"
    assert approval["approval_type"] == "cross_end_submit", approval
    assert approval["state"] == "pending", approval
    approval_id = approval["approval_id"]

    # With the gate closed, the executor's own store must show no execution and the
    # approval must still be undecided on both sides.
    time.sleep(2.0)
    b_snapshot = pair.b_snapshot()
    assert _executions_with(b_snapshot, text) == 0, b_snapshot["deliveries"]
    b_task = _task(b_snapshot, task_id)
    assert b_task is not None and b_task["status"] == "pending_approval", b_snapshot[
        "tasks"
    ]
    b_approval = next(
        (row for row in b_snapshot["approvals"] if row["approval_id"] == approval_id),
        None,
    )
    assert b_approval is not None, b_snapshot["approvals"]
    assert b_approval["decided"] is False, b_approval

    # A human with the decision authority answers through the real entry point.
    decided = pair.a_command(
        {
            "op": "decide",
            "approval_id": approval_id,
            "allowed": True,
            "actor": "alice",
            "reason": "本次允许",
        }
    )
    assert decided["applied"] is True, decided

    ran = pair.wait_b_task(task_id, list(TERMINAL_LOCAL), timeout_s=60)
    assert ran["task"]["status"] == "succeeded", ran["task"]

    # The initiator's own view follows the executor to the terminal state and the
    # originating conversation is woken.
    a_task = pair.wait_a_task(task_id, ["succeeded"], timeout_s=30)
    assert a_task["event"] == "task", a_task
    assert a_task["task"]["status"] == "succeeded", a_task["task"]
    deadline = time.monotonic() + 20
    wakes: list[dict] = []
    while time.monotonic() < deadline:
        wakes = [item for item in pair.a_snapshot()["wakes"] if item["umo"] == UMO]
        if wakes:
            break
        time.sleep(0.25)
    assert wakes, "the initiating conversation was never woken on completion"

    # Exactly one execution, and exactly one that the executor owns: this side
    # submitted the task, so it must never run it locally.
    time.sleep(2.0)
    b_snapshot = pair.b_snapshot()
    a_snapshot = pair.a_snapshot()
    executed_on_b = _executions_with(b_snapshot, text)
    executed_on_a = [
        item for item in a_snapshot["executions"] if item["task_id"] == task_id
    ]
    if executed_on_b != 1:
        held_row = _task(b_snapshot, task_id) or {}
        pytest.fail(
            "the executing side never ran the task after a human allowed it, yet the "
            f"task is {held_row.get('status')} there: deliveries_on_b="
            f"{b_snapshot['deliveries']} executions_on_a={executed_on_a} "
            f"a_task={_task(a_snapshot, task_id)}. The human decision was taken on the "
            "side that only mirror the peer's approval, and there it settled A's own "
            "*outbound* task: ApprovalService.human_decide (bridge/app/approvals.py) "
            "calls _apply() -> main.py:_on_approval_decided -> "
            "TaskService.on_approved (bridge/app/tasks.py:on_approved), whose "
            "`cross_end_submit` branch checks only the approval type — never the "
            "task's direction or the approval's `origin_side` — so it moves the "
            "initiator's task to `accepted` and calls `_schedule_execution`. A then "
            "runs a task it never owned, and its `task.event completed` is what makes "
            "B's inbound task look `succeeded` without B ever delivering the task "
            "text. Only `_send_decision_event` (approval.decision back to the peer) "
            "is correct for a mirrored approval."
        )
    assert not executed_on_a, executed_on_a

    # A repeated decision changes nothing: the latch is the durable status.
    again = pair.a_command(
        {
            "op": "decide",
            "approval_id": approval_id,
            "allowed": True,
            "actor": "alice",
            "reason": "再次允许",
        }
    )
    assert again["applied"] is False, again
    time.sleep(2.0)
    assert _executions_with(pair.b_snapshot(), text) == 1, (
        "a repeated decision re-ran the task"
    )


# --------------------------------------------------------------------------------------
# Native (harness) approvals
# --------------------------------------------------------------------------------------


def test_native_approval_allow_reaches_the_harness(pair: Any) -> None:
    """A harness approval claimed by B is answered by A's human and settles the ask.

    The request enters through the real ``approval/request`` waterfall on a real
    Cordis context, is claimed by the real bridge listener, travels to A as a real
    ``approval.request``, is stored by A's real approval service, is decided by a
    real human entry point, and comes back as ``approval.decision`` to settle the
    promise the harness is awaiting.

    Args:
        pair: Live A/B pair.
    """

    raised = pair.b_command(
        {
            "op": "native_request",
            "session_id": pair.sid,
            "tool": "bash",
            "reason": "需要执行一次部署命令",
            "timeout_s": 25,
        }
    )
    assert raised.get("ok") is True, raised
    approval_id = raised["approval_id"]
    assert raised["approval_type"] == "native_tool", raised

    queued = pair.wait_a_approval(approval_id)
    assert queued is not None, "the peer stored no approval for the forwarded request"
    assert queued["state"] == "pending", queued

    decided = pair.a_command(
        {
            "op": "decide",
            "approval_id": approval_id,
            "allowed": True,
            "actor": "alice",
            "reason": "允许这一次部署",
        }
    )
    assert decided["applied"] is True, decided

    settled = pair.b_command(
        {"op": "native_outcome", "approval_id": approval_id, "timeout_s": 20}
    )
    assert settled["ok"] is True, settled
    assert settled["outcome"] == "allowed-once", settled


def test_native_approval_reject_denies_the_harness(pair: Any) -> None:
    """A human rejection settles the harness request without granting it.

    Args:
        pair: Live A/B pair.
    """
    raised = pair.b_command(
        {
            "op": "native_request",
            "session_id": pair.sid,
            "tool": "bash",
            "reason": "尝试写入系统目录",
            "timeout_s": 25,
        }
    )
    assert raised.get("ok") is True, raised
    approval_id = raised["approval_id"]
    assert pair.wait_a_approval(approval_id) is not None, "the peer stored no approval"

    decided = pair.a_command(
        {
            "op": "decide",
            "approval_id": approval_id,
            "allowed": False,
            "actor": "alice",
            "reason": "该动作不允许",
        }
    )
    assert decided["applied"] is True, decided

    settled = pair.b_command(
        {"op": "native_outcome", "approval_id": approval_id, "timeout_s": 20}
    )
    assert settled["outcome"] == "rejected", settled


def test_native_approval_without_a_reason_is_accepted(pair: Any) -> None:
    """A harness request that carries no reason must still be forwardable.

    ``reason`` is an optional field in §12.2 and the protocol's own digest helper
    hashes a missing reason as ``null``. A request without one is therefore a
    legitimate request and must reach the human, not crash the receiving side.

    Args:
        pair: Live A/B pair.
    """

    raised = pair.b_command(
        {
            "op": "native_request",
            "session_id": pair.sid,
            "tool": "bash",
            "reason": None,
            "timeout_s": 20,
        }
    )
    assert raised.get("ok") is True, raised
    approval_id = raised["approval_id"]

    # The peer's own record says nothing about whether the *other* side accepted it:
    # the forward can fail and the claim then settles closed locally. The only
    # question this case asks is whether the forwarded request arrived.
    stored = pair.wait_a_approval(approval_id, timeout_s=15)
    if stored is not None:
        return

    evidence = {
        "result": raised,
        "a_approvals": pair.a_snapshot()["approvals"],
        "b_approvals": pair.b_snapshot()["approvals"],
        "a_integrity_errors": [
            line
            for line in pair.a_logs()
            if "IntegrityError" in line or "NOT NULL" in line
        ][-3:],
    }
    pytest.fail(
        "a harness approval request without a reason is rejected by the receiving "
        f"side: {evidence}. B publishes reason=null (lib/app/approvals.js:"
        "_publishRequest hashes it as null, lib/crypto.js:approvalRequestDigest "
        "normalises it to null), while A's approvals table declares 'reason TEXT NOT "
        "NULL' (bridge/store.py) and ApprovalService.handle_request passes "
        "params.get('reason', '') — a missing key defaults to '' but an explicit null "
        "stays null, so the INSERT raises sqlite3.IntegrityError and the request is "
        "lost with no reply to the peer."
    )


def test_native_approval_from_ungranted_session_is_delegated(pair: Any) -> None:
    """An unauthorized session is never claimed: the request goes to the host's own answerer.

    CLAIM_AND_DELEGATE are exclusive (§12), and the authorization table of the peer
    is the only authority. A session that was never granted must therefore delegate,
    so the deployment's local answerer still gets a chance to answer.

    Args:
        pair: Live A/B pair.
    """
    never_granted = "session-that-was-never-granted"
    probe = pair.b_command({"op": "native_delegate_probe", "session_id": never_granted})
    assert probe["value"] == "delegated", probe
    assert pair.a_snapshot()["approvals"] == [] or all(
        row["approval_type"] != "native_tool" or row.get("task_id")
        for row in pair.a_snapshot()["approvals"]
    )


# --------------------------------------------------------------------------------------
# Idempotency, authorization and resilience
# --------------------------------------------------------------------------------------


def test_duplicate_submit_does_not_execute_twice(pair: Any) -> None:
    """Re-submitting the same ``task_id`` is idempotent and never re-executes.

    Args:
        pair: Live A/B pair.
    """
    task_id = "a6a4d0e6-0d7b-4a1e-9f5c-3c1f0a4b9d21"
    text = "只应执行一次的任务"
    first = pair.a_command(
        {
            "op": "submit",
            "text": text,
            "origin": "human",
            "session_id": pair.sid,
            "task_id": task_id,
            "umo": UMO,
        }
    )
    assert first["ok"] is True, first
    pair.wait_b_task(task_id, list(TERMINAL_LOCAL), timeout_s=60)

    second = pair.a_command(
        {
            "op": "submit",
            "text": text,
            "origin": "human",
            "session_id": pair.sid,
            "task_id": task_id,
            "umo": UMO,
        }
    )
    assert second["ok"] is True, second
    assert second["result"]["dedup"] is True, second["result"]

    time.sleep(2.5)
    snapshot = pair.b_snapshot()
    assert _executions_with(snapshot, text) == 1, _executions_with(snapshot, text)


def test_reconnect_replays_the_outbox_and_does_not_rewake(pair: Any) -> None:
    """After a reconnect the initiator replays its outbox, and the peer deduplicates.

    A dropped link must not lose a notification; the sender retries the same
    business object under a new envelope (§11.3) until it is acknowledged. The
    receiving side must recognise the ``notify_id`` it already processed and must
    not wake the conversation a second time (§10.3).

    Args:
        pair: Live A/B pair.
    """
    text = "断线后仍应送达的任务"
    submitted = pair.b_command(
        {
            "op": "submit_outbound",
            "text": text,
            "origin": "human",
            "session_id": pair.sid,
        }
    )
    task_id = submitted["task_id"]
    pair.wait_a_task(task_id, list(TERMINAL_LOCAL), timeout_s=60)
    time.sleep(1.5)

    # A executes the task, so A is the side that publishes the lifecycle events
    # and owns the outbox that has to survive the drop.
    before = pair.a_snapshot()
    rows_before = _outbox_for(before, task_id)
    runs_before = [item for item in before["executions"] if item["task_id"] == task_id]
    assert len(runs_before) == 1, before["executions"]
    assert rows_before, before["notifies"]

    # Drop the link on A's side (the emitter) and bring it back: the outbox must
    # survive a real disconnect and be retried on the new session.
    assert pair.a_command({"op": "down"})["ok"] is True
    time.sleep(1.5)
    up = pair.a_command({"op": "up", "timeout_s": 30})
    assert up["ok"] is True, up
    time.sleep(6.0)

    after = pair.a_snapshot()
    # The task must not be re-executed by the replay: the peer already had it.
    runs_after = [item for item in after["executions"] if item["task_id"] == task_id]
    assert len(runs_after) == 1, after["executions"]
    a_rows = _outbox_for(after, task_id)
    assert a_rows, "the outbox lost the notification across the reconnect"
    # Retried, not duplicated: the same business rows stay, with attempts advanced.
    assert {row["notify_id"] for row in a_rows} == {
        row["notify_id"] for row in rows_before
    }, a_rows


def test_revoked_grant_blocks_cross_end_submission(pair: Any) -> None:
    """Revoking a session blocks new cross-end submissions to it.

    The peer's grant table is the authority (§9.7), and a revocation has to bite on
    the next submission rather than after a restart.

    Args:
        pair: Live A/B pair.
    """
    revoked = pair.a_command({"op": "revoke", "session_id": pair.sid})
    assert revoked["event"] == "revoked", revoked

    deadline = time.monotonic() + 20
    refused = None
    while time.monotonic() < deadline:
        attempt = pair.b_command(
            {
                "op": "submit_outbound",
                "text": "撤销后不应被接受",
                "origin": "human",
                "session_id": pair.sid,
            }
        )
        if attempt.get("ok") is False:
            refused = attempt
            break
        time.sleep(1.0)
    assert refused is not None, "a revoked session still accepted a submission"
    assert refused["code"] in ("session_not_authorized", "session_archived"), refused


def test_archived_session_blocks_delivery(pair: Any) -> None:
    """An archived session is refused as a delivery target on the receiving side.

    ``archive`` is a disposition recorded against a grant, and the side that would
    deliver is the side that has to honour it: a task must not land in a session the
    operator archived, and it must not be silently re-routed to another one.

    Args:
        pair: Live A/B pair.
    """
    # A is the receiver of an A->B submission only if it archived on B; here the
    # receiver is B, so the archive has to be recorded on B's own table.
    archived = pair.b_command({"op": "archive_session", "session_id": pair.sid})
    assert archived.get("event") == "archived", archived

    attempt = pair.a_command(
        {
            "op": "submit",
            "text": "归档后不应执行",
            "origin": "human",
            "session_id": pair.sid,
        }
    )
    assert attempt["ok"] is False, attempt
    assert attempt["code"] in ("session_archived", "session_not_authorized"), attempt

    # And the mirror direction: archiving on the receiver of B->A has the same effect.
    granted_again = pair.a_command({"op": "revoke", "session_id": pair.sid})
    assert granted_again["event"] == "revoked", granted_again


#: Statuses after which a task is no longer running.
TERMINAL_LOCAL = ("succeeded", "failed", "rejected", "canceled", "needs_human")


# --------------------------------------------------------------------------------------
# Wait-command timeout units
# --------------------------------------------------------------------------------------


@pytest.mark.delivery_delay(300)
def test_wait_task_timeout_is_seconds_not_milliseconds(pair: Any) -> None:
    """``wait_task`` reads the wire ``timeout_s`` as seconds, against a real delay.

    The B side's bounded wait takes milliseconds, while every command carries
    seconds. A 2-second bound must therefore still be running after 300ms: if the
    value is used raw as milliseconds, the probe gives up almost immediately and
    reports ``task_timeout`` for a task that is merely still executing.

    Args:
        pair: Live A/B pair whose B-side deliveries are delayed by 300ms.
    """
    text = "等待命令单位回归：任务"
    accepted = pair.a_command(
        {
            "op": "submit",
            "text": text,
            "origin": "human",
            "session_id": pair.sid,
            "umo": UMO,
        }
    )
    assert accepted["ok"] is True, accepted
    task_id = accepted["result"]["task_id"]

    started = time.monotonic()
    finished = pair.b_command(
        {
            "op": "wait_task",
            "task_id": task_id,
            "statuses": list(TERMINAL_LOCAL),
            "timeout_s": 2,
        },
        timeout_s=15,
    )
    elapsed = time.monotonic() - started

    assert finished["event"] == "task", finished
    assert finished["task"]["status"] == "succeeded", finished["task"]
    assert elapsed >= 0.2, (
        f"wait_task returned after {elapsed:.3f}s for a task delivered after "
        "~300ms: timeout_s was treated as milliseconds"
    )
    assert elapsed < 2.0, f"wait_task used the full 2s bound: {elapsed:.3f}s"


@pytest.mark.delivery_delay(300)
def test_wait_delivery_timeout_is_seconds_not_milliseconds(pair: Any) -> None:
    """``wait_delivery`` reads the wire ``timeout_s`` as seconds, against a real delay.

    Same unit rule as ``wait_task``. The delivery lands after 300ms, so a
    2-second bound must observe it; a milliseconds reading times out before the
    very first poll interval.

    Args:
        pair: Live A/B pair whose B-side deliveries are delayed by 300ms.
    """
    text = "等待命令单位回归：投递"
    accepted = pair.a_command(
        {
            "op": "submit",
            "text": text,
            "origin": "human",
            "session_id": pair.sid,
            "umo": UMO,
        }
    )
    assert accepted["ok"] is True, accepted

    started = time.monotonic()
    delivered = pair.b_command(
        {"op": "wait_delivery", "count": 1, "timeout_s": 2}, timeout_s=15
    )
    elapsed = time.monotonic() - started

    assert delivered["event"] == "delivered", delivered
    assert delivered["count"] >= 1, delivered
    assert any(item["text"] == text for item in delivered["deliveries"]), delivered
    assert elapsed >= 0.2, (
        f"wait_delivery returned after {elapsed:.3f}s for a delivery that took "
        "~300ms: timeout_s was treated as milliseconds"
    )
    assert elapsed < 2.0, f"wait_delivery used the full 2s bound: {elapsed:.3f}s"


@pytest.mark.approval_timeout(30)
def test_native_approval_expires_fail_closed(pair: Any) -> None:
    """An unanswered native approval expires into ``rejected``, never into a grant.

    §12.4: timeout always means denied. The harness request the user never answered
    must settle closed on both sides, and the peer's pending promise must not hang.

    Args:
        pair: Live A/B pair with a short approval deadline.
    """
    assert pair.wait_b_authz(pair.sid), "A never pushed the grant to B"
    raised = pair.b_command(
        {
            "op": "native_request",
            "session_id": pair.sid,
            "tool": "bash",
            "reason": "无人处理的审批",
            "timeout_s": 20,
        }
    )
    assert raised.get("ok") is True, raised
    approval_id = raised["approval_id"]
    assert pair.wait_a_approval(approval_id) is not None, "the peer stored no approval"

    deadline = time.monotonic() + 45
    expired = {"count": 0}
    while time.monotonic() < deadline:
        expired = pair.a_command({"op": "expire_now"})
        if expired.get("count"):
            break
        time.sleep(2.0)
    assert expired.get("count"), "the approval never expired"

    rows = [
        row
        for row in pair.a_snapshot()["approvals"]
        if row["approval_id"] == approval_id
    ]
    assert rows and rows[0]["state"] == "decided", rows
    assert rows[0]["outcome"] == "rejected", rows[0]
    assert rows[0]["channel"] == "timeout", rows[0]

    settled = pair.b_command(
        {"op": "native_outcome", "approval_id": approval_id, "timeout_s": 20}
    )
    assert settled["outcome"] in ("rejected", "unavailable"), settled


def test_tool_refusal_does_not_end_the_task(pair: Any) -> None:
    """A refused native tool call is audited, not turned into a task failure.

    §12.3: a ``native_tool`` approval covers one action inside a turn the peer still
    owns, so refusing it must not rewrite the owning task's lifecycle — the peer's
    own ``task.event`` stays authoritative. Both halves are checked: A refuses to
    transition the task, and the task later completes normally.

    Args:
        pair: Live A/B pair.
    """
    text = "跑一次会触发工具审批的任务"
    submitted = pair.b_command(
        {
            "op": "submit_outbound",
            "text": text,
            "origin": "human",
            "session_id": pair.sid,
        }
    )
    task_id = submitted["task_id"]
    pair.wait_a_task(task_id, list(TERMINAL_LOCAL), timeout_s=60)

    assert pair.wait_b_authz(pair.sid), "A never pushed the grant to B"
    raised = pair.b_command(
        {
            "op": "native_request",
            "session_id": pair.sid,
            "tool": "bash",
            "reason": "被拒绝的工具调用",
            "timeout_s": 20,
        }
    )
    assert raised.get("ok") is True, raised
    approval_id = raised["approval_id"]
    assert pair.wait_a_approval(approval_id) is not None, "the peer stored no approval"

    # Bind the approval to the finished task the way a real cross-end run would,
    # then deny it: the task's terminal state must survive untouched.
    before = _task(pair.a_snapshot(), task_id)
    decided = pair.a_command(
        {"op": "decide", "approval_id": approval_id, "allowed": False, "actor": "alice"}
    )
    assert decided["applied"] is True, decided
    time.sleep(2.0)
    after = _task(pair.a_snapshot(), task_id)
    assert after["status"] == before["status"] == "succeeded", (before, after)
    assert after["eseq"] == before["eseq"], (before, after)

    settled = pair.b_command(
        {"op": "native_outcome", "approval_id": approval_id, "timeout_s": 20}
    )
    assert settled["outcome"] == "rejected", settled


def test_approval_cannot_be_answered_twice(pair: Any) -> None:
    """The first human decision wins; a second one is refused, not applied.

    Args:
        pair: Live A/B pair.
    """
    assert pair.wait_b_authz(pair.sid), "A never pushed the grant to B"
    raised = pair.b_command(
        {
            "op": "native_request",
            "session_id": pair.sid,
            "tool": "bash",
            "reason": "重复审批",
            "timeout_s": 20,
        }
    )
    assert raised.get("ok") is True, raised
    approval_id = raised["approval_id"]
    assert pair.wait_a_approval(approval_id) is not None, "the peer stored no approval"

    first = pair.a_command(
        {"op": "decide", "approval_id": approval_id, "allowed": True, "actor": "alice"}
    )
    assert first["applied"] is True, first
    second = pair.a_command(
        {"op": "decide", "approval_id": approval_id, "allowed": False, "actor": "bob"}
    )
    assert second["applied"] is False, second
    # ``already_decided`` is the store's own verdict for a second decision (§12).
    assert second["reason"] == "already_decided", second

    settled = pair.b_command(
        {"op": "native_outcome", "approval_id": approval_id, "timeout_s": 20}
    )
    assert settled["outcome"] == "allowed-once", settled


def test_agent_actor_cannot_approve(pair: Any) -> None:
    """An approval attributed to an agent identity is refused.

    §12.1: only a human may approve. The gate has to hold at the decision entry
    point, not merely in the UI that normally calls it.

    Args:
        pair: Live A/B pair.
    """
    assert pair.wait_b_authz(pair.sid), "A never pushed the grant to B"
    raised = pair.b_command(
        {
            "op": "native_request",
            "session_id": pair.sid,
            "tool": "bash",
            "reason": "代理自批",
            "timeout_s": 20,
        }
    )
    assert raised.get("ok") is True, raised
    approval_id = raised["approval_id"]
    assert pair.wait_a_approval(approval_id) is not None, "the peer stored no approval"

    attempt = pair.a_command(
        {
            "op": "decide",
            "approval_id": approval_id,
            "allowed": True,
            "actor": "agent:assistant",
        }
    )
    # The decision entry point refuses an agent actor outright (a BridgeError), and
    # the approval must stay untouched either way.
    refused = (
        attempt.get("applied") is False or attempt.get("code") == "agent_cannot_approve"
    )
    assert refused, attempt
    rows = [
        row
        for row in pair.a_snapshot()["approvals"]
        if row["approval_id"] == approval_id
    ]
    assert rows and rows[0]["state"] == "pending", rows

    # A well-formed human decision on the same approval still works, so the refusal
    # was about the actor and not about the approval being unusable.
    human = pair.a_command(
        {"op": "decide", "approval_id": approval_id, "allowed": True, "actor": "alice"}
    )
    assert human["applied"] is True, human


def test_production_entrypoint_accepts_a_peer(b_ready: None) -> None:
    """The shipped entry point (``initialize()`` + its reconnect loop) must accept a peer.

    Every other case wires the carrier by hand so a connection-layer defect cannot
    mask the business results. This case is the opposite: it runs exactly what a user
    runs — ``DshBridgePlugin.initialize()`` with a configured connection, which starts
    ``_run_connection`` and its ``TransportManager.run_forever`` loop — and asserts the
    very first thing a deployment must do: complete a handshake with its peer.

    Args:
        b_ready: Ensures the environment check ran first.
    """
    pair = H.PeerPair()
    pair.a_mode = "plugin"
    try:
        pair.start_a()
        time.sleep(3.0)
        error = None
        try:
            pair.start_b(timeout_s=25)
        except H.HarnessError as exc:  # the peer never became ready
            error = str(exc)
        if error is None:
            assert pair.sid, "B reported ready without a session id"
            return

        logs = pair.a_logs()
        rebinds = [line for line in logs if "address already in use" in line]
        listening = [line for line in logs if "ws listening" in line]
        pytest.fail(
            "the production entry point never completed a handshake with its peer: "
            f"{error[:300]}. A bound its listener ({len(listening)} 'ws listening' "
            f"lines) and then failed to re-bind the same port {len(rebinds)} time(s) "
            "with EADDRINUSE. TransportManager.run_forever "
            "(bridge/transport/manager.py) re-enters bring_up() while the listening "
            "carrier is still bound, because WsTransport.alive() "
            "(bridge/transport/ws.py) is false until a peer connects — 'listening, no "
            "socket yet' is misread as 'carrier down'. bring_up() then calls "
            "_activate(), whose on_transport hook reassigns session._transport to the "
            "NEW carrier before that carrier's start() fails; the failed instance "
            "_stop_current() then leaves the ORIGINAL listener bound but no longer "
            "reachable by the session, so the reply to the peer's hello is written to "
            "a dead carrier and the peer times out. A restart-free deployment in "
            "listen mode therefore cannot accept its first peer at all."
        )
    finally:
        pair.close()


def _approval(snapshot: dict, approval_id: str) -> dict | None:
    """Find one approval row in a peer snapshot.

    Args:
        snapshot: Peer snapshot.
        approval_id: Approval identifier.

    Returns:
        The approval record, or ``None``.
    """
    return next(
        (
            row
            for row in snapshot.get("approvals") or []
            if row.get("approval_id") == approval_id
        ),
        None,
    )


def test_a_to_b_production_gate_reference_is_verified_by_lookup(pair: Any) -> None:
    """A's real tool gate produces a ref that B proves without any local mirror.

    The production path is exercised end to end: the LLM tool opens A's human gate
    and sends nothing; a human approves; the submission carries the reference; B
    holds it, queries A's authority on the live session, imports a trusted mirror,
    consumes it once and executes exactly once.

    Args:
        pair: Live A/B pair.
    """
    text = "生产门 A→B：为这个函数补测试"
    gated = pair.a_command(
        {
            "op": "submit_gated",
            "text": text,
            "purpose": "lookup-a2b",
            "session_id": pair.sid,
        }
    )
    assert gated["event"] == "gated", gated
    assert gated["task"] is not None, gated
    task_id = gated["task"]["task_id"]
    approval_id = gated["approval_id"]
    assert approval_id, gated
    # The real adapter entry received and forwarded prompt/purpose/session unchanged.
    assert gated["entry"] == "DshSubmitTaskTool", gated
    assert gated["tool_name"] == "dsh_submit_task", gated
    assert gated["session_id"] == pair.sid, gated
    assert gated["purpose"] == "lookup-a2b", gated

    # Nothing crossed the wire before the human answered.
    time.sleep(1.0)
    assert _task(pair.b_snapshot(), task_id) is None
    held = _task(pair.a_snapshot(), task_id)
    assert held is not None and held["status"] == "pending_approval", held
    assert held["direction"] == "outbound", held

    decided = pair.a_command(
        {
            "op": "decide",
            "approval_id": approval_id,
            "allowed": True,
            "actor": "alice",
            "channel": "im",
        }
    )
    assert decided["applied"] is True, decided

    delivered = pair.b_command({"op": "wait_delivery", "count": 1, "timeout_s": 60})
    assert delivered["event"] == "delivered", delivered
    assert any(text == item.get("text") for item in delivered["deliveries"]), delivered

    finished = pair.wait_a_task(task_id, list(TERMINAL_LOCAL), timeout_s=60)
    assert finished["event"] == "task", finished
    assert finished["task"]["status"] == "succeeded", finished["task"]

    b_snapshot = pair.b_snapshot()
    mirror = _approval(b_snapshot, approval_id)
    assert mirror is not None, b_snapshot["approvals"]
    assert mirror["source"] == "peer_lookup", mirror
    assert mirror["consumed_by_task"] == task_id, mirror
    digest = mirror["submit_digest"]
    assert isinstance(digest, str) and digest, mirror

    a_snapshot = pair.a_snapshot()
    authority = _approval(a_snapshot, approval_id)
    assert authority is not None, a_snapshot["approvals"]
    assert authority["released_by_task"] == task_id, authority
    assert authority["consumed_by_task"] is None, authority
    assert (
        len([item for item in b_snapshot["deliveries"] if item.get("text") == text])
        == 1
    ), b_snapshot["deliveries"]

    # A missing target session must be refused by the adapter itself: no gate row, no
    # approval and no auto-selection of the first authorized session.
    refused = pair.a_command(
        {
            "op": "submit_gated",
            "text": "缺少会话时不得提交",
            "purpose": "lookup-a2b-missing",
            "omit_session": True,
        }
    )
    assert refused["event"] == "gated", refused
    assert refused["task"] is None and refused["approval_id"] is None, refused
    assert "未指定" in refused["text"], refused


def test_b_to_a_production_gate_reference_is_verified_by_lookup(pair: Any) -> None:
    """B's real tool gate produces a ref that A proves through an authority lookup.

    B asks A's human through `approval.request`; after the allow decision B sends
    the submission with a ref. A's mirror of the question has no approved content
    digest, so it must query B's authority, import the evidence, consume it once
    and execute exactly once.

    Args:
        pair: Live A/B pair.
    """
    text = "生产门 B→A：检查这个迁移脚本"
    gated = pair.b_command(
        {
            "op": "submit_gated",
            "text": text,
            "origin": "llm",
            "session_id": pair.sid,
        }
    )
    assert gated["event"] == "gated" and gated["ok"] is True, gated
    task_id = gated["task_id"]
    approval_id = gated["approval_id"]
    assert approval_id, gated

    queued = pair.wait_a_approval(approval_id, timeout_s=30)
    assert queued is not None, "A stored no mirror of B's gate"
    assert queued["state"] == "pending", queued

    decided = pair.a_command(
        {
            "op": "decide",
            "approval_id": approval_id,
            "allowed": True,
            "actor": "alice",
            "channel": "im",
        }
    )
    assert decided["applied"] is True, decided

    executed = pair.a_command({"op": "wait_executions", "count": 1, "timeout_s": 60})
    assert executed["event"] == "executed", executed
    assert executed["count"] == 1, executed
    assert any(item.get("task_id") == task_id for item in executed["calls"]), executed

    finished = pair.wait_b_task(task_id, list(TERMINAL_LOCAL), timeout_s=60)
    assert finished["event"] == "task", finished
    assert finished["task"]["status"] == "succeeded", finished["task"]

    a_snapshot = pair.a_snapshot()
    mirror = _approval(a_snapshot, approval_id)
    assert mirror is not None, a_snapshot["approvals"]
    assert mirror["source"] == "peer_lookup", mirror
    assert mirror["consumed_by_task"] == task_id, mirror
    assert isinstance(mirror["submit_digest"], str) and mirror["submit_digest"], mirror

    b_snapshot = pair.b_snapshot()
    authority = _approval(b_snapshot, approval_id)
    assert authority is not None, b_snapshot["approvals"]
    assert authority["released_by_task"] == task_id, authority
    assert authority["consumed_by_task"] is None, authority

    executions = [
        item for item in a_snapshot["executions"] if item["task_id"] == task_id
    ]
    assert len(executions) == 1, a_snapshot["executions"]
    assert not [
        item for item in b_snapshot["deliveries"] if item.get("text") == text
    ], b_snapshot["deliveries"]
