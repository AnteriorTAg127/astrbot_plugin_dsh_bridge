"""Notification tests: at-least-once delivery, ack, retry, wake guards (§10.3, §11, §16.6)."""

from __future__ import annotations

import pytest

from bridge.app.notify import (
    NotifyService,
    build_ack_params,
    build_event_params,
    inbound_ack_message,
    inbound_event_message,
)
from bridge.constants import EVENT_COMPLETED, EVENT_NEEDS_DECISION, STATUS_SUCCEEDED
from bridge.errors import BridgeError

CONN = "default"


def make_task(task_id: str = "t-1", root: str = "t-1", **overrides) -> dict:
    """Build a minimal task row for notification tests.

    Args:
        task_id: Task identifier.
        root: Root task identifier.
        **overrides: Field overrides.

    Returns:
        Task dictionary.
    """
    task = {
        "task_id": task_id,
        "root_task_id": root,
        "eseq": 0,
        "status": "running",
        "direction": "inbound",
        "kind": "astr_agent_run",
        "origin": "human",
    }
    task.update(overrides)
    return task


@pytest.mark.asyncio
async def test_emit_persists_then_sends(store, sender) -> None:
    """``emit`` writes the outbox row before delivering it (§10.3)."""
    notify = NotifyService(store, conn=CONN, on_task_event=sender)
    task = make_task()
    notify_id = await notify.emit(task, EVENT_COMPLETED, STATUS_SUCCEEDED, result={"summary": "ok"})
    row = await store.get_notify(notify_id)
    assert row is not None
    assert row["message"] == "task.event"
    assert row["params"]["notify_id"] == notify_id
    assert row["params"]["eseq"] == 1
    assert len(sender.events) == 1
    assert sender.events[0]["event"] == EVENT_COMPLETED


@pytest.mark.asyncio
async def test_ack_marks_delivered(store, sender) -> None:
    """A peer ack marks the notification delivered (§11.1)."""
    notify = NotifyService(store, conn=CONN, on_task_event=sender)
    notify_id = await notify.emit(make_task(), EVENT_COMPLETED, STATUS_SUCCEEDED)
    result = await notify.on_ack(
        build_ack_params(notify_id, "t-1", "t-1", "processed")
    )
    assert result == {"notify_id": notify_id, "delivered": True}
    row = await store.get_notify(notify_id)
    assert row is not None and row["delivered"] is True


@pytest.mark.asyncio
async def test_ack_unknown_notify_raises(store, sender) -> None:
    """An unknown notify id reports ``event_not_found`` (§11.1)."""
    notify = NotifyService(store, conn=CONN, on_task_event=sender)
    with pytest.raises(BridgeError) as excinfo:
        await notify.on_ack(build_ack_params("missing", "t", "t"))
    assert excinfo.value.code == "event_not_found"


@pytest.mark.asyncio
async def test_failed_send_is_retried_with_backoff(store, sender) -> None:
    """A failed send increments attempts and schedules a retry (§11.3)."""
    notify = NotifyService(store, conn=CONN, on_task_event=sender)
    sender.fail_next = True
    notify_id = await notify.emit(make_task(), EVENT_COMPLETED, STATUS_SUCCEEDED)
    row = await store.get_notify(notify_id)
    assert row is not None
    assert row["delivered"] is False
    assert row["attempts"] == 1
    assert row["next_at"] > 0
    assert sender.events == []


@pytest.mark.asyncio
async def test_exhausted_retries_mark_undelivered_and_needs_human(store, sender) -> None:
    """After five attempts the notification is undelivered and the task is human-bound."""
    notify = NotifyService(store, conn=CONN, on_task_event=sender)
    task = make_task()
    await store.upsert_task(
        {
            "task_id": task["task_id"],
            "root_task_id": task["root_task_id"],
            "direction": "inbound",
            "kind": "astr_agent_run",
            "origin": "human",
            "status": "running",
        }
    )
    notify_id = await notify.emit(task, EVENT_COMPLETED, STATUS_SUCCEEDED)
    for attempt in range(5):
        await notify._schedule_retry(notify_id, attempt)
    row = await store.get_notify(notify_id)
    assert row is not None
    assert row["undelivered"] is True
    stored = await store.get_task("t-1")
    assert stored is not None
    assert stored["status"] == "needs_human"


@pytest.mark.asyncio
async def test_wake_chain_limit_trips(store, sender) -> None:
    """The ninth automatic wake for one root task is refused (§16.6)."""
    notify = NotifyService(store, conn=CONN, wake_max_chain=8, on_task_event=sender)
    root = make_task()
    # Eight *distinct* wakes fill the chain; a repeated ``(task_id, event)`` would be
    # deduped and must never consume a slot.
    for index in range(8):
        task = make_task(task_id=f"t-{index + 1}", root=root["root_task_id"])
        assert await notify.guard_wake(task, EVENT_COMPLETED, "session-1") is True
        await notify.record_wake(task, EVENT_COMPLETED)
    ninth = make_task(task_id="t-9", root=root["root_task_id"])
    with pytest.raises(BridgeError) as excinfo:
        await notify.guard_wake(ninth, EVENT_COMPLETED, "session-1")
    assert excinfo.value.code == "wake_chain_exceeded"


@pytest.mark.asyncio
async def test_wake_rate_limit_trips(store, sender) -> None:
    """Exceeding the per-window wake budget raises ``wake_rate_limited`` (§16.6)."""
    notify = NotifyService(store, conn=CONN, wake_rate_per_minute=2, on_task_event=sender)
    # The rate window key is ``conn:session_key``, so use one stable session key.
    task = make_task()
    for index in range(2):
        await notify.guard_wake(task, EVENT_NEEDS_DECISION, "session-1")
        await notify.record_wake(task, EVENT_NEEDS_DECISION)
        task = make_task(task_id=f"t-{index + 2}", root=task["root_task_id"])
    with pytest.raises(BridgeError) as excinfo:
        await notify.guard_wake(task, EVENT_NEEDS_DECISION, "session-1")
    assert excinfo.value.code == "wake_rate_limited"


@pytest.mark.asyncio
async def test_wake_is_deduped_per_task_and_event(store, sender) -> None:
    """Repeating the same ``(task_id, event)`` does not wake twice (§10.3)."""
    notify = NotifyService(store, conn=CONN, on_task_event=sender)
    task = make_task()
    assert await notify.guard_wake(task, EVENT_COMPLETED, "session-1") is True
    await notify.record_wake(task, EVENT_COMPLETED)
    # The duplicate reports "already delivered" and consumes no budget.
    assert await notify.guard_wake(task, EVENT_COMPLETED, "session-1") is False
    assert await store.wake_chain_count(task["root_task_id"]) == 1


@pytest.mark.asyncio
async def test_deduped_wake_survives_an_exhausted_chain(store, sender) -> None:
    """A duplicate never raises ``wake_chain_exceeded`` (§10.3 beats §16.6 budget)."""
    notify = NotifyService(store, conn=CONN, wake_max_chain=1, on_task_event=sender)
    task = make_task()
    assert await notify.guard_wake(task, EVENT_COMPLETED, "session-1") is True
    await notify.record_wake(task, EVENT_COMPLETED)
    assert await store.wake_chain_count(task["root_task_id"]) == 1
    # The chain is exhausted, but the same pair is a duplicate, not a new wake.
    assert await notify.guard_wake(task, EVENT_COMPLETED, "session-1") is False


@pytest.mark.asyncio
async def test_wake_guard_failure_becomes_needs_human(store, sender) -> None:
    """A guard failure converts the task to ``needs_human`` (§16.6)."""
    notify = NotifyService(store, conn=CONN, on_task_event=sender)
    task = make_task()
    await store.upsert_task(
        {
            "task_id": task["task_id"],
            "root_task_id": task["root_task_id"],
            "direction": "inbound",
            "kind": "astr_agent_run",
            "origin": "human",
            "status": "running",
        }
    )
    updated = await notify.handle_wake_guard_failure(task, "wake_chain_exceeded")
    assert updated is not None
    assert updated["status"] == "needs_human"
    assert updated["needs_human"] is True


@pytest.mark.asyncio
async def test_emit_event_supports_non_task_messages(store, sender) -> None:
    """``emit_event`` refuses messages without a sender, but records the row."""
    notify = NotifyService(store, conn=CONN, on_task_event=sender)
    await notify.emit_event("n-x", "approval.decision", {"approval_id": "a"}, "", "")
    row = await store.get_notify("n-x")
    assert row is not None
    assert row["message"] == "approval.decision"


def test_message_builders_match_protocol() -> None:
    """The helpers emit §9.1/§11 shaped objects."""
    task = make_task()
    params = build_event_params(task, EVENT_COMPLETED, STATUS_SUCCEEDED, "n-1", 3, result={"summary": "s"})
    assert set(params) == {
        "task_id",
        "root_task_id",
        "eseq",
        "event",
        "status",
        "notify_id",
        "result",
        "error",
        "decision",
        "approval",
    }
    message = inbound_event_message(params)
    assert message["k"] == "evt" and message["m"] == "task.event"

    ack = build_ack_params("n-1", "t-1", "t-1")
    assert ack["outcome"] == "processed"
    ack_message = inbound_ack_message(ack)
    assert ack_message["k"] == "req" and ack_message["m"] == "event.ack"
