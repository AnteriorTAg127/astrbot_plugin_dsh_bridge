"""Wire tests for the outbound ``event.ack`` request (§11.1).

An inbound ``task.event`` carries the *peer's* ``notify_id``. Acknowledging it must
therefore be a real ``req`` sent to the peer, never a lookup in our own outbox:
``NotifyService.on_ack`` consumes acks coming *from* the peer and would answer
``event_not_found`` here. These tests pin that direction split, the ``req`` envelope,
the duplicate-reack behaviour and the rule that a failed ack must not roll the task
state back.
"""

from __future__ import annotations

import asyncio
import importlib
import sys
from pathlib import Path

import pytest
from bridge.app.notify import (
    NotifyService,
    build_ack_params,
    inbound_ack_message,
)
from bridge.app.sessions import SessionService
from bridge.app.tasks import TaskService
from bridge.constants import STATUS_ACCEPTED, STATUS_SUCCEEDED
from bridge.errors import ERR_NOT_READY, BridgeError
from bridge.store import Store

CONN = "default"

PLUGIN_ROOT = Path(__file__).resolve().parent.parent


def _plugin_module():
    """Import the composition root the way AstrBot does.

    Returns:
        The ``astrbot_plugin_dsh_bridge.main`` module object.
    """
    package = PLUGIN_ROOT.name
    if package not in sys.path and PLUGIN_ROOT.parent.exists():
        sys.path.insert(0, str(PLUGIN_ROOT.parent))
    if str(PLUGIN_ROOT) not in sys.path:
        sys.path.insert(0, str(PLUGIN_ROOT))
    return importlib.import_module(f"{package}.main")


class AckRecorder:
    """Record outbound ``event.ack`` params and optionally fail."""

    def __init__(self, *, fail: Exception | None = None) -> None:
        """Create the recorder.

        Args:
            fail: Exception raised instead of returning a reply.
        """
        self.calls: list[dict] = []
        self.fail = fail

    async def __call__(self, params: dict) -> dict:
        """Record one ack request.

        Args:
            params: ``event.ack`` parameters.

        Returns:
            A minimal ``rep.result``.

        Raises:
            Exception: ``fail`` when configured.
        """
        self.calls.append(params)
        if self.fail is not None:
            raise self.fail
        return {"notify_id": params["notify_id"], "ok": True}


async def build_tasks(tmp_path, *, ack_fail: Exception | None = None):
    """Wire a real store, notify service and task service.

    Args:
        tmp_path: pytest temporary directory.
        ack_fail: Optional exception raised by the ack transport.

    Returns:
        ``(store, ack_recorder, state_events, tasks)``.
    """
    store = Store()
    await store.init(tmp_path / "bridge.db")
    ack = AckRecorder(fail=ack_fail)
    notify = NotifyService(store, conn=CONN, on_ack_request=ack)
    sessions = SessionService(store, conn=CONN)
    await sessions.init()
    state_events: list[str] = []

    async def on_state_change(task: dict, event: str) -> None:
        state_events.append(event)

    tasks = TaskService(
        store,
        conn=CONN,
        notify=notify,
        sessions=sessions,
        on_state_change=on_state_change,
    )
    return store, ack, state_events, tasks


async def seed_task(store: Store, task_id: str) -> None:
    """Insert an accepted outbound task.

    Args:
        store: Store to write.
        task_id: Task identifier.
    """
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


def event_params(task_id: str, notify_id: str = "n-peer") -> dict:
    """Build a peer ``task.event`` for a completed task.

    Args:
        task_id: Owning task.
        notify_id: Peer notification id.

    Returns:
        Full ``task.event`` parameter dictionary.
    """
    return {
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


def test_ack_is_a_req_envelope() -> None:
    """``event.ack`` is always wrapped as ``req``, never as ``evt``."""
    params = build_ack_params("n-peer", "t-1", "t-1", "processed")
    message = inbound_ack_message(params)
    assert message["k"] == "req"
    assert message["m"] == "event.ack"
    assert message["params"] == params
    assert params == {
        "notify_id": "n-peer",
        "task_id": "t-1",
        "root_task_id": "t-1",
        "outcome": "processed",
    }


@pytest.mark.asyncio
async def test_send_ack_uses_the_peer_sender_not_the_local_outbox(tmp_path) -> None:
    """A peer ``notify_id`` is unknown locally and must still be ackable."""
    store = Store()
    await store.init(tmp_path / "bridge.db")
    try:
        ack = AckRecorder()
        notify = NotifyService(store, conn=CONN, on_ack_request=ack)
        params = build_ack_params("peer-only", "t-1", "t-1", "processed")
        # ``on_ack`` would raise ``event_not_found``: no such local outbox row.
        assert await notify.send_ack(params) == {"notify_id": "peer-only", "ok": True}
        assert ack.calls == [params]
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_send_ack_without_sender_raises(tmp_path) -> None:
    """An unwired ack sender is a loud error, not a silent drop."""
    store = Store()
    await store.init(tmp_path / "bridge.db")
    try:
        notify = NotifyService(store, conn=CONN)
        with pytest.raises(RuntimeError):
            await notify.send_ack(build_ack_params("n-peer", "t-1", "t-1"))
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_processed_event_acks_over_the_peer_request(tmp_path) -> None:
    """A processed event is acked once and never marked delivered locally."""
    store, ack, _state_events, tasks = await build_tasks(tmp_path)
    try:
        task_id = "44444444-4444-4444-8444-444444444441"
        await seed_task(store, task_id)
        await tasks.on_event(event_params(task_id, "n-peer-1"))

        assert ack.calls == [
            build_ack_params("n-peer-1", task_id, task_id, "processed")
        ]
        stored = await store.get_task(task_id)
        assert stored is not None and stored["status"] == STATUS_SUCCEEDED
        # The peer's notify_id is not ours: nothing was invented in the local outbox.
        assert await store.get_notify("n-peer-1") is None
    finally:
        await tasks.stop()
        await store.close()


@pytest.mark.asyncio
async def test_duplicate_event_acknowledges_again_without_reprocessing(
    tmp_path,
) -> None:
    """A duplicate is acked as ``duplicate`` and changes neither state nor wake."""
    store, ack, state_events, tasks = await build_tasks(tmp_path)
    try:
        task_id = "44444444-4444-4444-8444-444444444442"
        await seed_task(store, task_id)
        params = event_params(task_id, "n-peer-2")
        await tasks.on_event(params)
        await tasks.on_event(dict(params))

        assert [call["outcome"] for call in ack.calls] == ["processed", "duplicate"]
        stored = await store.get_task(task_id)
        assert stored is not None and stored["eseq"] == 1
        assert state_events == ["completed"]
    finally:
        await tasks.stop()
        await store.close()


@pytest.mark.asyncio
async def test_unknown_task_is_acked_as_rejected(tmp_path) -> None:
    """An event for an unknown task is rejected on the wire, not ignored."""
    store, ack, _state_events, tasks = await build_tasks(tmp_path)
    try:
        await tasks.on_event(event_params("missing-task", "n-peer-3"))
        assert ack.calls == [
            build_ack_params("n-peer-3", "missing-task", "missing-task", "rejected")
        ]
    finally:
        await tasks.stop()
        await store.close()


@pytest.mark.asyncio
async def test_ack_failure_does_not_roll_the_task_state_back(tmp_path) -> None:
    """The persisted event survives an undeliverable ack; the peer resend retries."""
    store, ack, _state_events, tasks = await build_tasks(
        tmp_path, ack_fail=BridgeError(ERR_NOT_READY)
    )
    try:
        task_id = "44444444-4444-4444-8444-444444444443"
        await seed_task(store, task_id)
        await tasks.on_event(event_params(task_id, "n-peer-4"))

        assert len(ack.calls) == 1
        stored = await store.get_task(task_id)
        assert stored is not None and stored["status"] == STATUS_SUCCEEDED
        assert stored["eseq"] == 1
    finally:
        await tasks.stop()
        await store.close()


@pytest.mark.asyncio
async def test_main_sends_the_ack_as_a_session_request() -> None:
    """``main._send_ack_request`` queues ``session.call("event.ack", params)``."""
    main_module = _plugin_module()
    params = build_ack_params("n-peer-5", "t-1", "t-1", "processed")

    class ReadySession:
        """A ready session whose ``call`` waits for the test to settle its future."""

        state = main_module.SessionState.READY

        def __init__(self) -> None:
            self.calls: list[tuple[str, dict]] = []
            self.reply: asyncio.Future = asyncio.get_running_loop().create_future()

        async def call(self, message: str, params: dict, timeout_s=None) -> dict:
            """Record one request/reply and block until the test resolves it."""
            self.calls.append((message, params))
            return await self.reply

        async def send_message(self, message: dict) -> None:
            """Fail: an ack must be a request, never a one-way ``evt``."""
            raise AssertionError("event.ack must use Session.call")

    plugin = main_module.DshBridgePlugin.__new__(main_module.DshBridgePlugin)
    # ``__init__`` is bypassed: install the owned-ack set that the done callback
    # discards from and ``terminate`` reaps, or the task cannot be tracked.
    plugin._ack_tasks = set()
    session = ReadySession()
    plugin._session = session

    reply = await asyncio.wait_for(plugin._send_ack_request(params), timeout=1.0)

    # Queued, not delivered: the peer has not answered the request yet.
    assert reply == {"notify_id": "n-peer-5", "queued": True}
    # The call is scheduled, not executed inline: the caller never blocks on it.
    assert session.calls == []
    await asyncio.sleep(0)
    assert session.calls == [("event.ack", params)]
    assert len(plugin._ack_tasks) == 1
    pending = plugin._ack_tasks.copy().pop()
    assert not pending.done()

    # The peer's reply resolves the future; the owned task is then reaped.
    session.reply.set_result({"notify_id": "n-peer-5", "ok": True})
    await asyncio.wait_for(asyncio.gather(pending), timeout=1.0)
    await asyncio.sleep(0)
    assert plugin._ack_tasks == set()


@pytest.mark.asyncio
async def test_main_refuses_the_ack_without_a_ready_session() -> None:
    """No ready session raises, so the peer's resent event triggers a fresh ack."""
    main_module = _plugin_module()
    plugin = main_module.DshBridgePlugin.__new__(main_module.DshBridgePlugin)

    plugin._session = None
    with pytest.raises(RuntimeError):
        await plugin._send_ack_request(build_ack_params("n-peer-6", "t", "t"))

    class NotReadySession:
        """A session that still exists but lost ``ready``."""

        state = main_module.SessionState.HANDSHAKING

        async def call(self, message: str, params: dict, timeout_s=None) -> dict:
            """Fail the test if a request is attempted while not ready."""
            raise AssertionError("must not call while not ready")

    plugin._session = NotReadySession()
    with pytest.raises(RuntimeError):
        await plugin._send_ack_request(build_ack_params("n-peer-6", "t", "t"))
