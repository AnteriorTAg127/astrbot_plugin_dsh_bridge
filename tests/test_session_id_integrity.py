"""Session identifiers shown to agents/admins must be complete UUIDs.

The hotfix under test has two independent parts:

* ``dsh_list_sessions``/``/dsh sessions`` used to render ``session_id[:8]``.
  The same eight characters can belong to two different grants, and the value
  cannot be passed back to ``dsh_select_session`` (which requires the exact
  authorized id). Rendering must use the full UUID and must never resolve a
  prefix, auto-pick the first match, or widen authorization.
* ``session.select`` only validates and logs; it does not bind a task. The
  pending task and its approval gate were stored *before* a human answered, and
  ``submit_digest`` covers ``session_id``. Rewriting the task after the gate
  would therefore change already-approved content. These cases pin the honest
  surface (validate-only wording) and prove the approved content is unchanged.

The cases use the real ``Store``/``SessionService``/``TaskService``/
``ApprovalService`` and the real ``main.py`` tool adapters. No socket, host
runtime, credential or model is involved.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from bridge.app.approvals import ApprovalService, compute_submit_digest
from bridge.app.notify import NotifyService
from bridge.app.tasks import TaskService
from bridge.constants import STATUS_PENDING_APPROVAL

PLUGIN_ROOT = Path(__file__).resolve().parent.parent

#: Import the plugin the way AstrBot does while keeping the plain ``bridge``
#: package identical to the one the fixtures import (module identity matters).
_PACKAGE = PLUGIN_ROOT.name
if _PACKAGE not in sys.path and PLUGIN_ROOT.parent.exists():
    sys.path.insert(0, str(PLUGIN_ROOT.parent))
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))
for _name, _module in list(sys.modules.items()):
    if _name == "bridge" or _name.startswith("bridge."):
        sys.modules.setdefault(f"{_PACKAGE}.{_name}", _module)

main = importlib.import_module(f"{_PACKAGE}.main")

#: Two authorized UUIDs deliberately sharing the first eight characters. A
#: truncated list renders both as ``e28f9884`` and makes selection impossible.
SHARED_PREFIX = "e28f9884"
SESSION_A = "e28f9884-1111-4222-8333-444455556666"
SESSION_B = "e28f9884-9999-4aaa-8bbb-ccccddddeeee"

UMO = "platform:FriendMessage:session-1"


class Event:
    """AstrMessageEvent double carrying the identity the plugin reads."""

    unified_msg_origin = UMO

    def __init__(self, *, admin: bool = False) -> None:
        """Create the event.

        Args:
            admin: Whether the sender is an administrator.
        """
        self.role = "admin" if admin else "member"

    def get_sender_id(self) -> str:
        """Return a stable sender id.

        Returns:
            The sender id.
        """
        return "admin-1"

    def plain_result(self, text: str) -> str:
        """Build the object the command handler yields.

        Args:
            text: Response text.

        Returns:
            The response text itself.
        """
        return text


class Host:
    """Minimal plugin context: only ``get_config`` is read here."""

    def get_config(self) -> dict:
        """Return the host configuration.

        Returns:
            An empty configuration mapping.
        """
        return {}


def make_plugin(store, sessions, tasks=None):
    """Build the real plugin and inject the real services under test.

    Args:
        store: Real store fixture.
        sessions: Real ``SessionService`` fixture.
        tasks: Optional real ``TaskService``.

    Returns:
        The plugin instance.
    """
    plugin = main.DshBridgePlugin(Host(), {"dashboard_enabled": False})
    plugin._store = store
    plugin._sessions_svc = sessions
    plugin._tasks = tasks
    return plugin


async def make_services(store, sessions):
    """Build the real approval/task services used by the submission gate.

    Args:
        store: Real store fixture.
        sessions: Real ``SessionService`` fixture.

    Returns:
        ``(notify, approvals, tasks)``.
    """
    notify = NotifyService(store, conn="default")
    approvals = ApprovalService(
        store,
        conn="default",
        side="A",
        approval_timeout_s=1800,
        notify_channels=["web"],
        notify=notify,
    )
    tasks = TaskService(
        store,
        conn="default",
        notify=notify,
        sessions=sessions,
        approvals=approvals,
    )
    return notify, approvals, tasks


@pytest.mark.asyncio
async def test_llm_list_sessions_returns_full_ids_for_same_prefix_grants(
    store, sessions
) -> None:
    """The LLM-facing list distinguishes two grants that share an 8-char prefix."""
    await sessions.admin_grant(SESSION_A, purpose="plugin-test")
    await sessions.admin_grant(SESSION_B, purpose="plugin-test-2")
    plugin = make_plugin(store, sessions)

    text = await main.DshListSessionsTool(plugin)(Event())

    assert f"{SESSION_A} 用途=plugin-test" in text
    assert f"{SESSION_B} 用途=plugin-test-2" in text
    assert "完整 UUID" in text


@pytest.mark.asyncio
async def test_dsh_sessions_shows_full_ids_for_selection(store, sessions) -> None:
    """``/dsh sessions`` prints the exact UUID an admin must pass to select."""
    await sessions.admin_grant(SESSION_A, purpose="plugin-test")
    await sessions.admin_grant(SESSION_B, purpose="plugin-test-2")
    plugin = make_plugin(store, sessions)

    lines = [line async for line in plugin.dsh_sessions(Event(admin=True))]
    text = "\n".join(lines)

    assert SESSION_A in text
    assert SESSION_B in text
    assert "完整 UUID" in text


@pytest.mark.asyncio
async def test_select_requires_the_full_uuid_and_never_resolves_a_prefix(
    store, sessions
) -> None:
    """A unique 8-char prefix is still refused; the full UUID validates."""
    await sessions.admin_grant(SESSION_A, purpose="plugin-test")
    await sessions.admin_grant(SESSION_B, purpose="plugin-test-2")
    plugin = make_plugin(store, sessions)
    tool = main.DshSelectSessionTool(plugin)

    short = await tool(Event(), "task-1", SHARED_PREFIX)
    assert "校验会话失败：session_not_authorized" in short
    assert "完整 UUID" in short

    full = await tool(Event(), "task-1", SESSION_A)
    assert f"已校验会话 {SESSION_A}" in full
    assert "仅校验，不修改任务" in full
    assert "已将会话" not in full


@pytest.mark.asyncio
async def test_select_does_not_bind_or_rewrite_an_approved_pending_task(
    store, sessions
) -> None:
    """Selecting B leaves the A-bound pending task and its approved digest intact."""
    await sessions.admin_grant(SESSION_A, purpose="plugin-test")
    await sessions.admin_grant(SESSION_B, purpose="plugin-test-2")
    _notify, approvals, tasks = await make_services(store, sessions)
    held = await tasks.prepare_outbound_approval(
        input_parts=[{"type": "text", "text": "held work"}],
        purpose="plugin-test",
        session_id=SESSION_A,
    )
    task_id = held["task_id"]
    task_before = await store.get_task(task_id)
    approval_before = await store.get_approval(held["approval_id"])
    assert task_before is not None
    assert approval_before is not None
    assert task_before["status"] == STATUS_PENDING_APPROVAL
    assert task_before["payload"]["session_id"] == SESSION_A
    assert (
        compute_submit_digest(task_before["payload"])
        == approval_before["submit_digest"]
    )

    plugin = make_plugin(store, sessions, tasks)
    text = await main.DshSelectSessionTool(plugin)(Event(), task_id, SESSION_B)

    task_after = await store.get_task(task_id)
    approval_after = await store.get_approval(held["approval_id"])
    assert task_after is not None
    assert approval_after is not None
    assert f"已校验会话 {SESSION_B}" in text
    assert "仅校验，不修改任务" in text
    assert "已将会话" not in text
    # The task was stored before the human gate; its session and hash are unchanged.
    assert task_after["payload"]["session_id"] == SESSION_A
    assert task_after["session_id"] == SESSION_A
    assert task_after["request_hash"] == task_before["request_hash"]
    assert approval_after["session_id"] == SESSION_A
    assert approval_after["submit_digest"] == approval_before["submit_digest"]
    assert (
        compute_submit_digest(task_after["payload"]) == approval_after["submit_digest"]
    )
    # Why binding cannot be implemented here without a new human decision:
    # the digest under the gate is bound to the session it covered.
    altered = {**task_after["payload"], "session_id": SESSION_B}
    assert compute_submit_digest(altered) != approval_after["submit_digest"]


@pytest.mark.asyncio
async def test_submit_forwards_the_explicit_session_into_the_approval_gate(
    store, sessions
) -> None:
    """An explicit session reaches the gate verbatim; an absent one is refused."""
    await sessions.admin_grant(SESSION_A, purpose="plugin-test")
    _notify, _approvals, tasks = await make_services(store, sessions)
    plugin = make_plugin(store, sessions, tasks)
    plugin._session = SimpleNamespace(state=main.SessionState.READY)
    tool = main.DshSubmitTaskTool(plugin)

    text = await tool(Event(), "do the work", "purpose", session_id=SESSION_A)
    assert "task_id=" in text
    assert "审批号=" in text

    rows, _cursor = await store.list_tasks(limit=10)
    assert len(rows) == 1
    assert rows[0]["payload"]["session_id"] == SESSION_A
    assert rows[0]["session_id"] == SESSION_A
    pending = await store.list_approvals(state="pending", limit=10)
    assert len(pending) == 1
    assert pending[0]["session_id"] == SESSION_A
    assert compute_submit_digest(rows[0]["payload"]) == pending[0]["submit_digest"]

    refused = await tool(Event(), "do the work")
    assert "不会自动选择会话" in refused
    rows_after, _cursor = await store.list_tasks(limit=10)
    assert len(rows_after) == len(rows)


def test_select_tool_description_does_not_claim_binding() -> None:
    """The descriptions tell the model to use full UUIDs and never claim binding."""
    select_description = main.DshSelectSessionTool.description
    assert "does not bind" in select_description
    assert "full session UUID" in select_description
    assert "full UUID" in main.DshListSessionsTool.description
