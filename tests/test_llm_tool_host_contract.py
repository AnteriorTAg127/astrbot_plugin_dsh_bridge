"""LLM tool adapters against the real AstrBot tool contract (v0.1 hotfix).

These tests use the host's real ``Context.add_llm_tools``, ``FunctionToolManager``
(including ``get_full_tool_set``'s ``_PermissionGuardedTool`` wrapper) and
``FunctionToolExecutor.execute``. Only the plugin's business methods are doubles:
the tool layer must forward the event, arguments and explicit session unchanged,
and must never bypass the permission/approval path.

The lifecycle cases pin what the host actually does around plugin disable/enable and
unload: disable keeps the tool rows (marked inactive), a new plugin instance replaces
them without stale ownership, unload removes them by module path, and a partially
failed ``initialize`` releases the resources it opened before re-raising.
"""

from __future__ import annotations

import asyncio
import functools
import importlib
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from astrbot.core.agent.run_context import ContextWrapper
from astrbot.core.agent.tool import FunctionTool
from astrbot.core.astr_agent_tool_exec import FunctionToolExecutor
from astrbot.core.provider import func_tool_manager as host_func_tools
from astrbot.core.provider.func_tool_manager import FunctionToolManager
from astrbot.core.star.context import Context as HostContext
from astrbot.core.star.star import StarMetadata
from astrbot.core.star.star_handler import StarHandlerRegistry

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
_PACKAGE = PLUGIN_ROOT.name
if str(PLUGIN_ROOT.parent) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT.parent))

main = importlib.import_module(f"{_PACKAGE}.main")

PLUGIN_NAME = "astrbot_plugin_dsh_bridge"
MODULE_PATH = f"data.plugins.{PLUGIN_NAME}.main"
TOOL_NAMES = {
    "dsh_submit_task",
    "dsh_task_status",
    "dsh_list_sessions",
    "dsh_create_session",
    "dsh_select_session",
}


class ToolHost:
    """Minimal host whose ``add_llm_tools`` is the real AstrBot implementation."""

    #: Real method: resolves tool ownership from the live star registry and appends
    #: to / replaces rows in the real ``FunctionToolManager``.
    add_llm_tools = HostContext.add_llm_tools

    def __init__(self) -> None:
        """Create a host exposing a real tool manager."""
        self.provider_manager = SimpleNamespace(llm_tools=FunctionToolManager())
        self._config: dict = {}

    def get_config(self) -> dict:
        """Return the host configuration used by the plugin.

        Returns:
            An empty configuration mapping.
        """
        return self._config


class Event:
    """AstrMessageEvent double carrying identity used by permission checks."""

    unified_msg_origin = "test:FriendMessage:session-1"

    def __init__(self, *, admin: bool = False) -> None:
        """Create the event.

        Args:
            admin: Whether the sender is an administrator.
        """
        self.role = "admin" if admin else "member"
        self._admin = admin

    def is_admin(self) -> bool:
        """Return the configured administrator verdict.

        Returns:
            ``True`` for an administrator.
        """
        return self._admin

    def get_sender_id(self) -> str:
        """Return a stable sender id.

        Returns:
            The sender id used in permission-denied messages.
        """
        return "member-1"


@pytest.fixture
def host(monkeypatch):
    """Provide a real tool manager and register this plugin like the host does.

    Args:
        monkeypatch: pytest monkeypatch fixture.

    Returns:
        The host double backed by the real tool manager.
    """
    metadata = StarMetadata(
        name=PLUGIN_NAME,
        root_dir_name=PLUGIN_NAME,
        module_path=MODULE_PATH,
    )
    monkeypatch.setattr(
        importlib.import_module("astrbot.core.star.context"),
        "star_registry",
        [metadata],
    )

    async def fake_global_get(key, default=None):
        if key == "tool_permissions":
            return {}
        return default

    monkeypatch.setattr(host_func_tools.sp, "global_get", fake_global_get)
    return ToolHost()


def make_plugin(host: ToolHost) -> main.DshBridgePlugin:
    """Build a plugin bound to the host double without running ``initialize``.

    Args:
        host: Host double with the real tool manager.

    Returns:
        The plugin instance.
    """
    return main.DshBridgePlugin(host, {"dashboard_enabled": False})


def run_context(event: Event) -> ContextWrapper:
    """Build the host run context used by ``FunctionToolExecutor``.

    Args:
        event: Message event double.

    Returns:
        A run context carrying the event.
    """
    return ContextWrapper(context=SimpleNamespace(event=event))


async def collect_tool_result(tool, context, **arguments) -> str:
    """Execute one tool through the real executor and return its text.

    Args:
        tool: Function tool (usually the permission-guarded wrapper).
        context: Host run context.
        **arguments: Tool arguments.

    Returns:
        The text payload yielded by the executor.
    """
    results = [
        result
        async for result in FunctionToolExecutor.execute(tool, context, **arguments)
    ]
    assert len(results) == 1
    return results[0].content[0].text


def guarded_tool(host: ToolHost, name: str) -> FunctionTool:
    """Return the host-wrapped tool with ``name``.

    Args:
        host: Host double holding the real manager.
        name: Registered tool name.

    Returns:
        The ``_PermissionGuardedTool`` wrapper returned by the host.
    """
    manager = host.provider_manager.llm_tools
    tool = manager.get_full_tool_set().get_tool(name)
    assert tool is not None
    return tool


TOOL_CASES = [
    (
        "dsh_submit_task",
        "llm_submit_task",
        {"prompt": "do", "purpose": "why", "session_id": "sess-1"},
        ("do", "why"),
        {"session_id": "sess-1"},
    ),
    (
        "dsh_task_status",
        "llm_task_status",
        {"task_id": "task-1"},
        ("task-1",),
        {},
    ),
    (
        "dsh_list_sessions",
        "llm_list_sessions",
        {"purpose": "code-review"},
        ("code-review",),
        {},
    ),
    (
        "dsh_create_session",
        "llm_create_session",
        {"purpose": "code-review", "title": "Review"},
        ("code-review", "Review"),
        {},
    ),
    (
        "dsh_select_session",
        "llm_select_session",
        {"task_id": "task-1", "session_id": "sess-1"},
        ("task-1", "sess-1"),
        {},
    ),
]


def test_registered_tools_are_concrete_function_tools(host) -> None:
    """All five adapters are real, owned, active ``FunctionTool`` rows."""
    plugin = make_plugin(host)
    plugin._register_llm_tools()

    manager = host.provider_manager.llm_tools
    assert {tool.name for tool in manager.func_list} == TOOL_NAMES
    assert len(manager.func_list) == 5
    for tool in manager.func_list:
        assert isinstance(tool, FunctionTool)
        assert tool.handler is not None
        assert callable(tool.handler)
        assert tool.active is True
        # Set by the real ``Context.add_llm_tools`` from the host star registry.
        assert tool.handler_module_path == MODULE_PATH


@pytest.mark.parametrize(
    ("tool_name", "method_name", "arguments", "expected_args", "expected_kwargs"),
    TOOL_CASES,
)
async def test_every_tool_runs_through_the_real_host_wrapper(
    host, tool_name, method_name, arguments, expected_args, expected_kwargs
) -> None:
    """Each tool executes via the real wrapper/executor and forwards args verbatim."""
    plugin = make_plugin(host)
    plugin._register_llm_tools()
    event = Event()
    business = AsyncMock(return_value=f"ok:{tool_name}")
    setattr(plugin, method_name, business)

    text = await collect_tool_result(
        guarded_tool(host, tool_name), run_context(event), **arguments
    )

    assert text == f"ok:{tool_name}"
    business.assert_awaited_once_with(event, *expected_args, **expected_kwargs)


async def test_permission_denial_stops_before_the_business_method(
    host, monkeypatch
) -> None:
    """The real permission guard runs before the tool handler and never bypasses it."""
    plugin = make_plugin(host)
    plugin._register_llm_tools()
    business = AsyncMock(return_value="should-not-run")
    plugin.llm_task_status = business

    async def admin_only_global_get(key, default=None):
        if key == "tool_permissions":
            return {"_default": {"dsh_task_status": "admin"}}
        return default

    monkeypatch.setattr(host_func_tools.sp, "global_get", admin_only_global_get)

    text = await collect_tool_result(
        guarded_tool(host, "dsh_task_status"),
        run_context(Event(admin=False)),
        task_id="task-1",
    )

    assert "Permission denied" in text
    business.assert_not_awaited()


async def test_duplicate_registration_keeps_one_row_per_tool(host) -> None:
    """Re-registering (host reload) replaces rows by name instead of appending."""
    plugin = make_plugin(host)
    plugin._register_llm_tools()
    manager = host.provider_manager.llm_tools
    first_rows = list(manager.func_list)

    # Same instance short-circuits its own guard, and a fresh instance re-registers
    # exactly the way the host does after a reload.
    plugin._register_llm_tools()
    assert list(manager.func_list) == first_rows

    second = make_plugin(host)
    second._register_llm_tools()
    assert len(manager.func_list) == 5
    assert {tool.name for tool in manager.func_list} == TOOL_NAMES
    assert all(tool.active for tool in manager.func_list)


async def test_disable_keeps_rows_and_new_instance_rebinds_without_misattribution(
    host,
) -> None:
    """Disable preserves rows; the next instance replaces them with its own handlers."""
    first = make_plugin(host)
    first._register_llm_tools()
    manager = host.provider_manager.llm_tools
    first_rows = {tool.name: tool for tool in manager.func_list}
    first_submit = AsyncMock(return_value="first")
    first.llm_submit_task = first_submit

    # ``PluginManager.turn_off_plugin`` keeps the rows and only flips ``active``.
    for tool in manager.func_list:
        assert tool.handler is not None
        tool.active = False
    assert len(manager.func_list) == 5
    assert all(tool.active is False for tool in manager.func_list)

    # ``turn_on_plugin`` loads a fresh instance. The host's load loop first rebinds
    # every existing row to that instance with ``functools.partial``; reproduce that
    # exact step, then registration must replace the stale rows (not keep the partial).
    second = make_plugin(host)
    for tool in manager.func_list:
        tool.handler = functools.partial(tool.handler, second)
    second._register_llm_tools()
    second_submit = AsyncMock(return_value="second")
    second.llm_submit_task = second_submit

    assert len(manager.func_list) == 5
    for tool in manager.func_list:
        assert tool.active is True
        assert tool.handler is not None
        assert not isinstance(tool.handler, functools.partial)
        assert tool.handler_module_path == MODULE_PATH
        assert tool is not first_rows[tool.name]

    text = await collect_tool_result(
        guarded_tool(host, "dsh_submit_task"),
        run_context(Event()),
        prompt="do",
        session_id="sess-1",
    )
    assert text == "second"
    assert second_submit.await_count == 1
    assert first_submit.await_count == 0
    event = second_submit.await_args.args[0]
    assert isinstance(event, Event)
    second_submit.assert_awaited_once_with(event, "do", "", session_id="sess-1")


async def test_unbind_removes_only_this_plugins_tool_paths(host, monkeypatch) -> None:
    """The real ``_unbind_plugin`` removes rows owned by this module only."""
    plugin = make_plugin(host)
    plugin._register_llm_tools()
    manager = host.provider_manager.llm_tools

    decoy = FunctionTool(
        name="other_tool",
        description="another plugin's tool",
        parameters={"type": "object", "properties": {}},
        handler_module_path="data.plugins.other_plugin.main",
    )
    manager.func_list.append(decoy)

    star_manager = importlib.import_module("astrbot.core.star.star_manager")
    metadata = StarMetadata(
        name=PLUGIN_NAME,
        root_dir_name=PLUGIN_NAME,
        module_path=MODULE_PATH,
        reserved=False,
    )
    monkeypatch.setattr(star_manager, "llm_tools", manager)
    monkeypatch.setattr(star_manager, "star_map", {MODULE_PATH: metadata})
    monkeypatch.setattr(star_manager, "star_registry", [metadata])
    monkeypatch.setattr(star_manager, "star_handlers_registry", StarHandlerRegistry())
    monkeypatch.setattr(
        star_manager, "unregister_platform_adapters_by_module", lambda _prefix: []
    )
    fake_manager = SimpleNamespace(_purge_modules=lambda **_kwargs: None)

    await star_manager.PluginManager._unbind_plugin(
        fake_manager, PLUGIN_NAME, MODULE_PATH
    )

    assert [tool.name for tool in manager.func_list] == ["other_tool"]


async def test_terminate_is_idempotent_and_resets_tool_registration(
    host, tmp_path, monkeypatch
) -> None:
    """Two terminates are safe and the flag is reset for a later initialize."""
    monkeypatch.setattr(main, "get_astrbot_plugin_data_path", lambda: str(tmp_path))
    plugin = make_plugin(host)
    await plugin.initialize()
    try:
        assert plugin._llm_tools_registered is True
        assert len(host.provider_manager.llm_tools.func_list) == 5

        await plugin.terminate()
        assert plugin._store is None
        assert plugin._llm_tools_registered is False

        await plugin.terminate()
        assert plugin._store is None
        assert plugin._llm_tools_registered is False
    finally:
        await plugin.terminate()


async def test_same_instance_reinitializes_after_terminate(
    host, tmp_path, monkeypatch
) -> None:
    """A terminated instance can initialize again and re-register its tools."""
    monkeypatch.setattr(main, "get_astrbot_plugin_data_path", lambda: str(tmp_path))
    plugin = make_plugin(host)
    await plugin.initialize()
    await plugin.terminate()

    await plugin.initialize()
    try:
        assert plugin._store is not None
        assert plugin._store.path is not None
        assert plugin._llm_tools_registered is True
        assert {tool.name for tool in host.provider_manager.llm_tools.func_list} == (
            TOOL_NAMES
        )
    finally:
        await plugin.terminate()


async def test_partial_initialize_failure_closes_resources_and_can_retry(
    host, tmp_path, monkeypatch
) -> None:
    """A failure after ``Store.init`` closes the store and leaves the data dir reusable."""
    monkeypatch.setattr(main, "get_astrbot_plugin_data_path", lambda: str(tmp_path))
    instances: list[main.Store] = []

    class RecordingStore(main.Store):
        def __init__(self) -> None:
            super().__init__()
            instances.append(self)

    original_cleanup = main.Store.cleanup_expired
    calls = 0

    async def flaky_cleanup(self, retention):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("cleanup failed after the store opened")
        return await original_cleanup(self, retention)

    monkeypatch.setattr(main, "Store", RecordingStore)
    monkeypatch.setattr(RecordingStore, "cleanup_expired", flaky_cleanup)

    first = make_plugin(host)
    with pytest.raises(RuntimeError, match="cleanup failed"):
        await first.initialize()

    assert first._store is None
    assert first._llm_tools_registered is False
    assert len(instances) == 1
    assert instances[0]._db is None
    assert instances[0].path is not None

    second = make_plugin(host)
    await second.initialize()
    try:
        assert second._store is not None
        assert second._store.path is not None
    finally:
        await second.terminate()


async def test_initialize_cancellation_propagates_after_cleanup(
    host, tmp_path, monkeypatch
) -> None:
    """``CancelledError`` is re-raised, not swallowed, and resources are still closed."""
    monkeypatch.setattr(main, "get_astrbot_plugin_data_path", lambda: str(tmp_path))
    instances: list[main.Store] = []

    class RecordingStore(main.Store):
        def __init__(self) -> None:
            super().__init__()
            instances.append(self)

    async def cancelled_cleanup(self, retention):
        del retention
        raise asyncio.CancelledError

    monkeypatch.setattr(main, "Store", RecordingStore)
    monkeypatch.setattr(RecordingStore, "cleanup_expired", cancelled_cleanup)

    plugin = make_plugin(host)
    with pytest.raises(asyncio.CancelledError):
        await plugin.initialize()

    assert plugin._store is None
    assert instances[0]._db is None


async def test_cleanup_failure_does_not_mask_the_initialize_error(
    host, tmp_path, monkeypatch
) -> None:
    """A failing terminate during cleanup must not replace the original exception."""
    monkeypatch.setattr(main, "get_astrbot_plugin_data_path", lambda: str(tmp_path))

    async def broken_cleanup(self, retention):
        del self, retention
        raise ValueError("original initialize failure")

    monkeypatch.setattr(main.Store, "cleanup_expired", broken_cleanup)
    plugin = make_plugin(host)
    failing_terminate = AsyncMock(side_effect=RuntimeError("cleanup blew up"))
    monkeypatch.setattr(plugin, "terminate", failing_terminate)

    with pytest.raises(ValueError, match="original initialize failure"):
        await plugin.initialize()

    failing_terminate.assert_awaited_once()
    if plugin._store is not None:
        await plugin._store.close()
