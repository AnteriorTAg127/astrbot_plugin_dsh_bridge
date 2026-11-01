"""Wake boundary tests: archived sessions, duplicates and real budget accounting.

These tests drive the **real composition root** (``DshBridgePlugin.initialize``) with
the real ``Store``/``NotifyService``/``PlatformHost``. Only AstrBot's ``Context`` is a
minimal host double, so a wake either reaches it or it does not.

Pinned behaviours (§16.6, §9.7):

* An archived session is never woken: no IM, no wake-chain/rate budget, and the task
  keeps its terminal status (never ``needs_human`` because of the archive).
* A host without a platform returns before occupying budget.
* A duplicate ``(task_id, event)`` stays idempotent even after the chain is exhausted;
  the chain limit still stops a genuinely new wake.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest
from bridge.constants import (
    DIRECTION_INBOUND,
    GRANTED_BY_HUMAN,
    STATUS_RUNNING,
    STATUS_SUCCEEDED,
)

PLUGIN_ROOT = Path(__file__).resolve().parent.parent

#: Import the plugin the way AstrBot does while keeping the plain ``bridge`` package
#: identical to the one the other tests import (module identity matters).
_PACKAGE = PLUGIN_ROOT.name
if _PACKAGE not in sys.path and PLUGIN_ROOT.parent.exists():
    sys.path.insert(0, str(PLUGIN_ROOT.parent))
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))
for _name, _module in list(sys.modules.items()):
    if _name == "bridge" or _name.startswith("bridge."):
        sys.modules.setdefault(f"{_PACKAGE}.{_name}", _module)

main = importlib.import_module(f"{_PACKAGE}.main")

UMO = "platform:FriendMessage:session-1"


class StubPlatform:
    """Platform instance double exposing only ``meta().id``."""

    def __init__(self, platform_id: str) -> None:
        """Create the double.

        Args:
            platform_id: Value returned by ``meta().id``.
        """
        self._platform_id = platform_id

    def meta(self):
        """Return the metadata the real host matches against.

        Returns:
            An object carrying the platform instance id.
        """
        from types import SimpleNamespace

        return SimpleNamespace(id=self._platform_id)


class HostContext:
    """Minimal AstrBot ``Context`` double recording every active message."""

    def __init__(self) -> None:
        """Create an empty host with the UMO's platform registered."""
        self.sent_messages: list[tuple[str, object]] = []
        self.platforms: dict[str, StubPlatform] = {"platform": StubPlatform("platform")}

    def add_llm_tools(self, *tools) -> None:
        """Ignore LLM tool registration."""

    def register_web_api(self, route, handler, methods, desc) -> None:
        """Ignore Dashboard route registration."""

    def get_config(self) -> dict:
        """Return an empty host configuration."""
        return {}

    def get_platform_inst(self, platform_id: str):
        """Resolve a platform exactly like the real ``Context``.

        Args:
            platform_id: Platform instance id to look up.

        Returns:
            The matching platform double, or ``None``.
        """
        return self.platforms.get(platform_id)

    async def get_using_provider_async(self, umo=None):
        """Report "no chat provider" like an unconfigured host."""
        return None

    async def send_message(self, umo, chain) -> bool:
        """Capture one active message instead of touching a real platform."""
        self.sent_messages.append((umo, chain))
        return True


async def make_task(
    store,
    task_id: str = "t-1",
    *,
    session_id: str | None = "s-1",
    archived: bool = False,
    status: str = STATUS_SUCCEEDED,
    umo: str = UMO,
) -> dict:
    """Persist one task plus its session grant, optionally archived.

    Args:
        store: Real plugin store.
        task_id: Task identifier.
        session_id: Session to authorize, or ``None`` for a task without a session.
        archived: Whether the grant is archived before the wake attempt.
        status: Task status at wake time.
        umo: Local wake routing hint stored in the payload.

    Returns:
        The stored task row.
    """
    if session_id is not None:
        await store.grant_session(
            {
                "session_id": session_id,
                "purpose": "archived-wake-test",
                "granted_by": GRANTED_BY_HUMAN,
                "granted_by_id": "human:1",
            }
        )
        if archived:
            await store.archive_grant(session_id)
    await store.upsert_task(
        {
            "task_id": task_id,
            "root_task_id": task_id,
            "direction": DIRECTION_INBOUND,
            "kind": "astr_agent_run",
            "origin": "human",
            "status": status,
            "payload": {"umo": umo},
            "session_id": session_id,
        }
    )
    task = await store.get_task(task_id)
    assert task is not None
    return task


@pytest.fixture
async def plugin_factory(tmp_path, monkeypatch):
    """Build initialised real plugin instances with real bridge services.

    Args:
        tmp_path: pytest temporary directory.
        monkeypatch: pytest monkeypatch fixture.

    Yields:
        A coroutine function ``make(**config)`` returning an initialised plugin.
    """
    monkeypatch.setattr(main, "get_astrbot_plugin_data_path", lambda: str(tmp_path))
    created: list = []

    async def make(**overrides) -> object:
        """Initialise one plugin with ``overrides`` merged over test defaults."""
        config = {
            "dashboard_enabled": False,
            "wake_max_chain": 8,
            "wake_rate_per_minute": 10,
            **overrides,
        }
        plugin = main.DshBridgePlugin(HostContext(), config)
        await plugin.initialize()
        created.append(plugin)
        return plugin

    try:
        yield make
    finally:
        for plugin in created:
            await plugin.terminate()


@pytest.mark.asyncio
async def test_archived_session_is_not_woken(plugin_factory) -> None:
    """An archived session gets no IM, no budget and no status change (§9.7/§16.6)."""
    plugin = await plugin_factory()
    store = plugin._store
    task = await make_task(store, archived=True)

    await plugin._on_task_state_change(task, "completed")

    assert plugin.context.sent_messages == []
    assert await store.wake_chain_count(task["root_task_id"]) == 0
    # The archive is not a guard failure: the task must stay terminal, untouched.
    stored = await store.get_task(task["task_id"])
    assert stored is not None
    assert stored["status"] == STATUS_SUCCEEDED
    assert stored["needs_human"] is False
    assert await store.wake_already_delivered(task["task_id"], "completed") is False


@pytest.mark.asyncio
async def test_archived_wake_does_not_spend_the_rate_budget(plugin_factory) -> None:
    """Skipping an archived wake leaves the next real wake inside its budget."""
    plugin = await plugin_factory(wake_rate_per_minute=1)
    store = plugin._store
    archived = await make_task(store, "t-archived", session_id="s-old", archived=True)
    await plugin._on_task_state_change(archived, "completed")
    assert plugin.context.sent_messages == []

    live = await make_task(store, "t-live", session_id="s-live")
    await plugin._on_task_state_change(live, "completed")

    assert len(plugin.context.sent_messages) == 1
    assert await store.wake_chain_count(live["root_task_id"]) == 1
    stored = await store.get_task(live["task_id"])
    assert stored is not None and stored["status"] == STATUS_SUCCEEDED


@pytest.mark.asyncio
async def test_no_platform_returns_before_occupying_budget(plugin_factory) -> None:
    """A host without a platform never consumes chain/rate or escalates the task."""
    plugin = await plugin_factory()
    plugin._platform = None
    store = plugin._store
    task = await make_task(store)

    await plugin._on_task_state_change(task, "completed")

    assert await store.wake_chain_count(task["root_task_id"]) == 0
    stored = await store.get_task(task["task_id"])
    assert stored is not None
    assert stored["status"] == STATUS_SUCCEEDED
    assert stored["needs_human"] is False


@pytest.mark.asyncio
async def test_normal_wake_happens_exactly_once(plugin_factory) -> None:
    """A non-archived task is woken exactly once and consumes one chain slot."""
    plugin = await plugin_factory()
    store = plugin._store
    task = await make_task(store)

    await plugin._on_task_state_change(task, "completed")

    assert len(plugin.context.sent_messages) == 1
    assert plugin.context.sent_messages[0][0] == UMO
    assert await store.wake_chain_count(task["root_task_id"]) == 1
    stored = await store.get_task(task["task_id"])
    assert stored is not None and stored["needs_human"] is False


@pytest.mark.asyncio
async def test_duplicate_wake_is_idempotent_at_chain_limit(plugin_factory) -> None:
    """A resent notification cannot turn an already-woken task into ``needs_human``."""
    plugin = await plugin_factory()
    store = plugin._store
    task = await make_task(store)

    await plugin._on_task_state_change(task, "completed")
    # Exhaust the chain *after* the wake was delivered: the next event is a duplicate.
    for _ in range(7):
        await store.bump_wake(task["root_task_id"])
    assert await store.wake_chain_count(task["root_task_id"]) == 8

    await plugin._on_task_state_change(task, "completed")

    stored = await store.get_task(task["task_id"])
    assert stored is not None
    assert stored["status"] == STATUS_SUCCEEDED
    assert stored["needs_human"] is False
    assert await store.wake_chain_count(task["root_task_id"]) == 8


@pytest.mark.asyncio
async def test_new_wake_is_still_stopped_at_chain_limit(plugin_factory) -> None:
    """A genuinely new wake at the chain limit still escalates to ``needs_human``."""
    plugin = await plugin_factory()
    store = plugin._store
    task = await make_task(store, status=STATUS_RUNNING)
    for _ in range(8):
        await store.bump_wake(task["root_task_id"])

    await plugin._on_task_state_change(task, "completed")

    assert plugin.context.sent_messages == []
    stored = await store.get_task(task["task_id"])
    assert stored is not None
    assert stored["status"] == "needs_human"
    assert stored["needs_human"] is True
