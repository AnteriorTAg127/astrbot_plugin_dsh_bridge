"""Host wiring behaviour: status flags, per-session vision, channels and wake budget.

These cases drive the real composition root (``DshBridgePlugin.initialize``) and the
real ``Store``/``NotifyService``/``PlatformHost`` while AstrBot itself is a minimal
host double. They pin the wiring rules that are easy to regress without touching the
protocol:

* ``GET status`` reports ``can_write`` from the same check that guards approval writes.
* A task's images are checked against the provider of *that* OpenAPI session; a
  missing session, an absent provider or a failed lookup uploads nothing and degrades
  to text.
* ``approval_notify_channels`` must be a list containing ``im`` before any IM leaves.
* An unreachable platform spends no wake budget, and becomes sendable once registered.
* Concurrent duplicate wakes send once; a rejected send spends its rate attempt but is
  never recorded as delivered.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

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

from bridge.constants import (  # noqa: E402
    DIRECTION_INBOUND,
    GRANTED_BY_HUMAN,
    STATUS_SUCCEEDED,
)
from bridge.host.capabilities import HostCapabilities  # noqa: E402
from bridge.host.openapi import OpenApiHost  # noqa: E402

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
        return SimpleNamespace(id=self._platform_id)


class HostContext:
    """Minimal AstrBot ``Context`` double with adjustable host facts."""

    def __init__(self) -> None:
        """Create a host whose UMO platform is registered and reachable."""
        self.sent_messages: list[tuple[str, object]] = []
        self.platforms: dict[str, StubPlatform] = {"platform": StubPlatform("platform")}
        self.verdict = True
        self.provider = None
        self.provider_error: Exception | None = None
        self.provider_umos: list[str | None] = []

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
        """Return the configured provider (or raise the configured error).

        Args:
            umo: Session whose provider is requested.

        Returns:
            The configured provider, or ``None``.
        """
        self.provider_umos.append(umo)
        if self.provider_error is not None:
            raise self.provider_error
        return self.provider

    async def send_message(self, umo, chain) -> bool:
        """Capture one active message and return the configured verdict.

        Args:
            umo: Target conversation.
            chain: Message chain.

        Returns:
            The configured host verdict.
        """
        self.sent_messages.append((umo, chain))
        return self.verdict


class BlobStub:
    """Return pre-validated attachments without touching disk or the store."""

    def __init__(self, items: list[dict]) -> None:
        """Store the attachments to return.

        Args:
            items: Validated attachment records.
        """
        self.items = items

    async def validate_task_attachments(self, payload: dict) -> list[dict]:
        """Return the prepared attachment list.

        Args:
            payload: Task payload (unused).

        Returns:
            The prepared attachment records.
        """
        return self.items


async def make_task(
    store, task_id: str = "t-1", *, session_id: str | None = "s-1"
) -> dict:
    """Persist one inbound task plus its session grant.

    Args:
        store: Real plugin store.
        task_id: Task identifier.
        session_id: Session to authorize, or ``None``.

    Returns:
        The stored task row.
    """
    if session_id is not None:
        await store.grant_session(
            {
                "session_id": session_id,
                "purpose": "host-wiring-test",
                "granted_by": GRANTED_BY_HUMAN,
                "granted_by_id": "human:1",
            }
        )
    await store.upsert_task(
        {
            "task_id": task_id,
            "root_task_id": task_id,
            "direction": DIRECTION_INBOUND,
            "kind": "astr_agent_run",
            "origin": "human",
            "status": STATUS_SUCCEEDED,
            "payload": {"umo": UMO},
            "session_id": session_id,
        }
    )
    task = await store.get_task(task_id)
    assert task is not None
    return task


@pytest.fixture
async def plugin_factory(tmp_path, monkeypatch):
    """Build initialised real plugin instances with a host double.

    Args:
        tmp_path: pytest temporary directory.
        monkeypatch: pytest monkeypatch fixture.

    Yields:
        A coroutine function ``make(context=None, **config)``.
    """
    created: list = []

    async def make(context: HostContext | None = None, **overrides) -> object:
        """Initialise one plugin with ``overrides`` merged over test defaults."""
        # Each instance gets its own data root so two hosts never share one SQLite file.
        data_root = tmp_path / f"instance-{len(created) + 1}"
        monkeypatch.setattr(
            main,
            "get_astrbot_plugin_data_path",
            lambda root=data_root: str(root),
        )
        host = context or HostContext()
        config = {
            "dashboard_enabled": False,
            "wake_max_chain": 8,
            "wake_rate_per_minute": 10,
            **overrides,
        }
        plugin = main.DshBridgePlugin(host, config)
        await plugin.initialize()
        created.append(plugin)
        return plugin

    try:
        yield make
    finally:
        for plugin in created:
            await plugin.terminate()


@pytest.mark.parametrize(
    ("username", "expected"),
    [("admin", True), ("api_key:key-1", False), (None, False)],
)
@pytest.mark.asyncio
async def test_status_can_write_uses_the_approval_write_check(
    username, expected, monkeypatch
) -> None:
    """``can_write`` is exactly ``_api_authorised()`` for user, API key and anonymous.

    Args:
        username: Dashboard identity exposed by the request proxy.
        expected: Expected ``can_write`` value.
        monkeypatch: pytest monkeypatch fixture.
    """
    plugin = main.DshBridgePlugin(HostContext(), {"dashboard_enabled": False})
    monkeypatch.setattr(main, "request", SimpleNamespace(username=username))

    response = await plugin._api_status()

    assert json.loads(response.body)["can_write"] is expected


@pytest.mark.asyncio
async def test_submit_tool_schema_exposes_and_forwards_session_id() -> None:
    """The adapter advertises ``session_id`` and forwards an explicit or absent value."""
    plugin = main.DshBridgePlugin(HostContext(), {"dashboard_enabled": False})
    calls: list[dict] = []

    async def fake_submit(
        event, prompt: str, purpose: str = "", origin: str = "llm", session_id=None
    ) -> str:
        """Record the adapter's arguments without opening a real gate."""
        calls.append({"prompt": prompt, "purpose": purpose, "session_id": session_id})
        return "handled"

    plugin.llm_submit_task = fake_submit
    tool = main.DshSubmitTaskTool(plugin)
    assert tool.parameters["properties"]["session_id"]["type"] == "string"
    assert "session_id" not in tool.parameters["required"]

    event = SimpleNamespace(unified_msg_origin=UMO)
    assert await tool(event, "do", "why", "sess-1") == "handled"
    assert await tool(event, "do") == "handled"
    assert calls == [
        {"prompt": "do", "purpose": "why", "session_id": "sess-1"},
        {"prompt": "do", "purpose": "", "session_id": None},
    ]


@pytest.mark.parametrize(
    ("mode", "session_id", "degraded", "uploads"),
    [
        ("image", "sess-1", False, 1),
        ("provider_none", "sess-1", True, 0),
        ("provider_error", "sess-1", True, 0),
        ("missing_session", None, True, 0),
    ],
)
@pytest.mark.asyncio
async def test_task_images_use_the_payload_session_provider(
    tmp_path, mode, session_id, degraded, uploads
) -> None:
    """Vision is resolved once from the task's own session; failures upload nothing.

    Args:
        tmp_path: pytest temporary directory.
        mode: Provider scenario to install on the host double.
        session_id: Session id stored in the task payload.
        degraded: Whether the image must degrade to a text placeholder.
        uploads: Expected number of OpenAPI uploads.
    """
    context = HostContext()
    if mode == "provider_none":
        context.provider = None
    elif mode == "provider_error":
        context.provider_error = RuntimeError("provider manager exploded")
    else:
        context.provider = SimpleNamespace(provider_config={"modalities": ["image"]})

    image_path = tmp_path / "image.png"
    image_path.write_bytes(b"\x89PNG\r\n\x1a\nfake-image")
    openapi = OpenApiHost(
        base_url="http://127.0.0.1:6185", api_key="test-key", key_id="k1"
    )
    upload_calls: list[tuple[bytes, str, str]] = []
    run_calls: list[dict] = []

    async def upload_image(data: bytes, mime: str, name: str) -> str:
        """Record one upload and return a deterministic attachment id."""
        upload_calls.append((data, mime, name))
        return "att-1"

    async def run_agent(*, parts, session_id=None, on_text=None) -> dict:
        """Record the composed run without calling a model."""
        run_calls.append({"parts": parts, "session_id": session_id})
        return {
            "text": "ok",
            "session_id": session_id,
            "events": [],
            "attachments": [],
        }

    openapi.upload_image = upload_image  # type: ignore[method-assign]
    openapi.run_agent = run_agent  # type: ignore[method-assign]

    plugin = main.DshBridgePlugin(context, {"dashboard_enabled": False})
    plugin._openapi = openapi
    plugin._blobs = BlobStub(
        [
            {
                "path": str(image_path),
                "media_type": "image/png",
                "blob_id": "b1",
            }
        ]
    )
    plugin._capabilities = HostCapabilities(version="0.1.0", transports=[], tls=False)

    payload = {
        "input_parts": [{"type": "text", "text": "look at this"}],
        "attachments": [{"blob_id": "b1"}],
    }
    if session_id is not None:
        payload["session_id"] = session_id

    result = await plugin._execute_task({"payload": payload})

    assert len(run_calls) == 1
    if session_id is not None:
        assert context.provider_umos == [openapi.umo_for_session(session_id)]
    else:
        assert context.provider_umos == []
    assert len(upload_calls) == uploads
    assert result["degraded"] == (["model_without_vision"] if degraded else [])
    image_parts = [part for part in run_calls[0]["parts"] if part["type"] == "image"]
    assert len(image_parts) == uploads
    if uploads:
        assert image_parts == [{"type": "image", "attachment_id": "att-1"}]


@pytest.mark.asyncio
async def test_human_notify_requires_an_explicit_im_channel(plugin_factory) -> None:
    """Web-only or malformed channel configs never send IM; ``im`` still does.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    context = HostContext()
    plugin = await plugin_factory(
        context,
        approval_notify_umo=UMO,
        approval_notify_channels=["im", "web"],
    )

    await plugin._on_human_notify({"approval_id": "a-web", "channels": ["web"]})
    assert context.sent_messages == []

    await plugin._on_human_notify({"approval_id": "a-str", "channels": "im"})
    assert context.sent_messages == []

    await plugin._on_human_notify({"approval_id": "a-im", "channels": ["im", "web"]})
    assert len(context.sent_messages) == 1
    assert context.sent_messages[0][0] == UMO

    # A decision request must carry the configured channels, never a hardcoded pair.
    captured: list[dict] = []

    async def capture(payload: dict) -> None:
        """Record one notification payload."""
        captured.append(payload)

    plugin._on_human_notify = capture
    await plugin._on_decision_request(
        {"decision_id": "d-1", "task_id": "t-1", "question": "q"}
    )
    assert captured[0]["channels"] == ["im", "web"]

    # A Web-only deployment keeps the decision row but sends no IM.
    web_context = HostContext()
    web_plugin = await plugin_factory(
        web_context,
        approval_notify_umo=UMO,
        approval_notify_channels=["web"],
    )
    await web_plugin._on_human_notify(
        {"approval_id": "a-web-only", "channels": ["web"]}
    )
    assert web_context.sent_messages == []

    captured_web: list[dict] = []

    async def capture_web(payload: dict) -> None:
        """Record one Web-only notification payload."""
        captured_web.append(payload)

    web_plugin._on_human_notify = capture_web
    await web_plugin._on_decision_request(
        {"decision_id": "d-2", "task_id": "t-2", "question": "q"}
    )
    assert captured_web[0]["channels"] == ["web"]


@pytest.mark.asyncio
async def test_unreachable_platform_spends_no_budget_and_recovers(
    plugin_factory,
) -> None:
    """An unregistered platform is silent and budget-free until it becomes reachable.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    context = HostContext()
    plugin = await plugin_factory(context)
    store = plugin._store
    task = await make_task(store)

    context.platforms.clear()
    await plugin._on_task_state_change(task, "completed")

    assert context.sent_messages == []
    assert await store.wake_chain_count(task["root_task_id"]) == 0
    stored = await store.get_task(task["task_id"])
    assert stored is not None
    assert stored["status"] == STATUS_SUCCEEDED
    assert stored["needs_human"] is False

    context.platforms["platform"] = StubPlatform("platform")
    await plugin._on_task_state_change(task, "completed")

    assert len(context.sent_messages) == 1
    assert await store.wake_chain_count(task["root_task_id"]) == 1


@pytest.mark.asyncio
async def test_five_concurrent_duplicate_wakes_send_exactly_once(
    plugin_factory,
) -> None:
    """The wake lock makes five simultaneous state changes produce one IM and one slot.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    context = HostContext()
    plugin = await plugin_factory(context)
    store = plugin._store
    task = await make_task(store)

    await asyncio.gather(
        *(plugin._on_task_state_change(task, "completed") for _ in range(5))
    )

    assert len(context.sent_messages) == 1
    assert await store.wake_chain_count(task["root_task_id"]) == 1
    assert await store.wake_already_delivered(task["task_id"], "completed") is True


@pytest.mark.asyncio
async def test_failed_send_spends_the_attempt_but_is_not_delivered(
    plugin_factory,
) -> None:
    """A ``False`` host verdict costs the rate attempt and never marks delivery.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    context = HostContext()
    context.verdict = False
    plugin = await plugin_factory(context, wake_rate_per_minute=1)
    store = plugin._store

    first = await make_task(store, "t-failed", session_id="s-1")
    await plugin._on_task_state_change(first, "completed")

    assert len(context.sent_messages) == 1
    assert await store.wake_already_delivered(first["task_id"], "completed") is False
    assert await store.wake_chain_count(first["root_task_id"]) == 0
    stored = await store.get_task(first["task_id"])
    assert stored is not None
    assert stored["status"] == STATUS_SUCCEEDED

    second = await make_task(store, "t-limited", session_id="s-1")
    await plugin._on_task_state_change(second, "completed")

    # The failed attempt already consumed the single slot, so nothing is sent again.
    assert len(context.sent_messages) == 1
    limited = await store.get_task(second["task_id"])
    assert limited is not None
    assert limited["status"] == "needs_human"
    assert limited["needs_human"] is True
