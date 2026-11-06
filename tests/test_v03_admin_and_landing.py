"""v0.3 R1/R2/R2b and v0.3.1 quick-approval UX: landing UMO, human approval, admin.

These cases use the real composition root. ``Store``, ``ApprovalService`` and
``TaskService`` are the production classes and SQLite is a temporary file; only
AstrBot itself is a host double. They pin the security-relevant behaviour:

* an unbound landing degrades honestly (log, local task marker, no IM) and a
  bound landing is used verbatim by the wake path;
* ``/dsh approve all`` / ``/dsh reject all`` still record a *human* decision per
  row, never a policy decision, and one failure cannot stop the rest;
* ``_is_admin`` rejects empty senders, empty platforms, cross-platform ids and
  unconfigured admins, and no longer trusts ``event.role`` on its own;
* v0.3.1 ``/dsh approve`` / ``/dsh reject`` without an id still call
  ``human_decide`` (``actor_kind="human"``), only selecting the newest pending
  row; ``/dsh pending`` mirrors the real queue and its notification hint never
  turns an approval into an automatic decision.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import logging
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from astrbot.core.platform.message_type import MessageType

PLUGIN_ROOT = Path(__file__).resolve().parent.parent

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
    ACTOR_HUMAN,
    DIRECTION_INBOUND,
    STATUS_SUCCEEDED,
)
from bridge.errors import BridgeError  # noqa: E402
from bridge.store import Store  # noqa: E402

PLATFORM = "platform"
UMO = "platform:FriendMessage:session-1"
OTHER_UMO = "platform:FriendMessage:session-2"
ADMIN = "admin-1"


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

    def __init__(self, *, admins: list[str] | None = None) -> None:
        """Create a host whose UMO platform is registered and reachable.

        Args:
            admins: ``admins_id`` returned by ``get_config``.
        """
        self.sent_messages: list[tuple[str, object]] = []
        self.platforms: dict[str, StubPlatform] = {PLATFORM: StubPlatform(PLATFORM)}
        self.config: dict = {"admins_id": [ADMIN] if admins is None else admins}
        self.verdict = True

    def add_llm_tools(self, *tools) -> None:
        """Ignore LLM tool registration."""

    def register_web_api(self, route, handler, methods, desc) -> None:
        """Ignore Dashboard route registration."""

    def get_config(self) -> dict:
        """Return the host configuration."""
        return self.config

    def get_platform_inst(self, platform_id: str):
        """Resolve a platform exactly like the real ``Context``.

        Args:
            platform_id: Platform instance id to look up.

        Returns:
            The matching platform double, or ``None``.
        """
        return self.platforms.get(platform_id)

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


class Event:
    """Command event double covering only the bridge's read surface."""

    def __init__(
        self,
        *,
        sender: str = ADMIN,
        platform_id: str = PLATFORM,
        umo: str = UMO,
        role: str = "member",
        message_type: MessageType = MessageType.FRIEND_MESSAGE,
    ) -> None:
        """Create one event.

        Args:
            sender: ``get_sender_id`` value.
            platform_id: ``get_platform_id`` value.
            umo: ``unified_msg_origin`` value.
            role: Host role attribute.
            message_type: ``get_message_type`` value.
        """
        self.unified_msg_origin = umo
        self.role = role
        self._sender = sender
        self._platform_id = platform_id
        self._message_type = message_type

    def get_sender_id(self) -> str:
        """Return the sender id."""
        return self._sender

    def get_platform_id(self) -> str:
        """Return the platform instance id."""
        return self._platform_id

    def get_message_type(self) -> MessageType:
        """Return the message type."""
        return self._message_type

    def plain_result(self, text: str):
        """Wrap one plain text command result.

        Args:
            text: Result text.

        Returns:
            A double carrying the text.
        """
        return SimpleNamespace(text=text)


async def collect(agen) -> list[str]:
    """Collect the text of one command's yielded results.

    Args:
        agen: Async generator produced by a command handler.

    Returns:
        The result texts.
    """
    return [item.text async for item in agen]


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


async def make_task(store, task_id: str, **overrides) -> dict:
    """Persist one inbound task without a payload UMO.

    Args:
        store: Real plugin store.
        task_id: Task identifier.
        **overrides: Task field overrides.

    Returns:
        The stored task row.
    """
    await store.upsert_task(
        {
            "task_id": task_id,
            "root_task_id": task_id,
            "direction": DIRECTION_INBOUND,
            "kind": "astr_agent_run",
            "origin": "human",
            "status": "succeeded",
            "payload": {},
            **overrides,
        }
    )
    task = await store.get_task(task_id)
    assert task is not None
    return task


async def create_pending(
    plugin, task_id: str, *, tool: str = "astr_agent_run", reason: str = "test approval"
) -> str:
    """Create one real pending ``cross_end_submit`` approval.

    Args:
        plugin: Initialised plugin with a real ``ApprovalService``.
        task_id: Owning task identifier.
        tool: Action label.
        reason: Human-facing reason recorded on the approval.

    Returns:
        The approval id.
    """
    params = {
        "task_id": task_id,
        "root_task_id": task_id,
        "kind": "astr_agent_run",
        "origin": "human",
        "session_id": None,
        "purpose": "test",
        "timeout_s": 300,
        "input_parts": [{"type": "text", "text": "run"}],
        "attachments": [],
        "tool_hints": [],
    }
    approval = await plugin._approvals.create_cross_end_submit(
        task={"task_id": task_id, "root_task_id": task_id},
        tool=tool,
        reason=reason,
        display_reason={"zh": f"测试审批：{reason}"},
        params=params,
    )
    return approval["approval_id"]


async def create_expired(store, approval_id: str) -> None:
    """Insert a pending row whose deadline has already passed.

    Args:
        store: Real plugin store.
        approval_id: Approval identifier.
    """
    await store.put_approval(
        {
            "approval_id": approval_id,
            "approval_type": "cross_end_submit",
            "task_id": None,
            "root_task_id": None,
            "session_id": None,
            "tool": "astr_agent_run",
            "reason": "already late",
            "display_reason": {},
            "request_digest": "expired-digest",
            "submit_digest": None,
            "origin_side": "A",
            "source": "local",
            "gate_scope": "inbound_release",
            "expires_at": time.time() - 1,
        }
    )


# -- R1: landing UMO ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_unbound_landing_is_silent_and_locally_marked(
    plugin_factory, caplog, monkeypatch
) -> None:
    """No payload UMO and no binding: zero sends, log, status hint, task marker.

    Args:
        plugin_factory: Initialised plugin factory.
        caplog: pytest log capture fixture.
        monkeypatch: pytest monkeypatch fixture.
    """
    monkeypatch.setattr(main, "request", SimpleNamespace(username="admin"))
    context = HostContext()
    plugin = await plugin_factory(context)
    task = await make_task(plugin._store, "task-unbound")
    caplog.set_level(logging.INFO)

    await plugin._on_task_state_change(task, "completed")

    assert context.sent_messages == []
    assert "reason=no_umo" in caplog.text
    stored = await plugin._store.get_task("task-unbound")
    assert stored is not None
    assert stored["error"]["details"]["degraded"] == "no_umo"

    status = "\n".join(await collect(plugin.dsh_status(Event())))
    assert "未绑定" in status

    api_status = json.loads((await plugin._api_status()).body)
    assert api_status["landing"] == {"bound": False}


@pytest.mark.asyncio
async def test_bound_landing_is_used_verbatim(plugin_factory, monkeypatch) -> None:
    """A binding makes the wake path send to the exact bound UMO.

    Args:
        plugin_factory: Initialised plugin factory.
        monkeypatch: pytest monkeypatch fixture.
    """
    monkeypatch.setattr(main, "request", SimpleNamespace(username="admin"))
    context = HostContext()
    plugin = await plugin_factory(context)

    bind = "\n".join(await collect(plugin.dsh_bind(Event())))
    assert UMO in bind
    assert await plugin._store.get_meta("bridge_landing_umo") == UMO
    meta = json.loads(await plugin._store.get_meta("bridge_landing_meta"))
    assert meta["platform_id"] == PLATFORM
    assert meta["message_type"] == "FriendMessage"
    assert meta["bound_at"]

    task = await make_task(plugin._store, "task-bound")
    await plugin._on_task_state_change(task, "completed")

    assert len(context.sent_messages) == 1
    assert context.sent_messages[0][0] == UMO

    status = "\n".join(await collect(plugin.dsh_status(Event())))
    assert UMO in status
    api_status = json.loads((await plugin._api_status()).body)
    assert api_status["landing"]["bound"] is True
    assert api_status["landing"]["umo"] == UMO


@pytest.mark.asyncio
async def test_non_admin_bind_is_refused_and_writes_nothing(plugin_factory) -> None:
    """A non-admin cannot bind and leaves the meta table untouched.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    context = HostContext()
    plugin = await plugin_factory(context)

    lines = await collect(plugin.dsh_bind(Event(sender="intruder")))
    assert "仅管理员" in "\n".join(lines)
    assert await plugin._store.get_meta("bridge_landing_umo") == ""
    assert context.sent_messages == []


@pytest.mark.asyncio
async def test_unbind_is_idempotent_and_binding_survives_reopen(
    plugin_factory,
) -> None:
    """``unbind`` is safe twice and a fresh ``Store`` sees the persisted binding.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    context = HostContext()
    plugin = await plugin_factory(context)
    await collect(plugin.dsh_bind(Event()))

    reopened = Store()
    await reopened.init(plugin._store.path)
    try:
        assert await reopened.get_meta("bridge_landing_umo") == UMO
    finally:
        await reopened.close()

    first = "\n".join(await collect(plugin.dsh_unbind(Event())))
    second = "\n".join(await collect(plugin.dsh_unbind(Event())))
    assert "已解除" in first
    assert "已解除" in second
    assert await plugin._store.get_meta("bridge_landing_umo") == ""
    assert await plugin._store.get_meta("bridge_landing_meta") == ""


@pytest.mark.asyncio
async def test_explicit_approval_notify_umo_still_wins(plugin_factory) -> None:
    """Landing never overrides the explicit approval notification target.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    context = HostContext()
    plugin = await plugin_factory(
        context, approval_notify_umo=OTHER_UMO, approval_notify_channels=["im"]
    )
    await collect(plugin.dsh_bind(Event()))

    await plugin._on_human_notify({"approval_id": "a-1", "channels": ["im"]})

    assert len(context.sent_messages) == 1
    assert context.sent_messages[0][0] == OTHER_UMO

    # With no explicit target, a bound landing must NOT become an IM fallback.
    silent_context = HostContext()
    silent = await plugin_factory(silent_context, approval_notify_channels=["im"])
    await collect(silent.dsh_bind(Event()))
    await silent._on_human_notify({"approval_id": "a-2", "channels": ["im"]})
    assert silent_context.sent_messages == []


# -- R2: batch human approval ------------------------------------------------------


@pytest.mark.asyncio
async def test_approve_all_records_three_distinct_human_decisions(
    plugin_factory,
) -> None:
    """``/dsh approve all`` decides every pending row as a human, once.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    plugin = await plugin_factory(HostContext())
    ids = [await create_pending(plugin, f"task-{index}") for index in range(3)]

    lines = await collect(plugin.dsh_approve(Event(), "all", "3"))
    output = "\n".join(lines)

    for approval_id in ids:
        assert approval_id in output
        row = await plugin._store.get_approval(approval_id)
        assert row is not None
        assert row["state"] == "decided"
        assert row["outcome"] == "allowed-once"
        assert row["actor_kind"] == ACTOR_HUMAN
        assert row["actor"] == f"astrbot_admin:{ADMIN}"
        assert row["channel"] == "im"


@pytest.mark.asyncio
async def test_approve_all_empty_queue_is_explicit(plugin_factory) -> None:
    """An empty pending queue produces a clear no-op message.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    plugin = await plugin_factory(HostContext())
    output = "\n".join(await collect(plugin.dsh_approve(Event(), "all")))
    assert "没有待审批" in output


@pytest.mark.asyncio
async def test_one_expired_approval_does_not_block_the_others(plugin_factory) -> None:
    """An expired row is reported but the remaining rows are still decided.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    plugin = await plugin_factory(HostContext())
    expired = "11111111-1111-4111-8111-111111111111"
    await create_expired(plugin._store, expired)
    valid = [await create_pending(plugin, f"task-{index}") for index in range(2)]

    output = "\n".join(await collect(plugin.dsh_approve(Event(), "all", "10")))

    assert expired in output
    assert "expired" in output
    for approval_id in valid:
        row = await plugin._store.get_approval(approval_id)
        assert row is not None and row["outcome"] == "allowed-once"
    late = await plugin._store.get_approval(expired)
    assert late is not None and late["state"] == "pending"


@pytest.mark.asyncio
async def test_non_admin_batch_has_zero_side_effects(plugin_factory) -> None:
    """A non-admin cannot batch-decide and no approval row changes.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    plugin = await plugin_factory(HostContext())
    ids = [await create_pending(plugin, f"task-{index}") for index in range(3)]

    output = "\n".join(
        await collect(plugin.dsh_approve(Event(sender="intruder"), "all"))
    )
    assert "仅管理员" in output
    for approval_id in ids:
        row = await plugin._store.get_approval(approval_id)
        assert row is not None
        assert row["state"] == "pending"
        assert row["actor"] is None


@pytest.mark.asyncio
async def test_reject_all_rejects_every_pending_row(plugin_factory) -> None:
    """``/dsh reject all`` records a human rejection for each pending row.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    plugin = await plugin_factory(HostContext())
    ids = [await create_pending(plugin, f"task-{index}") for index in range(2)]

    output = "\n".join(await collect(plugin.dsh_reject(Event(), "all", "2")))

    for approval_id in ids:
        assert approval_id in output
        row = await plugin._store.get_approval(approval_id)
        assert row is not None and row["outcome"] == "rejected"
        assert row["actor_kind"] == ACTOR_HUMAN


@pytest.mark.asyncio
async def test_batch_decisions_record_their_source_command(plugin_factory) -> None:
    """Each batch decision carries an audit-grep-able ``source_command``.

    PRD §2.2 requires the batch command to be recorded as the origin of every
    decision. The existing ``decided_reason`` column is reused with a fixed
    ``source_command=<name>`` prefix, so no protocol or DB field is added.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    plugin = await plugin_factory(HostContext())
    approved = [await create_pending(plugin, f"approve-{index}") for index in range(2)]
    await collect(plugin.dsh_approve(Event(), "all", "2"))
    for approval_id in approved:
        row = await plugin._store.get_approval(approval_id)
        assert row is not None
        assert row["decided_reason"] == "source_command=approve_all"

    rejected = [await create_pending(plugin, f"reject-{index}") for index in range(2)]
    await collect(plugin.dsh_reject(Event(), "all", "out of scope"))
    for approval_id in rejected:
        row = await plugin._store.get_approval(approval_id)
        assert row is not None
        assert row["outcome"] == "rejected"
        assert row["decided_reason"].startswith("source_command=reject_all")
        assert "out of scope" in row["decided_reason"]


@pytest.mark.asyncio
async def test_agent_actor_is_still_refused(plugin_factory) -> None:
    """The human-only decision path still rejects agent-shaped actors.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    plugin = await plugin_factory(HostContext())
    approval_id = await create_pending(plugin, "task-agent")

    with pytest.raises(BridgeError) as excinfo:
        await plugin._approvals.human_decide(
            approval_id,
            allowed=True,
            actor="agent:auto",
            channel="im",
        )
    assert excinfo.value.code == "agent_cannot_approve"
    row = await plugin._store.get_approval(approval_id)
    assert row is not None and row["state"] == "pending"


# -- R2b: hardened administrator check ---------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("config_admins", "sender", "platform_id", "umo", "role"),
    [
        ([""], "", PLATFORM, UMO, "member"),
        ([ADMIN], ADMIN, "", "platform:FriendMessage:s", "member"),
        ([f"{PLATFORM}:{ADMIN}"], ADMIN, "other", OTHER_UMO, "member"),
        ([], ADMIN, PLATFORM, UMO, "member"),
        ([ADMIN], "attacker", PLATFORM, UMO, "admin"),
        ([ADMIN], ADMIN, PLATFORM, "other:FriendMessage:s", "member"),
    ],
)
async def test_admin_check_rejects_untrusted_identity(
    plugin_factory, config_admins, sender, platform_id, umo, role
) -> None:
    """Empty, cross-platform, unconfigured and role-only identities are denied.

    Args:
        plugin_factory: Initialised plugin factory.
        config_admins: ``admins_id`` value.
        sender: Event sender id.
        platform_id: Event platform instance id.
        umo: Event unified message origin.
        role: Host role attribute.
    """
    context = HostContext(admins=config_admins)
    plugin = await plugin_factory(context)
    event = Event(sender=sender, platform_id=platform_id, umo=umo, role=role)
    assert plugin._is_admin(event) is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("config_admins", "sender", "platform_id", "umo"),
    [
        ([ADMIN], ADMIN, PLATFORM, UMO),
        ([f"{PLATFORM}:{ADMIN}"], ADMIN, PLATFORM, UMO),
    ],
)
async def test_admin_check_accepts_configured_identity(
    plugin_factory, config_admins, sender, platform_id, umo
) -> None:
    """Bare and platform-qualified ``admins_id`` entries both work on their platform.

    Args:
        plugin_factory: Initialised plugin factory.
        config_admins: ``admins_id`` value.
        sender: Event sender id.
        platform_id: Event platform instance id.
        umo: Event unified message origin.
    """
    context = HostContext(admins=config_admins)
    plugin = await plugin_factory(context)
    event = Event(sender=sender, platform_id=platform_id, umo=umo)
    assert plugin._is_admin(event) is True


@pytest.mark.asyncio
async def test_existing_admin_commands_still_work(plugin_factory) -> None:
    """The hardened check keeps admin commands working and refuses non-admins.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    context = HostContext()
    plugin = await plugin_factory(context)

    admin_status = "\n".join(await collect(plugin.dsh_status(Event())))
    assert "DSH 桥接状态" in admin_status

    denied = "\n".join(await collect(plugin.dsh_status(Event(sender="intruder"))))
    assert "仅管理员" in denied


# -- L-1 / peer task error codes ---------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["agent_turn_failed", "agent_output_missing"])
async def test_peer_task_error_code_is_stored_verbatim(
    plugin_factory, code: str
) -> None:
    """A peer-defined task error code is stored and listed without a whitelist.

    ``agent_turn_failed`` / ``agent_output_missing`` are B-side task event codes,
    not §15 ``BridgeError`` codes. The A endpoint must persist them verbatim and
    keep the task ``failed`` (not ``needs_human``, not an internal error).

    Args:
        plugin_factory: Initialised plugin factory.
        code: Peer task error code to feed.
    """
    plugin = await plugin_factory(HostContext())
    task_id = f"task-{code}"
    await make_task(plugin._store, task_id, status="running")

    await plugin._tasks.on_event(
        {
            "task_id": task_id,
            "root_task_id": task_id,
            "notify_id": f"notify-{code}",
            "event": "failed",
            "eseq": 1,
            "error": {
                "code": code,
                "message": "peer turn produced no usable output",
                "details": {"reason": "turn_error"},
            },
        }
    )

    stored = await plugin._store.get_task(task_id)
    assert stored is not None
    assert stored["status"] == "failed"
    assert stored["error"]["code"] == code
    assert stored["error"]["message"] == "peer turn produced no usable output"

    listed = "\n".join(await collect(plugin.dsh_tasks(Event(), 10)))
    assert task_id in listed
    assert "failed" in listed


@pytest.mark.asyncio
async def test_success_clears_stale_degraded_marker(plugin_factory) -> None:
    """A terminal success drops the local ``error.details.degraded`` marker.

    ``mark_task_degraded`` is a local notification note, not an error. When the
    task later reaches ``succeeded`` the stale marker must not survive in the
    status row, while the success result and any other error fields stay intact.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    plugin = await plugin_factory(HostContext())
    task = await make_task(plugin._store, "task-degraded-then-ok", status="running")
    await plugin._store.mark_task_degraded(task["task_id"], "no_umo")
    marked = await plugin._store.get_task(task["task_id"])
    assert marked is not None
    assert marked["error"]["details"]["degraded"] == "no_umo"

    updated = await plugin._store.transition(
        task["task_id"],
        STATUS_SUCCEEDED,
        eseq=1,
        result={"summary": "done"},
    )

    assert updated["status"] == STATUS_SUCCEEDED
    assert updated["result"] == {"summary": "done"}
    details = (updated["error"] or {}).get("details") or {}
    assert "degraded" not in details


# -- v0.3.1: quick approval UX (no protocol or approval-semantics change) -----------

QUICK_HINT = "回复 /dsh approve 即可批准最新一项，或 /dsh approve <id> 指定。"


async def make_two_pending(plugin):
    """Create an older and a newer pending approval, distinct and ordered.

    Args:
        plugin: Initialised plugin with a real ``ApprovalService``.

    Returns:
        ``(older_id, newer_id)``.
    """
    older = await create_pending(plugin, "task-older", reason="older")
    await asyncio.sleep(0.01)
    newer = await create_pending(plugin, "task-newer", reason="newer")
    return older, newer


@pytest.mark.asyncio
async def test_quick_approve_targets_the_latest_pending(plugin_factory) -> None:
    """``/dsh approve`` without an id allows only the newest pending row.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    plugin = await plugin_factory(HostContext())
    older, newer = await make_two_pending(plugin)

    output = "\n".join(await collect(plugin.dsh_approve(Event())))

    assert newer in output
    assert "已批准" in output
    assert "cross_end_submit" in output
    assert "task-newer" in output
    assert "测试审批：newer" in output
    row = await plugin._store.get_approval(newer)
    assert row is not None
    assert row["state"] == "decided"
    assert row["outcome"] == "allowed-once"
    assert row["actor_kind"] == ACTOR_HUMAN
    assert row["actor"] == f"astrbot_admin:{ADMIN}"
    assert row["channel"] == "im"
    assert row["decided_reason"] == "source_command=approve_latest"
    untouched = await plugin._store.get_approval(older)
    assert untouched is not None
    assert untouched["state"] == "pending"
    assert untouched["actor"] is None


@pytest.mark.asyncio
async def test_quick_reject_targets_the_latest_pending(plugin_factory) -> None:
    """``/dsh reject`` without an id rejects only the newest pending row.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    plugin = await plugin_factory(HostContext())
    older, newer = await make_two_pending(plugin)

    output = "\n".join(await collect(plugin.dsh_reject(Event())))

    assert newer in output
    assert older not in output
    assert "已拒绝" in output
    row = await plugin._store.get_approval(newer)
    assert row is not None
    assert row["state"] == "decided"
    assert row["outcome"] == "rejected"
    assert row["actor_kind"] == ACTOR_HUMAN
    assert row["channel"] == "im"
    assert row["decided_reason"] == "source_command=reject_latest"
    untouched = await plugin._store.get_approval(older)
    assert untouched is not None and untouched["state"] == "pending"


@pytest.mark.asyncio
async def test_quick_decision_empty_queue_is_explicit_and_calls_nothing(
    plugin_factory,
) -> None:
    """An empty queue answers clearly for both commands and never decides.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    plugin = await plugin_factory(HostContext())
    calls: list[tuple] = []
    original = plugin._approvals.human_decide

    async def counted(*args, **kwargs):
        calls.append((args, kwargs))
        return await original(*args, **kwargs)

    plugin._approvals.human_decide = counted
    try:
        approve = "\n".join(await collect(plugin.dsh_approve(Event())))
        reject = "\n".join(await collect(plugin.dsh_reject(Event())))
    finally:
        plugin._approvals.human_decide = original

    assert "没有待审批" in approve
    assert "没有待审批" in reject
    assert calls == []


@pytest.mark.asyncio
async def test_quick_approval_non_admin_has_zero_side_effects(plugin_factory) -> None:
    """A non-admin cannot quick-decide or list pending and changes nothing.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    plugin = await plugin_factory(HostContext())
    older, newer = await make_two_pending(plugin)

    approve = "\n".join(await collect(plugin.dsh_approve(Event(sender="intruder"))))
    reject = "\n".join(await collect(plugin.dsh_reject(Event(sender="intruder"))))
    listing = "\n".join(await collect(plugin.dsh_pending(Event(sender="intruder"))))

    for output in (approve, reject, listing):
        assert "仅管理员" in output
        assert older not in output
        assert newer not in output
    for approval_id in (older, newer):
        row = await plugin._store.get_approval(approval_id)
        assert row is not None
        assert row["state"] == "pending"
        assert row["actor"] is None


@pytest.mark.asyncio
async def test_pending_lists_real_rows_newest_first(plugin_factory) -> None:
    """``/dsh pending`` mirrors the real pending queue, newest first.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    plugin = await plugin_factory(HostContext())
    created = []
    for index in range(3):
        created.append(
            await create_pending(plugin, f"task-{index}", reason=f"r{index}")
        )
        await asyncio.sleep(0.01)

    output = "\n".join(await collect(plugin.dsh_pending(Event())))

    pending = await plugin._store.list_approvals(state="pending", limit=200)
    listed = [row["approval_id"] for row in pending]
    assert listed == list(reversed(created))
    for approval_id in listed:
        assert approval_id in output
    assert output.index(created[-1]) < output.index(created[0])
    for index in range(3):
        assert f"测试审批：r{index}" in output


@pytest.mark.asyncio
async def test_pending_limit_and_default_cap(plugin_factory) -> None:
    """``/dsh pending [n]`` honours ``n`` and the hard cap of 20.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    plugin = await plugin_factory(HostContext())
    created = []
    for index in range(21):
        created.append(
            await create_pending(plugin, f"task-{index}", reason=f"r{index}")
        )

    explicit = "\n".join(await collect(plugin.dsh_pending(Event(), 2)))
    shown = [approval_id for approval_id in created if approval_id in explicit]
    assert len(shown) == 2
    assert created[-1] in shown and created[-2] in shown
    assert created[0] not in shown

    default = "\n".join(await collect(plugin.dsh_pending(Event())))
    assert sum(1 for approval_id in created if approval_id in default) == 5

    capped = "\n".join(await collect(plugin.dsh_pending(Event(), 100)))
    assert sum(1 for approval_id in created if approval_id in capped) == 20
    assert created[0] not in capped


@pytest.mark.asyncio
async def test_pending_empty_queue_is_explicit(plugin_factory) -> None:
    """``/dsh pending`` reports an empty queue instead of failing.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    plugin = await plugin_factory(HostContext())
    output = "\n".join(await collect(plugin.dsh_pending(Event())))
    assert "没有待审批" in output


@pytest.mark.asyncio
async def test_explicit_id_and_batch_all_keep_their_meaning(plugin_factory) -> None:
    """The pre-existing ``<id>`` and ``all`` paths still decide exactly as before.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    plugin = await plugin_factory(HostContext())
    older, newer = await make_two_pending(plugin)

    explicit = "\n".join(await collect(plugin.dsh_approve(Event(), older)))
    assert older in explicit
    oldest_row = await plugin._store.get_approval(older)
    assert oldest_row is not None
    assert oldest_row["outcome"] == "allowed-once"
    assert oldest_row["decided_reason"] is None
    assert (await plugin._store.get_approval(newer))["state"] == "pending"

    extra = await create_pending(plugin, "task-extra", reason="extra")
    batch = "\n".join(await collect(plugin.dsh_approve(Event(), "all", "5")))
    assert newer in batch and extra in batch
    for approval_id in (newer, extra):
        row = await plugin._store.get_approval(approval_id)
        assert row is not None
        assert row["outcome"] == "allowed-once"
        assert row["actor_kind"] == ACTOR_HUMAN
        assert row["decided_reason"] == "source_command=approve_all"


@pytest.mark.asyncio
async def test_approval_notification_advertises_copyable_quick_commands(
    plugin_factory,
) -> None:
    """The IM approval text ends with a copy-paste hint, keeping its trigger rules.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    context = HostContext()
    plugin = await plugin_factory(
        context, approval_notify_umo=UMO, approval_notify_channels=["im"]
    )

    await plugin._on_human_notify(
        {
            "approval_id": "a-quick",
            "approval_type": "cross_end_submit",
            "tool": "astr_agent_run",
            "channels": ["im"],
        }
    )
    text = context.sent_messages[0][1].chain[0].text
    assert "a-quick" in text
    assert QUICK_HINT in text

    # A timeout announcement is not actionable, so it must not advertise approve.
    await plugin._on_human_notify(
        {
            "approval_id": "a-timeout",
            "approval_type": "cross_end_submit",
            "timed_out": True,
            "channels": ["im"],
        }
    )
    timeout_text = context.sent_messages[1][1].chain[0].text
    assert QUICK_HINT not in timeout_text

    # Business decisions are answered through the decision path, not /dsh approve.
    await plugin._on_human_notify(
        {
            "approval_id": "d-1",
            "approval_type": "business_decision",
            "tool": "decision",
            "channels": ["im"],
        }
    )
    decision_text = context.sent_messages[2][1].chain[0].text
    assert QUICK_HINT not in decision_text

    # ``approval_notify_umo`` still decides the target; no landing fallback appears.
    assert all(umo == UMO for umo, _chain in context.sent_messages)


@pytest.mark.asyncio
async def test_wake_text_needs_approval_advertises_quick_commands(
    plugin_factory,
) -> None:
    """The wake text for an approval event carries the same copyable hint.

    Args:
        plugin_factory: Initialised plugin factory.
    """
    plugin = await plugin_factory(HostContext())
    task = await make_task(plugin._store, "task-wake")
    text = plugin._wake_text(task, "needs_approval")
    assert QUICK_HINT in text
