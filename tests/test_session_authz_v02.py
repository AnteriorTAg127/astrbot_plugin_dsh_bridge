"""v0.2 A-side session governance: authority instance, peer audit, complete ids.

The three increments under test (``开发/v0.2/prd.md``):

* R1 — ``authz_meta.instance_id`` / ``instance_started_at`` are generated once
  per database and exposed by ``Store.authz_snapshot`` /
  ``SessionService.snapshot``, so the peer can tell a rebuilt authority from a
  stale version. ``tests/fixtures/session_authz_v02.json`` is the cross-end
  contract: its key set and value types must match the wire payload.
* R2 — ``SessionService.peer_audit`` reconciles the local authoritative grants
  with the peer's ``session.list``; ``/dsh sessions check fix`` raises the local
  version to ``max(local, peer) + 1`` and uses a strict push that propagates
  failures.
* R4 — ``/dsh tasks`` prints the complete ``task_id``.

R3 (the failed-task grant marker) is **not** implemented: the security review
removed it from v0.2, so neither the store, the commands nor the peer wire
format may know anything about it.

Everything runs against the real ``Store`` and ``SessionService`` with a
throwaway SQLite file. Only the live peer link is a recording double, exactly
like the other app-layer tests; no business logic is mocked away.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import sqlite3
import sys
import time
import uuid
from pathlib import Path

import pytest
from bridge.app.sessions import SessionService
from bridge.errors import BridgeError
from bridge.session import SessionState
from bridge.store import Store

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

CONN = "default"
UMO = "platform:FriendMessage:session-1"

#: Two authorized sessions that share their first eight characters.
SESSION_A = "7c4e1a90-1111-4222-8333-444455556666"
SESSION_B = "7c4e1a90-9999-4aaa-8bbb-ccccddddeeee"
#: A session that exists only on the peer side.
SESSION_PEER_ONLY = "0f9d2c31-2222-4333-8444-555566667777"

#: Normalised cross-end contract snapshot, copied byte-for-byte into the DSH
#: plugin repository. Only the key set and value types are asserted here; the
#: concrete instance id and timestamps are runtime values on both sides.
FIXTURE_PATH = PLUGIN_ROOT / "tests" / "fixtures" / "session_authz_v02.json"


class Event:
    """AstrMessageEvent double carrying only what the commands read."""

    unified_msg_origin = UMO

    def __init__(self, *, admin: bool = True) -> None:
        """Create the event.

        Args:
            admin: Whether the sender is an administrator.
        """
        self.role = "admin" if admin else "member"
        self._admin = admin

    def get_sender_id(self) -> str:
        """Return a stable sender id.

        Returns:
            The sender id: the configured admin when ``admin`` is true, otherwise
            a different member (v0.3 hardening no longer trusts ``role`` alone).
        """
        return "admin-1" if self._admin else "member-1"

    def get_platform_id(self) -> str:
        """Return the platform instance id.

        Returns:
            The platform instance id backing ``unified_msg_origin``.
        """
        return "platform"

    def plain_result(self, text: str) -> str:
        """Build the object the command handler yields.

        Args:
            text: Response text.

        Returns:
            The response text itself.
        """
        return text


class Host:
    """Minimal plugin context: only ``get_config`` is read by these commands."""

    def get_config(self) -> dict:
        """Return the host configuration.

        Returns:
            A configuration with the one administrator the event doubles use.
        """
        return {"admins_id": ["admin-1"]}


class PeerLink:
    """Live-session double whose peer table mirrors the last applied snapshot.

    ``send_message`` simulates the peer accepting a ``session.authz`` push, so a
    second ``peer_audit`` observes the applied state instead of the old table.
    ``call`` answers both ``session.list`` and ``session.create``: the latter
    raises the peer's cached version like the real B side does.
    """

    def __init__(
        self,
        *,
        sessions: list[str] | None = None,
        version: int = 0,
        state: SessionState = SessionState.READY,
        error: Exception | None = None,
        push_error: Exception | None = None,
    ) -> None:
        """Create the peer double.

        Args:
            sessions: Session ids the peer currently authorizes.
            version: The peer's cached ``authz_version``.
            state: Advertised session state.
            error: Exception raised by ``call`` instead of replying.
            push_error: Exception raised by ``send_message`` instead of applying.
        """
        self.state = state
        self.sessions = list(sessions or [])
        self.version = version
        self.error = error
        self.push_error = push_error
        self.calls: list[dict] = []
        self.pushes: list[dict] = []
        self.created = 0

    async def call(
        self, message: str, params: dict, timeout_s: float | None = None
    ) -> dict:
        """Record one outbound request and return the scripted reply.

        Args:
            message: Message name.
            params: Request parameters.
            timeout_s: Optional reply timeout override.

        Returns:
            The scripted reply.

        Raises:
            Exception: The scripted error, when one was configured.
        """
        self.calls.append(
            {"message": message, "params": params, "timeout_s": timeout_s}
        )
        if self.error is not None:
            raise self.error
        if message == "session.create":
            self.version += 1
            created_id = f"peer-created-{self.created}"
            self.created += 1
            self.sessions.append(created_id)
            return {
                "session_id": created_id,
                "authorized": True,
                "granted_by": "agent_auto",
                "authz_version": self.version,
            }
        assert message == "session.list"
        return {
            "sessions": [
                {
                    "session_id": session_id,
                    "purpose": "",
                    "title": "",
                    "state": "cold",
                    "authorized": True,
                    "granted_by": "human",
                    "granted_by_id": "dashboard",
                    "expires_at": None,
                    "created_by_task": None,
                }
                for session_id in self.sessions
            ],
            "next_cursor": None,
            "authz_version": self.version,
        }

    async def send_message(self, message: dict) -> None:
        """Apply a pushed ``session.authz`` snapshot as the peer would.

        Args:
            message: Event message.

        Raises:
            Exception: The scripted ``push_error``, when one was configured.
        """
        if self.push_error is not None:
            raise self.push_error
        self.pushes.append(message)
        params = message["params"]
        self.version = params["version"]
        self.sessions = [grant["session_id"] for grant in params["grants"]]


async def build_audit_service(store) -> tuple[SessionService, PeerLink]:
    """Wire the real ``SessionService`` to a recording peer link.

    Args:
        store: Real store fixture.

    Returns:
        ``(service, peer)``.
    """
    peer = PeerLink()

    async def apply_authz(snapshot: dict) -> None:
        await peer.send_message({"params": snapshot})

    service = SessionService(
        store, conn=CONN, allow_agent_create=True, on_authz_changed=apply_authz
    )
    await service.init()
    service.set_session_provider(lambda: peer)
    return service, peer


def make_plugin(store, sessions) -> main.DshBridgePlugin:
    """Build the real plugin and inject the real services under test.

    Args:
        store: Real store fixture.
        sessions: Real ``SessionService`` instance.

    Returns:
        The plugin instance.
    """
    plugin = main.DshBridgePlugin(Host(), {"dashboard_enabled": False})
    plugin._store = store
    plugin._sessions_svc = sessions
    return plugin


def _shape(value):
    """Return the nested key/type signature of a JSON-like value.

    Args:
        value: Parsed JSON value.

    Returns:
        A nested structure with only keys and type names, so runtime UUIDs and
        timestamps can differ while the contract still matches exactly.
    """
    if isinstance(value, dict):
        return {key: _shape(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_shape(item) for item in value]
    return type(value).__name__


# -- R1: authority instance identity ------------------------------------------------


@pytest.mark.asyncio
async def test_authority_instance_survives_reopen_and_changes_with_a_new_database(
    tmp_path,
) -> None:
    """One database keeps both instance fields; a new file changes both."""
    db_path = tmp_path / "bridge.db"
    first = Store()
    await first.init(db_path)
    try:
        snapshot = await first.authz_snapshot()
        instance = snapshot["instance_id"]
        started_at = snapshot["instance_started_at"]
        assert snapshot["version"] == 0
    finally:
        await first.close()
    assert isinstance(instance, str) and instance
    assert uuid.UUID(instance).version == 4
    assert isinstance(started_at, int) and not isinstance(started_at, bool)
    assert started_at > 0

    reopened = Store()
    await reopened.init(db_path)
    try:
        snapshot = await reopened.authz_snapshot()
        assert snapshot["instance_id"] == instance
        assert snapshot["instance_started_at"] == started_at
        assert snapshot["version"] == 0
    finally:
        await reopened.close()

    # The started-at value has second granularity, so a new database must be
    # created in a later wall-clock second to be observably newer.
    await asyncio.sleep(1.05)
    other = Store()
    await other.init(tmp_path / "other.db")
    try:
        snapshot = await other.authz_snapshot()
        other_instance = snapshot["instance_id"]
        other_started_at = snapshot["instance_started_at"]
        assert snapshot["version"] == 0
    finally:
        await other.close()
    assert isinstance(other_instance, str) and other_instance
    assert other_instance != instance
    assert other_started_at != started_at


@pytest.mark.asyncio
async def test_service_snapshots_expose_both_instance_fields(store, sessions) -> None:
    """``authz_snapshot`` and the ``session.authz`` payload carry both fields."""
    store_snapshot = await store.authz_snapshot()
    instance = store_snapshot["instance_id"]
    started_at = store_snapshot["instance_started_at"]
    assert isinstance(instance, str) and instance
    assert isinstance(started_at, int) and not isinstance(started_at, bool)

    service_snapshot = await sessions.snapshot()
    assert service_snapshot["instance_id"] == instance
    assert service_snapshot["instance_started_at"] == started_at

    message = await sessions.authz_message()
    assert message["params"]["instance_id"] == instance
    assert message["params"]["instance_started_at"] == started_at


@pytest.mark.asyncio
async def test_authz_message_matches_the_cross_end_contract_fixture(
    store, sessions
) -> None:
    """The wire payload's key set and value types equal the shared fixture.

    The fixture is copied byte-for-byte into the DSH plugin repository, so this
    is the structural check that stops A from silently omitting a field the peer
    requires (the previous ``instance_started_at`` omission made F3 unfixable).
    """
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    await sessions.admin_grant(
        SESSION_A,
        purpose="audit",
        title="Example session",
        expires_at=time.time() + 3600,
    )
    await sessions.admin_grant(SESSION_B)
    await sessions.admin_revoke(SESSION_B)

    params = (await sessions.authz_message())["params"]

    assert set(params) == set(fixture)
    assert _shape(params) == _shape(fixture)
    assert isinstance(params["instance_id"], str)
    assert uuid.UUID(params["instance_id"]).version == 4
    assert isinstance(params["instance_started_at"], int)
    assert not isinstance(params["instance_started_at"], bool)
    assert params["grants"][0]["created_by_task"] is None


@pytest.mark.asyncio
async def test_authz_snapshot_keeps_meta_grants_and_revoked_in_one_view(
    store, sessions
) -> None:
    """Grants, revokes and the version they produced are read from one state.

    The three queries run inside a single transaction, so a snapshot never
    combines a grant row from one state with a version from another. The test
    asserts the same-source property by matching every snapshot against the
    version returned by the mutation that produced it.
    """
    granted = await sessions.admin_grant(SESSION_A)
    snapshot = await store.authz_snapshot()
    assert snapshot["version"] == granted
    assert [grant["session_id"] for grant in snapshot["grants"]] == [SESSION_A]
    assert snapshot["revoked"] == []

    await sessions.admin_grant(SESSION_B)
    revoked = await sessions.admin_revoke(SESSION_A)
    snapshot = await store.authz_snapshot()
    assert snapshot["version"] == revoked
    assert [grant["session_id"] for grant in snapshot["grants"]] == [SESSION_B]
    assert snapshot["revoked"] == [SESSION_A]
    assert set(snapshot["revoked"]).isdisjoint(
        {grant["session_id"] for grant in snapshot["grants"]}
    )


# -- R2: peer audit ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_peer_audit_reports_no_difference_when_tables_match(store) -> None:
    """Identical tables produce empty ``only_local``/``only_peer`` sets."""
    service, peer = await build_audit_service(store)
    await service.admin_grant(SESSION_A)
    await service.admin_grant(SESSION_B)
    peer.sessions = [SESSION_A, SESSION_B]
    peer.version = 9

    report = await service.peer_audit()

    local = await store.authz_snapshot()
    assert report["local_version"] == local["version"]
    assert report["local_instance_id"] == local["instance_id"]
    assert report["peer_authz_version"] == 9
    assert report["both"] == sorted([SESSION_A, SESSION_B])
    assert report["only_local"] == []
    assert report["only_peer"] == []
    assert peer.calls[0]["message"] == "session.list"
    assert peer.calls[0]["params"] == {
        "purpose": None,
        "state": "any",
        "limit": 200,
        "cursor": None,
    }


@pytest.mark.asyncio
async def test_peer_audit_lists_both_differences_and_skips_local_expired(
    store,
) -> None:
    """Local-only, peer-only and expired local grants are classified correctly."""
    service, peer = await build_audit_service(store)
    await service.admin_grant(SESSION_A)
    await service.admin_grant(SESSION_B)
    await service.admin_grant("d1c0ffee-0000-4000-8000-000000000001", expires_at=1.0)
    peer.sessions = [SESSION_B, SESSION_PEER_ONLY]
    peer.version = 4

    report = await service.peer_audit()

    assert report["only_local"] == [SESSION_A]
    assert report["only_peer"] == [SESSION_PEER_ONLY]
    assert report["both"] == [SESSION_B]
    # The expired grant is still stored but must not be reported as missing.
    assert "d1c0ffee-0000-4000-8000-000000000001" not in report["only_local"]


@pytest.mark.asyncio
async def test_peer_audit_without_ready_session_sends_nothing(store) -> None:
    """No READY session fails with ``not_ready`` and zero peer traffic."""
    service, peer = await build_audit_service(store)
    peer.state = SessionState.HANDSHAKING

    with pytest.raises(BridgeError) as excinfo:
        await service.peer_audit()

    assert excinfo.value.code == "not_ready"
    assert excinfo.value.details == {"reason": "no_ready_session"}
    assert peer.calls == []

    service.set_session_provider(lambda: None)
    with pytest.raises(BridgeError) as excinfo:
        await service.peer_audit()
    assert excinfo.value.code == "not_ready"
    assert peer.calls == []


@pytest.mark.asyncio
async def test_peer_audit_passes_peer_errors_through_and_wraps_carrier_failures(
    store,
) -> None:
    """A peer ``BridgeError`` keeps its code; a carrier crash is unavailable."""
    service, peer = await build_audit_service(store)
    peer.error = BridgeError("unknown_message")
    with pytest.raises(BridgeError) as excinfo:
        await service.peer_audit()
    assert excinfo.value.code == "unknown_message"

    peer.error = RuntimeError("link died")
    with pytest.raises(BridgeError) as excinfo:
        await service.peer_audit()
    assert excinfo.value.code == "capability_unavailable"


# -- R2: command surface -----------------------------------------------------------


@pytest.mark.asyncio
async def test_sessions_check_command_prints_diff_and_honest_limit(store) -> None:
    """``/dsh sessions check`` reconciles and refuses to over-claim."""
    service, peer = await build_audit_service(store)
    await service.admin_grant(SESSION_A)
    peer.sessions = [SESSION_A]
    plugin = make_plugin(store, service)

    lines = [line async for line in plugin.dsh_sessions(Event(), "check")]
    text = "\n".join(lines)

    assert "【会话授权体检】" in text
    assert "一致：1 条" in text
    assert "仅本端有（对端尚未收到）：无" in text
    assert "仅对端有（对端陈旧残留）：无" in text
    assert "instance=" in text
    assert "（本端）" in text
    assert "不比对实例" in text
    assert "不能证明 DSH 侧会话真实存在" in text
    assert "state=cold 不代表" in text


@pytest.mark.asyncio
async def test_sessions_check_command_reports_missing_connection(store) -> None:
    """Without a live link the command says so and makes no request."""
    service, peer = await build_audit_service(store)
    service.set_session_provider(lambda: None)
    plugin = make_plugin(store, service)

    lines = [line async for line in plugin.dsh_sessions(Event(), "check")]
    text = "\n".join(lines)

    assert "无法体检" in text
    assert "活动连接" in text
    assert peer.calls == []


@pytest.mark.asyncio
async def test_non_admin_is_refused_with_zero_peer_traffic(store) -> None:
    """``check`` and ``check fix`` are admin-only and touch no peer state."""
    service, peer = await build_audit_service(store)
    await service.admin_grant(SESSION_A)
    pushes_before = len(peer.pushes)
    plugin = make_plugin(store, service)
    plugin._session = peer

    for extra in ("", "fix"):
        lines = [
            line
            async for line in plugin.dsh_sessions(Event(admin=False), "check", extra)
        ]
        text = "\n".join(lines)
        assert "该指令仅管理员可用" in text
        assert "无法体检" not in text
        assert "重新推送后" not in text
    assert peer.calls == []
    assert len(peer.pushes) == pushes_before


@pytest.mark.asyncio
async def test_sessions_check_fix_raises_the_local_version_above_the_peer(
    store,
) -> None:
    """``fix`` uses ``max(local, peer) + 1``, not a plain local increment.

    The peer's own ``session.create`` raises its cached version, so ``local + 1``
    can still be rejected as stale. The pushed snapshot must land strictly above
    the version the audit observed on the peer.
    """
    service, peer = await build_audit_service(store)
    await service.admin_grant(SESSION_A)
    await service.admin_grant(SESSION_B)
    peer.version = 41
    peer.sessions = [SESSION_A]
    plugin = make_plugin(store, service)
    plugin._session = peer
    before = await store.authz_snapshot()

    lines = [line async for line in plugin.dsh_sessions(Event(), "check", "fix")]
    text = "\n".join(lines)

    after = await store.authz_snapshot()
    assert after["version"] == 42
    assert after["version"] == max(before["version"], 41) + 1
    assert peer.version == 42
    assert peer.pushes[-1]["params"]["version"] == 42
    assert "重新推送后" in text
    assert "version=42" in text
    assert "一致：2 条" in text
    assert "仅本端有（对端尚未收到）：无" in text
    assert "仅对端有（对端陈旧残留）：无" in text


@pytest.mark.asyncio
async def test_sessions_check_fix_reports_a_push_failure_honestly(store) -> None:
    """A failed strict push is an error line, never a successful audit report."""
    service, peer = await build_audit_service(store)
    await service.admin_grant(SESSION_A)
    peer.push_error = RuntimeError("link down")
    plugin = make_plugin(store, service)
    plugin._session = peer

    lines = [line async for line in plugin.dsh_sessions(Event(), "check", "fix")]
    text = "\n".join(lines)

    assert "无法体检" in text
    assert "推送失败" in text
    assert "重新推送后" not in text
    assert "【会话授权体检】" not in text
    assert "一致：" not in text


@pytest.mark.asyncio
async def test_fix_and_peer_creation_are_serialised_without_losing_grants(
    store,
) -> None:
    """Concurrent ``fix`` and ``create_peer_session`` keep both grants."""
    service, peer = await build_audit_service(store)
    await service.admin_grant(SESSION_A)
    plugin = make_plugin(store, service)
    plugin._session = peer

    created, text = await asyncio.gather(
        service.create_peer_session({"request_id": "concurrent-1", "purpose": "audit"}),
        plugin._sessions_check(fix=True),
    )

    created_id = created["session_id"]
    snapshot = await store.authz_snapshot()
    authorized = {grant["session_id"] for grant in snapshot["grants"]}
    assert set(authorized) == {SESSION_A, created_id}
    assert await store.get_grant(created_id) is not None
    assert snapshot["version"] >= created["authz_version"]
    assert snapshot["version"] == peer.version
    assert set(peer.sessions) == authorized
    assert "重新推送后" in text


# -- R1: migration from a v0.1 database --------------------------------------------


_V01_SCHEMA = """
CREATE TABLE authz_meta (
    id                 INTEGER PRIMARY KEY CHECK (id = 1),
    version            INTEGER NOT NULL DEFAULT 0,
    allow_agent_create INTEGER NOT NULL DEFAULT 1,
    max_agent_sessions INTEGER NOT NULL DEFAULT 10
);

CREATE TABLE session_grants (
    session_id     TEXT PRIMARY KEY,
    purpose        TEXT NOT NULL DEFAULT '',
    title          TEXT NOT NULL DEFAULT '',
    state          TEXT NOT NULL DEFAULT 'idle',
    granted_by     TEXT NOT NULL,
    granted_by_id  TEXT NOT NULL,
    expires_at     REAL,
    created_by_task TEXT,
    revoked        INTEGER NOT NULL DEFAULT 0,
    archived       INTEGER NOT NULL DEFAULT 0,
    created_at     REAL NOT NULL,
    updated_at     REAL NOT NULL
);

INSERT INTO authz_meta (id, version, allow_agent_create, max_agent_sessions)
VALUES (1, 5, 1, 10);
INSERT INTO session_grants (session_id, purpose, title, state, granted_by,
    granted_by_id, expires_at, created_by_task, revoked, archived, created_at,
    updated_at)
VALUES ('legacy-session', 'legacy', '', 'idle', 'human', 'dashboard', NULL, NULL,
    0, 0, 1.0, 1.0);
"""


@pytest.mark.asyncio
async def test_v01_database_upgrades_with_both_instance_columns(tmp_path) -> None:
    """An existing v0.1 database keeps its rows and gains both instance fields."""
    db_path = tmp_path / "bridge.db"
    connection = sqlite3.connect(db_path)
    try:
        connection.executescript(_V01_SCHEMA)
        connection.commit()
    finally:
        connection.close()

    store = Store()
    await store.init(db_path)
    try:
        snapshot = await store.authz_snapshot()
        instance = snapshot["instance_id"]
        started_at = snapshot["instance_started_at"]
        assert isinstance(instance, str) and instance
        assert uuid.UUID(instance).version == 4
        assert isinstance(started_at, int) and not isinstance(started_at, bool)
        assert snapshot["version"] == 5
        assert [grant["session_id"] for grant in snapshot["grants"]] == [
            "legacy-session"
        ]

        grant = await store.get_grant("legacy-session")
        assert grant is not None
        assert grant["revoked"] is False
    finally:
        await store.close()


# -- R4: complete task ids ---------------------------------------------------------


@pytest.mark.asyncio
async def test_tasks_command_prints_full_ids_that_distinguish_a_shared_prefix(
    store, sessions
) -> None:
    """Two tasks sharing eight characters are distinguishable in ``/dsh tasks``."""
    first = "deadbeef-1111-4222-8333-444455556666"
    second = "deadbeef-9999-4aaa-8bbb-ccccddddeeee"
    for task_id in (first, second):
        await store.upsert_task(
            {
                "task_id": task_id,
                "root_task_id": task_id,
                "direction": "outbound",
                "kind": "dsh_agent_run",
                "origin": "llm",
                "status": "accepted",
                "session_id": SESSION_A,
                "purpose": "audit",
            }
        )
    plugin = make_plugin(store, sessions)

    lines = [line async for line in plugin.dsh_tasks(Event())]
    text = "\n".join(lines)

    assert first in text
    assert second in text
    assert "任务 ID 为完整 UUID" in text
    assert "dsh_task_status" in text
    assert "dsh_select_session" in text
    rows = text.splitlines()
    first_line = next(line for line in rows if first in line)
    assert first_line.startswith("→ ")
    assert f"→ {first} " in text
