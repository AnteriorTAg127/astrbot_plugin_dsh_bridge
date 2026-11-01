"""Session authorization tests (protocol §9.7, PRD §6.4).

Covers scoped listing, the auto-authorization quota, revoke/reclaim, idempotent
``session.create``, and the requirement that agents cannot widen their own scope.
"""

from __future__ import annotations

import pytest

from bridge.app.sessions import SessionService
from bridge.errors import BridgeError


@pytest.mark.asyncio
async def test_list_shows_only_authorized_sessions(sessions) -> None:
    """``session.list`` returns granted sessions with purpose and provenance (§9.7)."""
    await sessions.admin_grant("s-1", purpose="code-review", granted_by_id="admin:alice")
    payload = await sessions.list_sessions({"purpose": None, "state": "any", "limit": 50})
    assert [item["session_id"] for item in payload["sessions"]] == ["s-1"]
    entry = payload["sessions"][0]
    assert entry["purpose"] == "code-review"
    assert entry["authorized"] is True
    assert entry["granted_by"] == "human"
    assert entry["granted_by_id"] == "admin:alice"
    assert payload["authz_version"] >= 1


@pytest.mark.asyncio
async def test_list_filters_by_purpose_and_state(sessions) -> None:
    """Filters operate inside the authorized set only."""
    await sessions.admin_grant("s-1", purpose="code-review")
    await sessions.admin_grant("s-2", purpose="docgen")
    by_purpose = await sessions.list_sessions({"purpose": "docgen", "state": "any"})
    assert [item["session_id"] for item in by_purpose["sessions"]] == ["s-2"]
    by_state = await sessions.list_sessions({"purpose": None, "state": "busy"})
    assert by_state["sessions"] == []


@pytest.mark.asyncio
async def test_list_rejects_invalid_state(sessions) -> None:
    """An unknown state value is ``bad_params``."""
    with pytest.raises(BridgeError) as excinfo:
        await sessions.list_sessions({"state": "exploded"})
    assert excinfo.value.code == "bad_params"


@pytest.mark.asyncio
async def test_create_auto_authorizes_inside_quota(sessions) -> None:
    """``session.create`` auto-authorizes and tags ``agent_auto`` (§9.7, PRD §6.4.2)."""
    result = await sessions.create_session(
        {"request_id": "req-1", "purpose": "code-review", "title": "审查"}
    )
    assert result["authorized"] is True
    assert result["granted_by"] == "agent_auto"
    grant = await sessions._store.get_grant(result["session_id"])
    assert grant is not None
    assert grant["granted_by"] == "agent_auto"
    assert "req-1" in grant["granted_by_id"]
    assert await sessions._store.is_authorized(result["session_id"])


@pytest.mark.asyncio
async def test_create_is_idempotent_per_request_id(sessions) -> None:
    """The same ``request_id`` never creates a second session (§9.7)."""
    first = await sessions.create_session({"request_id": "req-x", "purpose": "a"})
    second = await sessions.create_session({"request_id": "req-x", "purpose": "a"})
    assert first["session_id"] == second["session_id"]
    grants = await sessions.admin_grants()
    assert len(grants) == 1


@pytest.mark.asyncio
async def test_create_respects_the_quota(sessions) -> None:
    """Exceeding ``max_agent_sessions`` is ``session_quota_exceeded`` (§9.7)."""
    await sessions.admin_set_policy(True, 2)
    await sessions.create_session({"request_id": "r1"})
    await sessions.create_session({"request_id": "r2"})
    with pytest.raises(BridgeError) as excinfo:
        await sessions.create_session({"request_id": "r3"})
    assert excinfo.value.code == "session_quota_exceeded"
    grants = await sessions.admin_grants()
    assert len(grants) == 2


@pytest.mark.asyncio
async def test_create_denied_when_policy_disabled(sessions) -> None:
    """Revoking the creation permission blocks new sessions (§9.7, PRD §6.4.2)."""
    await sessions.admin_set_policy(False, 10)
    with pytest.raises(BridgeError) as excinfo:
        await sessions.create_session({"request_id": "r1"})
    assert excinfo.value.code == "session_create_denied"


@pytest.mark.asyncio
async def test_quota_changes_do_not_delete_existing_grants(sessions) -> None:
    """Lowering the quota keeps existing grants; only new creations are refused."""
    await sessions.create_session({"request_id": "r1"})
    await sessions.admin_set_policy(True, 0)
    grants = await sessions.admin_grants()
    assert len(grants) == 1
    with pytest.raises(BridgeError):
        await sessions.create_session({"request_id": "r2"})


@pytest.mark.asyncio
async def test_unauthorized_session_is_refused(sessions) -> None:
    """``require_authorized`` raises for unknown sessions (§9.7)."""
    with pytest.raises(BridgeError) as excinfo:
        await sessions.require_authorized("nope")
    assert excinfo.value.code == "session_not_authorized"


@pytest.mark.asyncio
async def test_revoke_removes_authorization_and_bumps_version(sessions) -> None:
    """Revoking a grant makes it unusable and advances ``authz_version``."""
    await sessions.admin_grant("s-1", purpose="code-review")
    before = (await sessions.snapshot())["version"]
    version = await sessions.admin_revoke("s-1")
    assert version > before
    assert not await sessions._store.is_authorized("s-1")
    with pytest.raises(BridgeError):
        await sessions.require_authorized("s-1")


@pytest.mark.asyncio
async def test_reclaim_agent_sessions_only(sessions) -> None:
    """Reclaiming agent-created sessions leaves human grants intact (§9.7)."""
    await sessions.admin_grant("human-1", purpose="manual")
    created = await sessions.create_session({"request_id": "r1", "purpose": "auto"})
    await sessions.admin_revoke_agent_sessions()
    assert await sessions._store.is_authorized("human-1")
    assert not await sessions._store.is_authorized(created["session_id"])


@pytest.mark.asyncio
async def test_quota_usage_is_reported(sessions) -> None:
    """The status page can show used/max quota for agent sessions."""
    await sessions.create_session({"request_id": "r1"})
    await sessions.admin_grant("human-1")
    quota = await sessions.admin_quota()
    assert quota["used"] == 1
    assert quota["max"] == 10
    assert quota["allow_agent_create"] is True


@pytest.mark.asyncio
async def test_manage_rename_and_archive(sessions) -> None:
    """``session.manage`` supports exactly ``rename`` and ``archive`` (§9.7)."""
    await sessions.admin_grant("s-1", purpose="code-review", title="old")
    renamed = await sessions.manage_session(
        {"session_id": "s-1", "action": "rename", "title": "new"}
    )
    assert renamed["applied"] is True
    grant = await sessions._store.get_grant("s-1")
    assert grant is not None and grant["title"] == "new"

    archived = await sessions.manage_session({"session_id": "s-1", "action": "archive"})
    assert archived["applied"] is True
    grant = await sessions._store.get_grant("s-1")
    assert grant is not None and grant["archived"] is True

    with pytest.raises(BridgeError) as excinfo:
        await sessions.manage_session({"session_id": "s-1", "action": "delete"})
    assert excinfo.value.code == "bad_params"


@pytest.mark.asyncio
async def test_manage_out_of_scope_is_refused(sessions) -> None:
    """Managing a session without a grant is ``session_not_authorized`` (§9.7)."""
    with pytest.raises(BridgeError) as excinfo:
        await sessions.manage_session(
            {"session_id": "unknown", "action": "rename", "title": "x"}
        )
    assert excinfo.value.code == "session_not_authorized"


@pytest.mark.asyncio
async def test_select_requires_authorization(sessions) -> None:
    """``session.select`` validates the grant before switching (§9.7)."""
    with pytest.raises(BridgeError):
        await sessions.select_session({"task_id": "t", "session_id": "nope"})
    await sessions.admin_grant("s-1")
    assert await sessions.select_session({"task_id": "t", "session_id": "s-1"}) == {"ok": True}


@pytest.mark.asyncio
async def test_select_archived_session_is_refused(sessions) -> None:
    """An archived session cannot receive new work (§9.7)."""
    await sessions.admin_grant("s-1")
    await sessions.manage_session({"session_id": "s-1", "action": "archive"})
    with pytest.raises(BridgeError) as excinfo:
        await sessions.select_session({"task_id": "t", "session_id": "s-1"})
    assert excinfo.value.code == "session_archived"


@pytest.mark.asyncio
async def test_authz_message_is_monotonic(sessions) -> None:
    """``session.authz`` carries a strictly increasing version (§9.7)."""
    message = await sessions.authz_message()
    assert message["k"] == "evt"
    assert message["m"] == "session.authz"
    first_version = message["params"]["version"]
    await sessions.admin_grant("s-1")
    second = await sessions.authz_message()
    assert second["params"]["version"] > first_version
    assert "allow_agent_create" in second["params"]
    assert "max_agent_sessions" in second["params"]


@pytest.mark.asyncio
async def test_authz_push_callback_runs(sessions) -> None:
    """The push callback fires whenever the table changes (A→B authority)."""
    pushed: list[dict] = []

    async def on_change(snapshot: dict) -> None:
        pushed.append(snapshot)

    sessions._on_authz_changed = on_change
    await sessions.admin_grant("s-1")
    assert pushed and pushed[-1]["version"] >= 1


@pytest.mark.asyncio
async def test_expired_grant_is_not_authorized(sessions) -> None:
    """A grant past ``expires_at`` stops authorizing (§9.7)."""
    import time

    await sessions.admin_grant("s-1", expires_at=time.time() - 1)
    with pytest.raises(BridgeError):
        await sessions.require_authorized("s-1")
    payload = await sessions.list_sessions({"purpose": None, "state": "any"})
    assert payload["sessions"] == []


@pytest.mark.asyncio
async def test_new_service_instance_reads_persisted_policy(tmp_path, store) -> None:
    """Quota and version survive a service restart (persistence requirement)."""
    first = SessionService(store, conn="default", allow_agent_create=True, max_agent_sessions=3)
    await first.init()
    await first.admin_set_policy(True, 3)
    second = SessionService(store, conn="default", allow_agent_create=True, max_agent_sessions=3)
    quota = await second.admin_quota()
    assert quota["max"] == 3
