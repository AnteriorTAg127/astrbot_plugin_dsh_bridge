"""Session authorization surface (protocol §9.7) — A is the authoritative side.

AstrBot owns the grant table, the creation quota and the ``session.authz`` push.
Every operation is scoped: agents may only see and manage sessions inside the
authorized set, and out-of-scope ids are reported as "not found" rather than
revealing their existence.

Agent-created sessions are auto-authorized inside the configured quota
(PRD §6.4.2), always tagged ``granted_by="agent_auto"`` with the triggering
connection and task so an administrator can reclaim them in one action.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Awaitable, Callable

from astrbot.api import logger

from ..constants import (
    GRANTED_BY_AGENT_AUTO,
    GRANTED_BY_HUMAN,
    KIND_EVT,
    MSG_SESSION_AUTHZ,
    SESSION_ACTIONS,
    SESSION_STATES,
)
from ..errors import (
    ERR_BAD_PARAMS,
    ERR_SESSION_ARCHIVED,
    ERR_SESSION_CREATE_DENIED,
    ERR_SESSION_NOT_AUTHORIZED,
    ERR_SESSION_QUOTA_EXCEEDED,
    BridgeError,
)
from ..session import utc_iso_ms
from ..store import Store


def _iso(epoch: float | None) -> str | None:
    """Render an epoch timestamp as protocol ISO 8601 UTC milliseconds.

    Args:
        epoch: Unix seconds, or ``None``.

    Returns:
        ISO string or ``None``.
    """
    if epoch is None:
        return None
    millis = int(epoch * 1000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(millis // 1000)) + (
        f".{millis % 1000:03d}Z"
    )


class SessionService:
    """Authoritative session grant table plus the wire-facing operations."""

    def __init__(
        self,
        store: Store,
        *,
        conn: str,
        allow_agent_create: bool = True,
        max_agent_sessions: int = 10,
        on_authz_changed: Callable[[dict], Awaitable[None]] | None = None,
    ) -> None:
        """Create the service.

        Args:
            store: Persistent store.
            conn: Connection identifier that owns this authorization table.
            allow_agent_create: Whether agents may create sessions at all.
            max_agent_sessions: Quota for agent-created sessions.
            on_authz_changed: Coroutine invoked with the new snapshot whenever the
                table changes, so the caller can push ``session.authz`` to the peer.
        """
        self._store = store
        self._conn = conn
        self._allow_agent_create = allow_agent_create
        self._max_agent_sessions = max_agent_sessions
        self._on_authz_changed = on_authz_changed

    async def init(self) -> None:
        """Persist the configured creation policy into the store."""
        await self._store.set_agent_create_policy(
            self._allow_agent_create, self._max_agent_sessions
        )

    # -- wire operations ---------------------------------------------------------------

    async def list_sessions(self, params: dict) -> dict:
        """``session.list``: authorized sessions only (§9.7).

        Args:
            params: ``{"purpose", "state", "limit", "cursor"}``.

        Returns:
            ``{"sessions": [...], "next_cursor": None, "authz_version": n}``.
        """
        purpose = params.get("purpose")
        state = params.get("state", "any")
        limit = params.get("limit", 50)
        try:
            limit = max(1, min(200, int(limit)))
        except (TypeError, ValueError):
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "limit"}) from None
        if state not in ("any", *SESSION_STATES):
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "state"})

        grants = await self._store.list_grants(include_revoked=False)
        snapshot = await self._store.authz_snapshot()
        items = []
        for grant in grants:
            if purpose and grant["purpose"] != purpose:
                continue
            if state != "any" and grant["state"] != state:
                continue
            if grant["expires_at"] is not None and grant["expires_at"] <= time.time():
                continue
            items.append(
                {
                    "session_id": grant["session_id"],
                    "purpose": grant["purpose"],
                    "title": grant["title"],
                    "state": grant["state"],
                    "authorized": True,
                    "granted_by": grant["granted_by"],
                    "granted_by_id": grant["granted_by_id"],
                    "expires_at": _iso(grant["expires_at"]),
                    "created_by_task": grant["created_by_task"],
                }
            )
        items.sort(key=lambda item: item["session_id"])
        return {
            "sessions": items[:limit],
            "next_cursor": None,
            "authz_version": snapshot["version"],
        }

    async def create_session(self, params: dict) -> dict:
        """``session.create``: auto-authorize inside the quota (§9.7, PRD §6.4.2).

        Args:
            params: ``{"request_id", "purpose", "title"}``.

        Returns:
            ``{"session_id", "authorized", "granted_by", "authz_version"}``.

        Raises:
            BridgeError: ``session_create_denied`` when the policy forbids creation,
                ``session_quota_exceeded`` when the quota is exhausted.
        """
        request_id = params.get("request_id")
        if not isinstance(request_id, str) or not request_id:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "request_id"})
        snapshot = await self._store.authz_snapshot()
        if not snapshot["allow_agent_create"]:
            logger.warning(
                "bridge session.create denied conn=%s reason=policy_disabled",
                self._conn,
            )
            raise BridgeError(ERR_SESSION_CREATE_DENIED)

        purpose = params.get("purpose") or ""
        title = params.get("title") or ""
        if not isinstance(purpose, str) or not isinstance(title, str):
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "purpose"})

        # Idempotency: a replayed request_id must never create a second session.
        existing_id = await self._store.lookup_session_create_request(request_id)
        if existing_id:
            grant = await self._store.get_grant(existing_id)
            if grant is not None:
                return {
                    "session_id": grant["session_id"],
                    "authorized": True,
                    "granted_by": grant["granted_by"],
                    "authz_version": snapshot["version"],
                }

        session_id = str(uuid.uuid4())
        await self._store.record_session_create_request(request_id, session_id)
        try:
            version = await self._store.grant_session(
                {
                    "session_id": session_id,
                    "purpose": purpose,
                    "title": title,
                    "state": "idle",
                    "granted_by": GRANTED_BY_AGENT_AUTO,
                    "granted_by_id": f"conn:{self._conn}#request:{request_id}",
                    "created_by_task": params.get("task_id"),
                }
            )
        except BridgeError as exc:
            if exc.code == ERR_SESSION_QUOTA_EXCEEDED:
                logger.warning(
                    "bridge session.create rejected conn=%s reason=quota_exceeded",
                    self._conn,
                )
            raise
        await self._push_authz()
        logger.info(
            "bridge session auto-authorized conn=%s session=%s request=%s",
            self._conn,
            session_id,
            request_id,
        )
        return {
            "session_id": session_id,
            "authorized": True,
            "granted_by": GRANTED_BY_AGENT_AUTO,
            "authz_version": version,
        }

    async def select_session(self, params: dict) -> dict:
        """``session.select``: switch a task onto an authorized session (§9.7).

        Args:
            params: ``{"task_id", "session_id"}``.

        Returns:
            ``{"ok": True}``.

        Raises:
            BridgeError: ``session_not_authorized`` / ``session_archived``.
        """
        task_id = params.get("task_id")
        session_id = params.get("session_id")
        if not isinstance(task_id, str) or not task_id:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "task_id"})
        if not isinstance(session_id, str) or not session_id:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "session_id"})
        await self.require_authorized(session_id)
        grant = await self._store.get_grant(session_id)
        if grant is not None and grant["archived"]:
            raise BridgeError(ERR_SESSION_ARCHIVED)
        logger.info(
            "bridge session selected conn=%s task=%s session=%s",
            self._conn,
            task_id,
            session_id,
        )
        return {"ok": True}

    async def manage_session(self, params: dict) -> dict:
        """``session.manage``: ``rename`` or ``archive`` (§9.7).

        Args:
            params: ``{"session_id", "action", "title"}``.

        Returns:
            ``{"session_id", "action", "applied": True}``.

        Raises:
            BridgeError: ``bad_params`` for an unsupported action,
                ``session_not_authorized`` when out of scope.
        """
        session_id = params.get("session_id")
        action = params.get("action")
        if not isinstance(session_id, str) or not session_id:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "session_id"})
        if action not in SESSION_ACTIONS:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "action"})
        await self.require_authorized(session_id)
        title = params.get("title") or ""
        if not isinstance(title, str):
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "title"})
        if action == "rename":
            await self._store.set_grant_title(session_id, title)
        else:
            await self._store.archive_grant(session_id)
        logger.info(
            "bridge session managed conn=%s session=%s action=%s",
            self._conn,
            session_id,
            action,
        )
        return {"session_id": session_id, "action": action, "applied": True}

    async def require_authorized(self, session_id: str) -> None:
        """Assert that a session may be used by the peer (§9.7).

        Args:
            session_id: Session identifier.

        Raises:
            BridgeError: ``session_not_authorized`` when no valid grant exists.
        """
        if not await self._store.is_authorized(session_id):
            logger.warning(
                "bridge session authorization denied conn=%s session=%s",
                self._conn,
                session_id,
            )
            raise BridgeError(ERR_SESSION_NOT_AUTHORIZED)

    # -- administration (status page / commands) ---------------------------------------

    async def admin_grants(self) -> list[dict]:
        """Return every grant (including revoked) for the status page.

        Returns:
            Grant dictionaries with ISO timestamps.
        """
        grants = await self._store.list_grants(include_revoked=True)
        return [
            {
                **grant,
                "expires_at": _iso(grant["expires_at"]),
                "created_at": _iso(grant["created_at"]),
                "updated_at": _iso(grant["updated_at"]),
            }
            for grant in grants
        ]

    async def admin_grant(
        self,
        session_id: str,
        *,
        purpose: str = "",
        title: str = "",
        granted_by_id: str = "dashboard",
        expires_at: float | None = None,
    ) -> int:
        """Authorize a session from the dashboard or a command.

        Args:
            session_id: Session identifier.
            purpose: Purpose label shown to agents.
            title: Human title.
            granted_by_id: Identity of the granting operator.
            expires_at: Optional expiry as Unix seconds.

        Returns:
            The new authorization version.
        """
        version = await self._store.grant_session(
            {
                "session_id": session_id,
                "purpose": purpose,
                "title": title,
                "state": "idle",
                "granted_by": GRANTED_BY_HUMAN,
                "granted_by_id": granted_by_id,
                "expires_at": expires_at,
            }
        )
        await self._push_authz()
        logger.info(
            "bridge session granted conn=%s session=%s by=%s",
            self._conn,
            session_id,
            granted_by_id,
        )
        return version

    async def admin_revoke(self, session_id: str) -> int:
        """Revoke one session authorization.

        Args:
            session_id: Session identifier.

        Returns:
            The new authorization version.
        """
        version = await self._store.revoke_session(session_id)
        await self._push_authz()
        logger.info("bridge session revoked conn=%s session=%s", self._conn, session_id)
        return version

    async def admin_revoke_agent_sessions(
        self, granted_by_id: str | None = None
    ) -> int:
        """Reclaim every agent-created session for this connection (§9.7).

        Args:
            granted_by_id: Optional connection scope.

        Returns:
            The new authorization version.
        """
        version = await self._store.revoke_agent_sessions(granted_by_id)
        await self._push_authz()
        logger.info(
            "bridge agent sessions reclaimed conn=%s scope=%s",
            self._conn,
            granted_by_id or "all",
        )
        return version

    async def admin_set_policy(self, allow: bool, max_sessions: int) -> int:
        """Change the agent creation policy at runtime.

        Args:
            allow: Whether agents may create sessions.
            max_sessions: Quota for agent-created sessions.

        Returns:
            The new authorization version.
        """
        self._allow_agent_create = allow
        self._max_agent_sessions = max_sessions
        version = await self._store.set_agent_create_policy(allow, max_sessions)
        await self._push_authz()
        logger.info(
            "bridge agent create policy conn=%s allow=%s max=%s",
            self._conn,
            allow,
            max_sessions,
        )
        return version

    async def admin_quota(self) -> dict:
        """Return quota usage for the status page.

        Returns:
            ``{"used", "max", "allow_agent_create", "authz_version"}``.
        """
        snapshot = await self._store.authz_snapshot()
        used = sum(
            1
            for grant in snapshot["grants"]
            if grant["granted_by"] == GRANTED_BY_AGENT_AUTO
        )
        return {
            "used": used,
            "max": snapshot["max_agent_sessions"],
            "allow_agent_create": snapshot["allow_agent_create"],
            "authz_version": snapshot["version"],
        }

    async def snapshot(self) -> dict:
        """Return the full authorization table for ``session.authz`` (§9.7).

        Returns:
            Snapshot with ISO timestamps so it can be serialised directly.
        """
        snapshot = await self._store.authz_snapshot()
        return {
            "version": snapshot["version"],
            "grants": [
                {**grant, "expires_at": _iso(grant["expires_at"])}
                for grant in snapshot["grants"]
            ],
            "revoked": snapshot["revoked"],
            "allow_agent_create": snapshot["allow_agent_create"],
            "max_agent_sessions": snapshot["max_agent_sessions"],
        }

    async def authz_message(self) -> dict:
        """Build the ``session.authz`` event message (§9.7).

        Returns:
            Message object ready for ``Session.send_message``.
        """
        return {
            "k": KIND_EVT,
            "m": MSG_SESSION_AUTHZ,
            "id": str(uuid.uuid4()),
            "ts": utc_iso_ms(),
            "params": await self.snapshot(),
        }

    async def _push_authz(self) -> None:
        """Notify the caller that the table changed so it can push ``session.authz``."""
        if self._on_authz_changed is None:
            return
        try:
            await self._on_authz_changed(await self.snapshot())
        except Exception:
            logger.exception("bridge session.authz push failed")


def is_human_actor(actor_kind: str | None) -> bool:
    """Whether an actor may approve or decide (§12.3, §9.8).

    Args:
        actor_kind: ``human`` or ``agent`` as declared by the caller.

    Returns:
        ``True`` only for ``human``.
    """
    return actor_kind == "human"


__all__ = ["SessionService", "is_human_actor"]
