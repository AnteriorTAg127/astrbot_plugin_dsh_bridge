"""SQLite persistence for tasks, notifications, approvals, sessions and wake guards.

Implements protocol §10.1 (idempotency keys must survive a restart), §10.2
("persist, then report") and §16.1 (legal state transitions). All methods are
``async``; a single ``aiosqlite`` connection serialises writes.

The database lives at ``data/plugin_data/astrbot_plugin_dsh_bridge/bridge.db`` —
never inside the plugin directory (project rule 3).
"""

from __future__ import annotations

import json
import math
import time
import uuid
from pathlib import Path
from typing import Any

import aiosqlite

from astrbot.api import logger

from .constants import (
    ACTOR_HUMAN,
    ALLOWED_TRANSITIONS,
    APPROVAL_CROSS_END_SUBMIT,
    APPROVAL_OUTCOMES,
    OPEN_STATUSES,
    OUTCOME_UNAVAILABLE,
    STATUS_ACCEPTED,
    STATUS_NEEDS_HUMAN,
    STATUS_REJECTED,
    TERMINAL_STATUSES,
)
from .errors import (
    ERR_TASK_EXISTS,
    ERR_TASK_NOT_FOUND,
    BridgeError,
)

SCHEMA_VERSION = 3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id       TEXT PRIMARY KEY,
    root_task_id  TEXT NOT NULL,
    direction     TEXT NOT NULL,
    kind          TEXT NOT NULL,
    origin        TEXT NOT NULL,
    status        TEXT NOT NULL,
    eseq          INTEGER NOT NULL DEFAULT 0,
    attempts      INTEGER NOT NULL DEFAULT 0,
    session_id    TEXT,
    purpose       TEXT,
    submit_digest TEXT,
    request_hash  TEXT NOT NULL DEFAULT '',
    payload       TEXT NOT NULL DEFAULT '{}',
    result        TEXT,
    error         TEXT,
    needs_human   INTEGER NOT NULL DEFAULT 0,
    created_at    REAL NOT NULL,
    updated_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_open ON tasks (status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_tasks_root ON tasks (root_task_id);

CREATE TABLE IF NOT EXISTS reply_cache (
    key       TEXT PRIMARY KEY,
    reply     TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS notify_outbox (
    notify_id  TEXT PRIMARY KEY,
    task_id    TEXT NOT NULL,
    root_task_id TEXT NOT NULL,
    message    TEXT NOT NULL,
    params     TEXT NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    next_at    REAL NOT NULL,
    delivered  INTEGER NOT NULL DEFAULT 0,
    undelivered INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_outbox_pending
    ON notify_outbox (delivered, undelivered, next_at);

CREATE TABLE IF NOT EXISTS inbound_notify (
    notify_id   TEXT PRIMARY KEY,
    task_id     TEXT NOT NULL,
    eseq        INTEGER NOT NULL DEFAULT 0,
    processed_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id   TEXT PRIMARY KEY,
    approval_type TEXT NOT NULL,
    task_id       TEXT,
    root_task_id  TEXT,
    session_id    TEXT,
    tool          TEXT,
    reason        TEXT NOT NULL DEFAULT '',
    display_reason TEXT NOT NULL DEFAULT '{}',
    call_id       TEXT,
    request_digest TEXT NOT NULL,
    submit_digest TEXT,
    notify_id     TEXT,
    origin_side   TEXT NOT NULL,
    -- Evidence provenance (protocol §12.7/§12.8). ``local`` = this endpoint
    -- opened the gate; ``peer_request`` = mirror of a peer's approval.request;
    -- ``peer_lookup`` = mirror materialised from an authoritative lookup.
    source        TEXT NOT NULL DEFAULT 'local',
    -- ``inbound_release`` gates a held inbound submission; ``outbound_submit``
    -- gates a submission this endpoint is about to send to the peer. The two
    -- must never authorize each other's role.
    gate_scope    TEXT NOT NULL DEFAULT 'inbound_release',
    -- Session identity captured when the human decision was recorded. A lookup
    -- only answers for the *current* conn/sid; old rows stay unanswerable.
    conn          TEXT,
    sid           TEXT,
    -- Initiator-domain release marker (§12.7.4 naming domains). Distinct from
    -- ``consumed_by_task``, which belongs to the receiving endpoint.
    released_by_task TEXT,
    evidence      TEXT,
    expires_at    REAL NOT NULL,
    state         TEXT NOT NULL DEFAULT 'pending',
    outcome       TEXT,
    actor         TEXT,
    actor_kind    TEXT,
    channel       TEXT,
    decided_reason TEXT,
    decided_at    REAL,
    consumed_by_task TEXT,
    consumed_at   REAL,
    created_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approvals_state ON approvals (state, expires_at);

CREATE TABLE IF NOT EXISTS decisions (
    decision_id  TEXT PRIMARY KEY,
    task_id      TEXT NOT NULL,
    root_task_id TEXT NOT NULL,
    question     TEXT NOT NULL,
    options      TEXT NOT NULL DEFAULT '[]',
    allow_free_text INTEGER NOT NULL DEFAULT 0,
    default_option TEXT,
    expires_at   REAL NOT NULL,
    notify_id    TEXT,
    state        TEXT NOT NULL DEFAULT 'pending',
    choice       TEXT,
    free_text    TEXT,
    actor        TEXT,
    actor_kind   TEXT,
    answered_at  REAL,
    created_at   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS session_grants (
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

CREATE TABLE IF NOT EXISTS authz_meta (
    id                 INTEGER PRIMARY KEY CHECK (id = 1),
    version            INTEGER NOT NULL DEFAULT 0,
    allow_agent_create INTEGER NOT NULL DEFAULT 1,
    max_agent_sessions INTEGER NOT NULL DEFAULT 10,
    instance_id        TEXT,
    instance_started_at INTEGER
);

CREATE TABLE IF NOT EXISTS session_create_requests (
    request_id  TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS wake_chain (
    root_task_id TEXT PRIMARY KEY,
    count        INTEGER NOT NULL DEFAULT 0,
    updated_at   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS wake_rate (
    session_key TEXT PRIMARY KEY,
    window      TEXT NOT NULL,
    updated_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS wake_dedupe (
    task_id    TEXT NOT NULL,
    event_type TEXT NOT NULL,
    stamp      REAL NOT NULL,
    PRIMARY KEY (task_id, event_type)
);

CREATE TABLE IF NOT EXISTS poll_nonces (
    sid    TEXT NOT NULL,
    side   TEXT NOT NULL,
    nonce  TEXT NOT NULL,
    stamp  REAL NOT NULL,
    PRIMARY KEY (sid, side, nonce)
);
"""


def _json(value: Any) -> str:
    """Serialise a value for storage.

    Args:
        value: JSON-compatible value; ``None`` becomes ``"null"``.

    Returns:
        Compact JSON text.
    """
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _unjson(value: str | None, default: Any = None) -> Any:
    """Deserialise a stored JSON value.

    Args:
        value: Stored text, possibly ``None``.
        default: Returned when the text is empty or invalid.

    Returns:
        Decoded value or ``default``.
    """
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


class Store:
    """Async SQLite store for every persistent bridge object."""

    def __init__(self) -> None:
        """Create an unopened store; call :meth:`init` before use."""
        self._db: aiosqlite.Connection | None = None
        self._path: Path | None = None

    @property
    def path(self) -> Path | None:
        """Path of the opened database file, if any."""
        return self._path

    async def init(self, db_path: Path) -> None:
        """Open (and create) the database.

        Args:
            db_path: Absolute path to the SQLite file. Parent directories are
                created as needed.

        Raises:
            RuntimeError: When called twice on the same instance.
        """
        if self._db is not None:
            raise RuntimeError("Store.init called twice")
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._path = db_path
        self._db = await aiosqlite.connect(db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=FULL")
        await self._db.execute("PRAGMA foreign_keys=ON")
        await self._db.executescript(_SCHEMA)
        # Minimal forward migration: databases created before the approval
        # evidence columns existed keep their rows, and the new columns start
        # empty. The verifier treats an empty ``submit_digest`` as "no evidence"
        # and refuses the row instead of falling back to a self-computed digest.
        await self._ensure_approval_evidence_columns()
        await self._ensure_authz_instance_columns()
        await self._db.execute(
            "INSERT OR IGNORE INTO authz_meta (id, version, allow_agent_create,"
            " max_agent_sessions) VALUES (1, 0, 1, 10)"
        )
        # The authority instance identity identifies this database across restarts
        # (§9.7.1). Both values are generated once, in a single statement, and only
        # when missing, so rebuilding the file yields a new instance while
        # reopening the same file keeps the original one. ``instance_started_at``
        # is what lets the peer order two instances; an empty id is treated as
        # missing, matching the v0.1 upgrade path.
        await self._db.execute(
            "UPDATE authz_meta SET"
            " instance_id = COALESCE(NULLIF(instance_id, ''), ?),"
            " instance_started_at = COALESCE(instance_started_at, ?)"
            " WHERE id = 1",
            (str(uuid.uuid4()), int(time.time())),
        )
        await self._db.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        await self._db.commit()
        logger.info("bridge store opened at %s", db_path)

    async def _ensure_approval_evidence_columns(self) -> None:
        """Add the approval evidence columns to a database created before them.

        SQLite has no ``ADD COLUMN IF NOT EXISTS``, so the existing columns are
        read first. The migration is additive only: no row is rewritten and no
        approval becomes usable just because it survived the upgrade.
        """
        db = self._conn()
        async with db.execute("PRAGMA table_info(approvals)") as cursor:
            columns = {str(row["name"]) for row in await cursor.fetchall()}
        for name, ddl in (
            ("submit_digest", "ALTER TABLE approvals ADD COLUMN submit_digest TEXT"),
            (
                "consumed_by_task",
                "ALTER TABLE approvals ADD COLUMN consumed_by_task TEXT",
            ),
            ("consumed_at", "ALTER TABLE approvals ADD COLUMN consumed_at REAL"),
            (
                "source",
                "ALTER TABLE approvals ADD COLUMN source TEXT NOT NULL DEFAULT 'local'",
            ),
            (
                "gate_scope",
                "ALTER TABLE approvals ADD COLUMN gate_scope TEXT NOT NULL"
                " DEFAULT 'inbound_release'",
            ),
            ("conn", "ALTER TABLE approvals ADD COLUMN conn TEXT"),
            ("sid", "ALTER TABLE approvals ADD COLUMN sid TEXT"),
            (
                "released_by_task",
                "ALTER TABLE approvals ADD COLUMN released_by_task TEXT",
            ),
            ("evidence", "ALTER TABLE approvals ADD COLUMN evidence TEXT"),
        ):
            if name not in columns:
                await db.execute(ddl)
        await db.commit()

    async def _ensure_authz_instance_columns(self) -> None:
        """Add the ``authz_meta`` instance columns to a database created before them.

        SQLite has no ``ADD COLUMN IF NOT EXISTS``, so ``PRAGMA table_info`` is
        read first. The migration only adds the nullable columns; :meth:`init`
        fills them afterwards, which keeps existing versions, grants and revokes.
        """
        db = self._conn()
        async with db.execute("PRAGMA table_info(authz_meta)") as cursor:
            columns = {str(row["name"]) for row in await cursor.fetchall()}
        if "instance_id" not in columns:
            await db.execute("ALTER TABLE authz_meta ADD COLUMN instance_id TEXT")
        if "instance_started_at" not in columns:
            await db.execute(
                "ALTER TABLE authz_meta ADD COLUMN instance_started_at INTEGER"
            )
        await db.commit()

    async def close(self) -> None:
        """Commit and close the database, tolerating repeated calls."""
        db = self._db
        self._db = None
        if db is None:
            return
        try:
            await db.commit()
        except Exception:
            logger.exception("bridge store commit on close failed")
        finally:
            await db.close()

    def _conn(self) -> aiosqlite.Connection:
        """Return the open connection.

        Returns:
            The active connection.

        Raises:
            RuntimeError: When the store is not initialised.
        """
        if self._db is None:
            raise RuntimeError("Store is not initialised")
        return self._db

    # -- tasks -------------------------------------------------------------------------

    async def upsert_task(self, task: dict) -> dict:
        """Insert a task, or return the existing one for the same ``task_id``.

        This is the persistent half of the ``(conn, task_id)`` idempotency key
        (§10.1): a duplicate submission must never create a second row.

        Args:
            task: Task row fields. Requires ``task_id``, ``root_task_id``,
                ``direction``, ``kind``, ``origin``, ``status``.

        Returns:
            The stored task as a dictionary, with ``dedup`` set to ``True`` when the
            row already existed.

        Raises:
            BridgeError: ``task_exists`` when the same id arrives with a different
                request hash (idempotency conflict, §15.3).
        """
        db = self._conn()
        now = time.time()
        existing = await self.get_task(task["task_id"])
        if existing is not None:
            incoming_hash = task.get("request_hash", "")
            if incoming_hash and existing.get("request_hash") not in (
                "",
                incoming_hash,
            ):
                raise BridgeError(ERR_TASK_EXISTS)
            return {**existing, "dedup": True}
        await db.execute(
            """
            INSERT INTO tasks (task_id, root_task_id, direction, kind, origin, status,
                               eseq, attempts, session_id, purpose, submit_digest,
                               request_hash, payload, result, error, needs_human,
                               created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                task["task_id"],
                task.get("root_task_id") or task["task_id"],
                task.get("direction", "outbound"),
                task.get("kind", ""),
                task.get("origin", "llm"),
                task.get("status", STATUS_ACCEPTED),
                0,
                int(task.get("attempts", 0)),
                task.get("session_id"),
                task.get("purpose"),
                task.get("submit_digest", ""),
                task.get("request_hash", ""),
                _json(task.get("payload", {})),
                _json(task.get("result")) if task.get("result") is not None else None,
                _json(task.get("error")) if task.get("error") is not None else None,
                1 if task.get("needs_human") else 0,
                now,
                now,
            ),
        )
        await db.commit()
        stored = await self.get_task(task["task_id"])
        if stored is None:  # pragma: no cover - defensive
            raise BridgeError(ERR_TASK_NOT_FOUND)
        return {**stored, "dedup": False}

    async def get_task(self, task_id: str) -> dict | None:
        """Fetch one task by id.

        Args:
            task_id: Task identifier.

        Returns:
            Task dictionary, or ``None`` when unknown.
        """
        db = self._conn()
        async with db.execute(
            "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
        ) as cursor:
            row = await cursor.fetchone()
        return _task_row(row) if row is not None else None

    async def list_open_tasks(
        self, limit: int = 50, cursor: str | None = None
    ) -> tuple[list[dict], str | None]:
        """List non-terminal tasks ordered by ``updated_at`` descending (§9.5).

        Args:
            limit: Page size, clamped to ``1..200``.
            cursor: Opaque cursor: the ``updated_at`` value of the last item.

        Returns:
            ``(tasks, next_cursor)``.
        """
        db = self._conn()
        limit = max(1, min(200, int(limit)))
        placeholders = ",".join("?" for _ in OPEN_STATUSES)
        params: list[Any] = list(OPEN_STATUSES)
        sql = f"SELECT * FROM tasks WHERE status IN ({placeholders})"
        if cursor:
            try:
                sql += " AND updated_at < ?"
                params.append(float(cursor))
            except (TypeError, ValueError):
                pass
        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit + 1)
        async with db.execute(sql, params) as handle:
            rows = await handle.fetchall()
        items = [_task_row(row) for row in rows[:limit]]
        next_cursor = None
        if len(rows) > limit and items:
            next_cursor = f"{items[-1]['updated_at']:.6f}"
        return items, next_cursor

    async def list_tasks(
        self, limit: int = 20, cursor: str | None = None
    ) -> tuple[list[dict], str | None]:
        """List tasks of any status for the status page.

        Args:
            limit: Page size, clamped to ``1..200``.
            cursor: Opaque cursor (``updated_at`` of the last item).

        Returns:
            ``(tasks, next_cursor)``.
        """
        db = self._conn()
        limit = max(1, min(200, int(limit)))
        params: list[Any] = []
        sql = "SELECT * FROM tasks"
        if cursor:
            try:
                sql += " WHERE updated_at < ?"
                params.append(float(cursor))
            except (TypeError, ValueError):
                pass
        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit + 1)
        async with db.execute(sql, params) as handle:
            rows = await handle.fetchall()
        items = [_task_row(row) for row in rows[:limit]]
        next_cursor = (
            f"{items[-1]['updated_at']:.6f}" if len(rows) > limit and items else None
        )
        return items, next_cursor

    async def transition(
        self,
        task_id: str,
        to_status: str,
        *,
        eseq: int,
        result: dict | None = None,
        error: dict | None = None,
        needs_human: bool | None = None,
        eseq_strict: bool = True,
    ) -> dict:
        """Apply a status transition after validating it against §16.1.

        The row is written before the caller reports the change to the peer
        (§10.2 "persist, then report").

        Args:
            task_id: Task identifier.
            to_status: Target status.
            eseq: Event sequence number carried by this transition.
            result: Result object for terminal success.
            error: Error object for failure.
            needs_human: Explicit ``needs_human`` flag override.
            eseq_strict: When ``True`` (inbound events) an ``eseq`` that is not
                greater than the stored value is dropped.

        Returns:
            The updated task dictionary. When the transition is illegal or the event
            is stale, the unchanged task is returned and a warning is logged.

        Raises:
            BridgeError: ``task_not_found`` when the task does not exist.
        """
        db = self._conn()
        task = await self.get_task(task_id)
        if task is None:
            raise BridgeError(ERR_TASK_NOT_FOUND)
        current = task["status"]
        if current in TERMINAL_STATUSES:
            logger.warning(
                "bridge dropping transition for terminal task %s %s->%s",
                task_id,
                current,
                to_status,
            )
            return task
        if to_status != current:
            allowed = ALLOWED_TRANSITIONS.get(current, frozenset())
            if to_status not in allowed:
                # Outbound rows mirror a task owned by the peer. The peer's own
                # executor enforces the §16.1 table, and the mirror MUST follow
                # whatever it reports (an event can legitimately jump from
                # ``accepted`` straight to ``completed``). Terminal states are still
                # immutable in both directions.
                if task["direction"] == "outbound":
                    logger.info(
                        "bridge mirroring peer transition task=%s %s->%s",
                        task_id,
                        current,
                        to_status,
                    )
                else:
                    logger.warning(
                        "bridge illegal transition task=%s %s->%s",
                        task_id,
                        current,
                        to_status,
                    )
                    return task
        if eseq_strict and eseq and eseq <= int(task["eseq"]):
            logger.warning(
                "bridge dropping stale eseq task=%s eseq=%s<=%s",
                task_id,
                eseq,
                task["eseq"],
            )
            return task

        now = time.time()
        flag = task["needs_human"]
        if needs_human is not None:
            flag = 1 if needs_human else 0
        elif to_status is STATUS_NEEDS_HUMAN:
            flag = 1
        await db.execute(
            """
            UPDATE tasks SET status = ?, eseq = ?, result = COALESCE(?, result),
                             error = COALESCE(?, error), needs_human = ?, updated_at = ?
            WHERE task_id = ?
            """,
            (
                to_status,
                max(eseq, int(task["eseq"])),
                _json(result) if result is not None else None,
                _json(error) if error is not None else None,
                flag,
                now,
                task_id,
            ),
        )
        await db.commit()
        updated = await self.get_task(task_id)
        return updated or task

    async def advance_eseq(self, task_id: str, eseq: int) -> dict | None:
        """Persist an event sequence so later events cannot reuse it (§11.2).

        ``notify.emit`` reports the sequence it sends; persisting it here makes
        the task row the durable monotonic cursor. Without this an event emitted
        outside a status transition (for example a ``failed`` after a lost
        acknowledgement) would reuse the previous number and the peer would drop
        it as stale.

        Args:
            task_id: Task identifier.
            eseq: Sequence number of the event that is about to be sent.

        Returns:
            The updated task, or ``None`` when the task is unknown.
        """
        db = self._conn()
        stamp = time.time()
        await db.execute(
            "UPDATE tasks SET eseq = ?, updated_at = ? WHERE task_id = ? AND eseq < ?",
            (int(eseq), stamp, task_id, int(eseq)),
        )
        await db.commit()
        return await self.get_task(task_id)

    async def bump_attempts(self, task_id: str) -> dict | None:
        """Increment the attempt counter for a task.

        Args:
            task_id: Task identifier.

        Returns:
            The updated task, or ``None`` when unknown.
        """
        db = self._conn()
        await db.execute(
            "UPDATE tasks SET attempts = attempts + 1, updated_at = ? WHERE task_id = ?",
            (time.time(), task_id),
        )
        await db.commit()
        return await self.get_task(task_id)

    async def mark_needs_human(
        self, task_id: str, code: str, message: str
    ) -> dict | None:
        """Force a task into ``needs_human`` and record why (§16.2).

        Args:
            task_id: Task identifier.
            code: Error code explaining the uncertainty.
            message: Short English explanation.

        Returns:
            The updated task, or ``None`` when unknown.
        """
        db = self._conn()
        await db.execute(
            """
            UPDATE tasks SET status = ?, needs_human = 1, error = ?, updated_at = ?
            WHERE task_id = ? AND status != ?
            """,
            (
                STATUS_NEEDS_HUMAN,
                _json({"code": code, "message": message, "details": None}),
                time.time(),
                task_id,
                STATUS_REJECTED,
            ),
        )
        await db.commit()
        return await self.get_task(task_id)

    async def tasks_by_status(self, statuses: list[str]) -> list[dict]:
        """Return every task whose status is in ``statuses``.

        Args:
            statuses: Status values to match.

        Returns:
            Task dictionaries ordered by ``updated_at`` ascending.
        """
        if not statuses:
            return []
        db = self._conn()
        placeholders = ",".join("?" for _ in statuses)
        async with db.execute(
            f"SELECT * FROM tasks WHERE status IN ({placeholders})"
            " ORDER BY updated_at ASC",
            list(statuses),
        ) as cursor:
            rows = await cursor.fetchall()
        return [_task_row(row) for row in rows]

    # -- reply cache -------------------------------------------------------------------

    async def cache_reply(self, key: str, reply: dict, ttl_s: int = 86400) -> None:
        """Persist an idempotent reply for ``(conn, m, id)`` (§10.1).

        Args:
            key: Composite key ``"conn|message|id"``.
            reply: Reply object to store.
            ttl_s: Retention in seconds; expired rows are pruned opportunistically.
        """
        db = self._conn()
        now = time.time()
        await db.execute(
            "INSERT OR REPLACE INTO reply_cache (key, reply, created_at) VALUES (?,?,?)",
            (key, _json(reply), now),
        )
        await db.execute("DELETE FROM reply_cache WHERE created_at < ?", (now - ttl_s,))
        await db.commit()

    async def get_cached_reply(self, key: str) -> dict | None:
        """Fetch a persisted reply.

        Args:
            key: Composite key ``"conn|message|id"``.

        Returns:
            The stored reply object, or ``None``.
        """
        db = self._conn()
        async with db.execute(
            "SELECT reply FROM reply_cache WHERE key = ?", (key,)
        ) as cursor:
            row = await cursor.fetchone()
        return _unjson(row["reply"]) if row is not None else None

    # -- notification outbox ------------------------------------------------------------

    async def enqueue_notify(
        self,
        notify_id: str,
        task_id: str,
        root_task_id: str,
        message: str,
        params: dict,
        *,
        available_at: float | None = None,
    ) -> None:
        """Persist an outbound notification before sending it (§10.3).

        Args:
            notify_id: Unique notification id (dedupe key).
            task_id: Owning task.
            root_task_id: Root task for wake-chain accounting.
            message: Message name to emit (``task.event`` / ``approval.decision`` / …).
            params: Message parameters.
            available_at: Earliest send time; defaults to now.
        """
        db = self._conn()
        now = time.time()
        await db.execute(
            """
            INSERT OR IGNORE INTO notify_outbox
                (notify_id, task_id, root_task_id, message, params, attempts,
                 next_at, delivered, undelivered, created_at)
            VALUES (?,?,?,?,?,0,?,0,0,?)
            """,
            (
                notify_id,
                task_id,
                root_task_id,
                message,
                _json(params),
                available_at if available_at is not None else now,
                now,
            ),
        )
        await db.commit()

    async def mark_delivered(self, notify_id: str) -> None:
        """Mark a notification as acknowledged by the peer.

        Args:
            notify_id: Notification id.
        """
        db = self._conn()
        await db.execute(
            "UPDATE notify_outbox SET delivered = 1 WHERE notify_id = ?", (notify_id,)
        )
        await db.commit()

    async def mark_undelivered(self, notify_id: str) -> None:
        """Mark a notification as permanently undelivered (attempts exhausted).

        Args:
            notify_id: Notification id.
        """
        db = self._conn()
        await db.execute(
            "UPDATE notify_outbox SET undelivered = 1 WHERE notify_id = ?", (notify_id,)
        )
        await db.commit()

    async def pending_notifies(self, limit: int = 50) -> list[dict]:
        """Return notifications due for (re)delivery.

        Args:
            limit: Maximum number of rows.

        Returns:
            Outbox rows with ``params`` decoded.
        """
        db = self._conn()
        async with db.execute(
            """
            SELECT * FROM notify_outbox
            WHERE delivered = 0 AND undelivered = 0 AND next_at <= ?
            ORDER BY next_at ASC LIMIT ?
            """,
            (time.time(), limit),
        ) as cursor:
            rows = await cursor.fetchall()
        return [
            {
                "notify_id": row["notify_id"],
                "task_id": row["task_id"],
                "root_task_id": row["root_task_id"],
                "message": row["message"],
                "params": _unjson(row["params"], {}),
                "attempts": int(row["attempts"]),
            }
            for row in rows
        ]

    async def reschedule_notify(
        self, notify_id: str, attempts: int, next_at: float
    ) -> None:
        """Record a failed delivery attempt with its backoff.

        Args:
            notify_id: Notification id.
            attempts: Attempt count after this failure.
            next_at: Absolute time of the next attempt.
        """
        db = self._conn()
        await db.execute(
            "UPDATE notify_outbox SET attempts = ?, next_at = ? WHERE notify_id = ?",
            (attempts, next_at, notify_id),
        )
        await db.commit()

    async def get_notify(self, notify_id: str) -> dict | None:
        """Fetch one outbox row.

        Args:
            notify_id: Notification id.

        Returns:
            Row dictionary with decoded ``params``, or ``None``.
        """
        db = self._conn()
        async with db.execute(
            "SELECT * FROM notify_outbox WHERE notify_id = ?", (notify_id,)
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return None
        return {
            "notify_id": row["notify_id"],
            "task_id": row["task_id"],
            "root_task_id": row["root_task_id"],
            "message": row["message"],
            "params": _unjson(row["params"], {}),
            "attempts": int(row["attempts"]),
            "delivered": bool(row["delivered"]),
            "undelivered": bool(row["undelivered"]),
            "next_at": float(row["next_at"]),
        }

    async def record_inbound_notify(
        self, notify_id: str, task_id: str, eseq: int
    ) -> bool:
        """Record an inbound notification, returning whether it is new (§10.3).

        Args:
            notify_id: Notification id from the peer.
            task_id: Owning task.
            eseq: Event sequence carried by the notification.

        Returns:
            ``True`` when this is the first sighting, ``False`` for a duplicate.
        """
        db = self._conn()
        async with db.execute(
            "SELECT 1 FROM inbound_notify WHERE notify_id = ?", (notify_id,)
        ) as cursor:
            row = await cursor.fetchone()
        if row is not None:
            return False
        await db.execute(
            "INSERT INTO inbound_notify (notify_id, task_id, eseq, processed_at)"
            " VALUES (?,?,?,?)",
            (notify_id, task_id, int(eseq), time.time()),
        )
        await db.commit()
        return True

    # -- approvals ----------------------------------------------------------------------

    async def put_approval(self, approval: dict) -> dict:
        """Insert an approval, returning the existing row when it already exists (§12.2).

        Args:
            approval: Approval fields; requires ``approval_id``,
                ``approval_type``, ``request_digest``, ``origin_side``.

        Returns:
            Stored approval row with ``dedup`` set when it already existed.
        """
        db = self._conn()
        existing = await self.get_approval(approval["approval_id"])
        if existing is not None:
            return {**existing, "dedup": True}
        now = time.time()
        await db.execute(
            """
            INSERT INTO approvals (approval_id, approval_type, task_id, root_task_id,
                session_id, tool, reason, display_reason, call_id, request_digest,
                submit_digest, notify_id, origin_side, source, gate_scope, conn, sid,
                released_by_task, evidence, expires_at, state, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                approval["approval_id"],
                approval["approval_type"],
                approval.get("task_id"),
                approval.get("root_task_id"),
                approval.get("session_id"),
                approval.get("tool"),
                approval.get("reason", ""),
                _json(approval.get("display_reason", {})),
                approval.get("call_id"),
                approval["request_digest"],
                approval.get("submit_digest"),
                approval.get("notify_id"),
                approval["origin_side"],
                approval.get("source", "local"),
                approval.get("gate_scope", "inbound_release"),
                approval.get("conn"),
                approval.get("sid"),
                approval.get("released_by_task"),
                _json(approval["evidence"]) if approval.get("evidence") else None,
                float(approval["expires_at"]),
                "pending",
                now,
            ),
        )
        await db.commit()
        stored = await self.get_approval(approval["approval_id"])
        if stored is None:  # pragma: no cover - defensive
            raise BridgeError(ERR_TASK_NOT_FOUND)
        return {**stored, "dedup": False}

    async def get_approval(self, approval_id: str) -> dict | None:
        """Fetch one approval.

        Args:
            approval_id: Approval identifier.

        Returns:
            Approval dictionary, or ``None``.
        """
        db = self._conn()
        async with db.execute(
            "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
        ) as cursor:
            row = await cursor.fetchone()
        return _approval_row(row) if row is not None else None

    async def import_approval_mirror(self, approval: dict) -> dict | None:
        """Persist a trusted ``peer_lookup`` mirror, or enrich an existing peer mirror.

        A lookup result is only ever attached to a row that this endpoint did
        **not** open itself (``source != 'local'``): a local gate is the
        authority's own evidence and must never be rewritten from the wire.
        A missing row is inserted already decided; an existing peer mirror is
        upgraded with the authoritative ``submit_digest``/``conn``/``sid`` so
        the verifier can use it. Repeated lookups with different evidence are
        refused (``None``), never merged.

        Args:
            approval: Mirror fields, including ``evidence`` and the authoritative
                decision fields.

        Returns:
            The stored row, or ``None`` when an existing row cannot be enriched.
        """
        db = self._conn()
        approval_id = approval.get("approval_id")
        decided_at = approval.get("decided_at_epoch")
        expires_at = approval.get("expires_at")
        # A mirror is evidence, so it must be complete on its own: a valid human
        # actor and a finite decision timestamp. Falling back to "now" would turn
        # a missing `decided_at` into a fabricated decision time, which is exactly
        # the kind of evidence this contract refuses.
        if (
            not isinstance(approval_id, str)
            or not approval_id
            or approval.get("approval_type") != APPROVAL_CROSS_END_SUBMIT
            or not isinstance(approval.get("submit_digest"), str)
            or not approval["submit_digest"]
            or not isinstance(approval.get("origin_side"), str)
            or not approval["origin_side"]
            or approval.get("outcome") not in APPROVAL_OUTCOMES
            or not isinstance(approval.get("actor"), str)
            or not approval["actor"]
            or approval.get("actor_kind") != ACTOR_HUMAN
            or not isinstance(decided_at, (int, float))
            or isinstance(decided_at, bool)
            or not math.isfinite(decided_at)
            or decided_at <= 0
            or not isinstance(expires_at, (int, float))
            or isinstance(expires_at, bool)
            or not math.isfinite(expires_at)
            or expires_at <= 0
        ):
            return None

        existing = await self.get_approval(approval_id)
        if existing is not None:
            if existing.get("source") == "local":
                # A local gate is this endpoint's own authority; it is never
                # rewritten from a wire answer.
                return None
            # An old row (including a pre-amendment ``peer_request`` mirror) may
            # only be enriched when it still describes the same approval. Any
            # conflicting binding is refused rather than merged.
            for field in ("approval_type", "task_id", "root_task_id", "session_id"):
                current = existing.get(field)
                incoming = approval.get(field)
                if current is None or incoming is None:
                    continue
                if current != incoming:
                    return None
            current_digest = existing.get("submit_digest")
            if current_digest and current_digest != approval["submit_digest"]:
                return None
            current_request = existing.get("request_digest")
            incoming_request = approval.get("request_digest")
            if (
                current_request
                and incoming_request
                and current_request != incoming_request
            ):
                return None
            if existing.get("evidence"):
                # The mirror's authoritative evidence is also the fallback for
                # the redundant top-level session columns: a caller that only
                # carries the complete ``evidence`` object still describes the
                # same decision, and omitting a column must never be mistaken
                # for a different one.
                evidence_value = approval.get("evidence") or {}
                incoming_conn = approval.get("conn")
                if incoming_conn is None:
                    incoming_conn = evidence_value.get("conn")
                incoming_sid = approval.get("sid")
                if incoming_sid is None:
                    incoming_sid = evidence_value.get("sid")
                same = (
                    existing.get("submit_digest") == approval["submit_digest"]
                    and existing.get("outcome") == approval.get("outcome")
                    and existing.get("actor") == approval.get("actor")
                    and existing.get("actor_kind") == approval.get("actor_kind")
                    and existing.get("conn") == incoming_conn
                    and existing.get("sid") == incoming_sid
                    and existing.get("released_by_task")
                    == approval.get("released_by_task")
                    and existing.get("decided_at") == decided_at
                )
                if not same:
                    return None
                # Same authoritative evidence: refresh only the deadline (the
                # authority may extend it) and keep the receiver's consumption.
                await db.execute(
                    """
                    UPDATE approvals SET evidence = ?, expires_at = ?
                    WHERE approval_id = ? AND source != 'local'
                    """,
                    (
                        _json(approval.get("evidence") or {}),
                        float(expires_at),
                        approval_id,
                    ),
                )
                await db.commit()
                return await self.get_approval(approval_id)
            await db.execute(
                """
                UPDATE approvals SET source = 'peer_lookup', submit_digest = ?,
                    evidence = ?, conn = ?, sid = ?, state = 'decided', outcome = ?,
                    actor = ?, actor_kind = ?, channel = ?, decided_at = ?,
                    expires_at = ?, released_by_task = ?,
                    request_digest = CASE WHEN request_digest = '' THEN ? ELSE request_digest END
                WHERE approval_id = ? AND source != 'local'
                """,
                (
                    approval["submit_digest"],
                    _json(approval.get("evidence") or {}),
                    approval.get("conn"),
                    approval.get("sid"),
                    approval.get("outcome"),
                    approval.get("actor"),
                    approval.get("actor_kind"),
                    approval.get("channel"),
                    decided_at,
                    float(expires_at),
                    approval.get("released_by_task"),
                    approval.get("request_digest") or "",
                    approval_id,
                ),
            )
            await db.commit()
            return await self.get_approval(approval_id)
        now = time.time()
        await db.execute(
            """
            INSERT INTO approvals (approval_id, approval_type, task_id, root_task_id,
                session_id, tool, reason, display_reason, call_id, request_digest,
                submit_digest, notify_id, origin_side, source, gate_scope, conn, sid,
                released_by_task, evidence, expires_at, state, outcome, actor,
                actor_kind, channel, decided_reason, decided_at, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                approval_id,
                approval["approval_type"],
                approval.get("task_id"),
                approval.get("root_task_id"),
                approval.get("session_id"),
                approval.get("tool"),
                approval.get("reason", ""),
                _json(approval.get("display_reason", {})),
                approval.get("call_id"),
                approval.get("request_digest") or "",
                approval["submit_digest"],
                approval.get("notify_id"),
                approval["origin_side"],
                "peer_lookup",
                "inbound_release",
                approval.get("conn"),
                approval.get("sid"),
                approval.get("released_by_task"),
                _json(approval.get("evidence") or {}),
                float(expires_at),
                "decided",
                approval.get("outcome"),
                approval.get("actor"),
                approval.get("actor_kind"),
                approval.get("channel"),
                approval.get("decided_reason"),
                decided_at,
                now,
            ),
        )
        await db.commit()
        return await self.get_approval(approval_id)

    async def claim_approval_release(self, approval_id: str, task_id: str) -> bool:
        """Mark an initiating gate as released for exactly one submission (§12.7.4).

        This is the **initiator domain** counterpart of
        :meth:`claim_approval_consumption` (receiver domain). The conditional
        update is atomic, so two concurrent releases cannot both win.

        Args:
            approval_id: Approval identifier.
            task_id: Submission the gate is released for.

        Returns:
            ``True`` when this call recorded the release.
        """
        db = self._conn()
        cursor = await db.execute(
            """
            UPDATE approvals SET released_by_task = ?
            WHERE approval_id = ?
              AND (released_by_task IS NULL OR released_by_task = '')
            """,
            (task_id, approval_id),
        )
        await db.commit()
        return bool(cursor.rowcount)

    async def get_task_approval(
        self, task_id: str, approval_type: str | None = None
    ) -> dict | None:
        """Return the newest approval recorded for one task.

        Args:
            task_id: Owning task.
            approval_type: Optional approval type filter.

        Returns:
            The newest matching approval row, or ``None``.
        """
        db = self._conn()
        if approval_type is None:
            sql = "SELECT * FROM approvals WHERE task_id = ? ORDER BY created_at DESC LIMIT 1"
            args: tuple[Any, ...] = (task_id,)
        else:
            sql = (
                "SELECT * FROM approvals WHERE task_id = ? AND approval_type = ?"
                " ORDER BY created_at DESC LIMIT 1"
            )
            args = (task_id, approval_type)
        async with db.execute(sql, args) as cursor:
            row = await cursor.fetchone()
        return _approval_row(row) if row is not None else None

    async def list_approvals(
        self, state: str | None = None, limit: int = 50
    ) -> list[dict]:
        """List approvals, newest first.

        Args:
            state: Optional ``pending``/``decided`` filter.
            limit: Page size.

        Returns:
            Approval dictionaries.
        """
        db = self._conn()
        limit = max(1, min(200, int(limit)))
        if state:
            sql = "SELECT * FROM approvals WHERE state = ? ORDER BY created_at DESC LIMIT ?"
            params: list[Any] = [state, limit]
        else:
            sql = "SELECT * FROM approvals ORDER BY created_at DESC LIMIT ?"
            params = [limit]
        async with db.execute(sql, params) as cursor:
            rows = await cursor.fetchall()
        return [_approval_row(row) for row in rows]

    async def decide_approval(
        self,
        approval_id: str,
        decision: dict,
        *,
        conn: str | None = None,
        sid: str | None = None,
    ) -> tuple[bool, str | None]:
        """Apply the first decision for an approval; later ones are ignored (§12.4).

        Args:
            approval_id: Approval identifier.
            decision: ``{"outcome", "actor", "actor_kind", "channel", "reason"}``.
            conn: Authenticated connection the answer arrived on (evidence, §12.7).
            sid: Authenticated session id the answer arrived on (evidence, §12.7).

        Returns:
            ``(applied, reason)`` where ``reason`` is ``None`` on success or one of
            ``already_decided`` / ``expired`` / ``not_found``.
        """
        db = self._conn()
        approval = await self.get_approval(approval_id)
        if approval is None:
            return False, "not_found"
        # The expiry condition and the ``pending`` latch are part of the
        # conditional update, not a pre-check: an approval that expires between
        # the read and the write must lose to ``expire_approvals`` and can never
        # become a grant. The post-update read below distinguishes a human loser
        # from a timeout loser.
        stamp = time.time()
        cursor = await db.execute(
            """
            UPDATE approvals SET state = 'decided', outcome = ?, actor = ?, actor_kind = ?,
                channel = ?, decided_reason = ?, decided_at = ?,
                conn = COALESCE(?, conn), sid = COALESCE(?, sid)
            WHERE approval_id = ? AND state = 'pending' AND expires_at > ?
            """,
            (
                decision["outcome"],
                decision.get("actor"),
                decision.get("actor_kind"),
                decision.get("channel"),
                decision.get("reason"),
                stamp,
                conn,
                sid,
                approval_id,
                stamp,
            ),
        )
        applied = bool(cursor.rowcount)
        await db.commit()
        if applied:
            return True, None
        updated = await self.get_approval(approval_id)
        if updated is None:
            return False, "not_found"
        if updated["state"] != "pending":
            # A row already finalised by the timeout sweep is reported as
            # ``expired`` (the human answer lost to the deadline), while a row
            # another human settled stays ``already_decided``.
            if updated.get("channel") == "timeout":
                return False, "expired"
            return False, "already_decided"
        # Still pending but the conditional update did not match: the only other
        # clause that can fail is the deadline.
        return False, "expired"

    async def claim_approval_consumption(self, approval_id: str, task_id: str) -> bool:
        """Consume an approval exactly once, for exactly one task (§12.1).

        The update is conditional on ``consumed_by_task`` still being empty, so two
        concurrent submissions cannot both win. A replay by the same task is *not*
        silently accepted here: the caller already proved the content digest, and
        this method reports the durable winner so the caller can refuse a second
        task without guessing.

        Args:
            approval_id: Approval identifier.
            task_id: Task claiming the approval.

        Returns:
            ``True`` when this call recorded the consumption, ``False`` when the
            approval was already consumed (by this task or another one).
        """
        db = self._conn()
        cursor = await db.execute(
            """
            UPDATE approvals SET consumed_by_task = ?, consumed_at = ?
            WHERE approval_id = ? AND (consumed_by_task IS NULL OR consumed_by_task = '')
            """,
            (task_id, time.time(), approval_id),
        )
        await db.commit()
        return bool(cursor.rowcount)

    async def expire_approvals(self, now: float | None = None) -> list[dict]:
        """Mark overdue pending approvals as rejected-by-timeout (§12.4).

        Args:
            now: Override for the current time (tests).

        Returns:
            The approvals that were expired by this call.
        """
        db = self._conn()
        stamp = time.time() if now is None else now
        async with db.execute(
            "SELECT * FROM approvals WHERE state = 'pending' AND expires_at <= ?",
            (stamp,),
        ) as cursor:
            rows = await cursor.fetchall()
        # Only the rows this call actually finalises are reported as expired.
        # A concurrent human decision (or a mirror enrichment that moved the
        # deadline) can win the conditional update; returning it as expired
        # would make the caller emit a timeout for an approval it never closed.
        expired: list[dict] = []
        for row in rows:
            approval = _approval_row(row)
            cursor = await db.execute(
                """
                UPDATE approvals SET state = 'decided', outcome = 'rejected',
                    actor = 'system', actor_kind = 'system', channel = 'timeout',
                    decided_reason = 'timeout', decided_at = ?
                WHERE approval_id = ? AND state = 'pending' AND expires_at <= ?
                """,
                (stamp, approval["approval_id"], stamp),
            )
            if cursor.rowcount:
                expired.append(approval)
        if expired:
            await db.commit()
        return expired

    async def invalidate_pending_approvals(
        self,
        approval_type: str | list[str] | tuple[str, ...] | None = None,
        *,
        reason: str = "unavailable",
    ) -> list[str]:
        """Finalise still-pending approvals as ``unavailable`` (local bookkeeping only).

        Used for approvals whose answer channel is gone: on process start and when
        a new ``sid`` appears on the same connection, the pending promise of the
        producing side no longer exists, so the only correct terminal state is
        ``unavailable`` (never a grant, never a fresh prompt). This touches only local
        rows: no wire field, no AAD, no protocol change, and no ``approval.decision``
        is emitted for the affected ids.

        Args:
            approval_type: Restrict to one ``approval_type`` or a collection of
                them; ``None`` means every pending approval.
            reason: ``decided_reason`` recorded on each row.

        Returns:
            The ``approval_id`` values that were actually invalidated.
        """
        db = self._conn()
        stamp = time.time()
        if approval_type is None:
            sql = "SELECT * FROM approvals WHERE state = 'pending'"
            args: tuple[Any, ...] = ()
        else:
            types = (
                [approval_type]
                if isinstance(approval_type, str)
                else list(approval_type)
            )
            placeholders = ",".join("?" for _ in types)
            sql = (
                "SELECT * FROM approvals WHERE state = 'pending'"
                f" AND approval_type IN ({placeholders})"
            )
            args = tuple(types)
        async with db.execute(sql, args) as cursor:
            rows = await cursor.fetchall()
        invalidated: list[str] = []
        for row in rows:
            cursor = await db.execute(
                """
                UPDATE approvals SET state = 'decided', outcome = ?,
                    actor = 'system', actor_kind = 'system', channel = ?,
                    decided_reason = ?, decided_at = ?
                WHERE approval_id = ? AND state = 'pending'
                """,
                (
                    OUTCOME_UNAVAILABLE,
                    OUTCOME_UNAVAILABLE,
                    reason,
                    stamp,
                    row["approval_id"],
                ),
            )
            if cursor.rowcount:
                invalidated.append(row["approval_id"])
        if invalidated:
            await db.commit()
        return invalidated

    # -- decisions ----------------------------------------------------------------------

    async def put_decision(self, decision: dict) -> dict:
        """Insert a pending business decision.

        Args:
            decision: Decision fields; requires ``decision_id``, ``task_id``,
                ``root_task_id``, ``question``, ``expires_at``.

        Returns:
            Stored decision row with ``dedup`` when it already existed.
        """
        db = self._conn()
        existing = await self.get_decision(decision["decision_id"])
        if existing is not None:
            return {**existing, "dedup": True}
        now = time.time()
        await db.execute(
            """
            INSERT INTO decisions (decision_id, task_id, root_task_id, question, options,
                allow_free_text, default_option, expires_at, notify_id, state, created_at)
            VALUES (?,?,?,?,?,?,?,?,?, 'pending', ?)
            """,
            (
                decision["decision_id"],
                decision["task_id"],
                decision["root_task_id"],
                decision["question"],
                _json(decision.get("options", [])),
                1 if decision.get("allow_free_text") else 0,
                decision.get("default_option"),
                float(decision["expires_at"]),
                decision.get("notify_id"),
                now,
            ),
        )
        await db.commit()
        stored = await self.get_decision(decision["decision_id"])
        if stored is None:  # pragma: no cover - defensive
            raise BridgeError(ERR_TASK_NOT_FOUND)
        return {**stored, "dedup": False}

    async def get_decision(self, decision_id: str) -> dict | None:
        """Fetch one decision.

        Args:
            decision_id: Decision identifier.

        Returns:
            Decision dictionary, or ``None``.
        """
        db = self._conn()
        async with db.execute(
            "SELECT * FROM decisions WHERE decision_id = ?", (decision_id,)
        ) as cursor:
            row = await cursor.fetchone()
        return _decision_row(row) if row is not None else None

    async def list_decisions(
        self, state: str | None = None, limit: int = 50
    ) -> list[dict]:
        """List decisions, newest first.

        Args:
            state: Optional ``pending``/``answered`` filter.
            limit: Page size.

        Returns:
            Decision dictionaries.
        """
        db = self._conn()
        limit = max(1, min(200, int(limit)))
        if state:
            sql = "SELECT * FROM decisions WHERE state = ? ORDER BY created_at DESC LIMIT ?"
            params: list[Any] = [state, limit]
        else:
            sql = "SELECT * FROM decisions ORDER BY created_at DESC LIMIT ?"
            params = [limit]
        async with db.execute(sql, params) as cursor:
            rows = await cursor.fetchall()
        return [_decision_row(row) for row in rows]

    async def answer_decision(
        self, decision_id: str, answer: dict
    ) -> tuple[bool, str | None]:
        """Apply the first answer for a decision (§9.8).

        Args:
            decision_id: Decision identifier.
            answer: ``{"choice", "free_text", "actor", "actor_kind"}``.

        Returns:
            ``(applied, reason)``; ``reason`` is ``already_answered``, ``expired`` or
            ``not_found`` when the answer did not take effect.
        """
        db = self._conn()
        # Same single-statement discipline as ``decide_approval``: the first
        # answer is the one whose conditional UPDATE matches, and the deadline is
        # part of that predicate so an answer that arrives after expiry can never
        # win the race against the timeout path.
        stamp = time.time()
        cursor = await db.execute(
            """
            UPDATE decisions SET state = 'answered', choice = ?, free_text = ?,
                actor = ?, actor_kind = ?, answered_at = ?
            WHERE decision_id = ? AND state = 'pending' AND expires_at > ?
            """,
            (
                answer.get("choice"),
                answer.get("free_text"),
                answer.get("actor"),
                answer.get("actor_kind"),
                stamp,
                decision_id,
                stamp,
            ),
        )
        applied = bool(cursor.rowcount)
        await db.commit()
        if applied:
            return True, None
        decision = await self.get_decision(decision_id)
        if decision is None:
            return False, "not_found"
        if decision["state"] == "expired":
            return False, "expired"
        if decision["state"] != "pending":
            return False, "already_answered"
        # The row is still pending, so the deadline clause is what made this late
        # answer lose. Do NOT mark it expired here: ``expire_decisions`` only scans
        # pending rows, and the timeout callback would then never fire. Leaving the
        # row pending makes the sweep the single claimant of the timeout outcome.
        return False, "expired"

    async def expire_decisions(self, now: float | None = None) -> list[dict]:
        """Claim and return pending decisions past their deadline (§9.8).

        The conditional update makes the winner durable as ``state='expired'``
        before the caller reports the timeout once. A second sweep (or a late
        human answer) can no longer claim the same row.

        Args:
            now: Override for the current time (tests).

        Returns:
            Overdue decisions.
        """
        db = self._conn()
        stamp = time.time() if now is None else now
        async with db.execute(
            "SELECT * FROM decisions WHERE state = 'pending' AND expires_at <= ?",
            (stamp,),
        ) as cursor:
            rows = await cursor.fetchall()
        # Claim the expiry atomically, exactly like ``expire_approvals``. The
        # caller reports the timeout once; returning a row that another sweep
        # already claimed would report it twice, and leaving it ``pending`` would
        # let a late human answer win after timeout.
        expired: list[dict] = []
        for row in rows:
            decision = _decision_row(row)
            cursor = await db.execute(
                """
                UPDATE decisions SET state = 'expired'
                WHERE decision_id = ? AND state = 'pending' AND expires_at <= ?
                """,
                (decision["decision_id"], stamp),
            )
            if cursor.rowcount:
                expired.append(decision)
        if expired:
            await db.commit()
        return expired

    # -- session authorization ----------------------------------------------------------

    async def authz_snapshot(self) -> dict:
        """Return the authoritative authorization table (§9.7).

        The three reads (meta, grants, revoked) run inside one transaction so a
        concurrent grant/revoke can never yield a version from one state and a
        grant list from another. ``BEGIN IMMEDIATE`` takes the write lock before
        the first read; when an implicit write transaction is already open on the
        same connection, the reads join it and its owner still commits.

        Returns:
            ``{"version", "instance_id", "instance_started_at", "grants",
            "revoked", "allow_agent_create", "max_agent_sessions"}``.
        """
        db = self._conn()
        started = not db.in_transaction
        if started:
            await db.execute("BEGIN IMMEDIATE")
        try:
            async with db.execute("SELECT * FROM authz_meta WHERE id = 1") as cursor:
                meta = await cursor.fetchone()
            async with db.execute(
                "SELECT * FROM session_grants WHERE revoked = 0 ORDER BY created_at ASC"
            ) as cursor:
                rows = await cursor.fetchall()
            async with db.execute(
                "SELECT session_id FROM session_grants WHERE revoked = 1"
            ) as cursor:
                revoked_rows = await cursor.fetchall()
        finally:
            if started:
                await db.commit()
        return {
            "version": int(meta["version"]) if meta is not None else 0,
            "instance_id": (meta["instance_id"] or None) if meta is not None else None,
            "instance_started_at": (
                int(meta["instance_started_at"])
                if meta is not None and meta["instance_started_at"] is not None
                else None
            ),
            "grants": [_grant_payload(row) for row in rows],
            "revoked": [row["session_id"] for row in revoked_rows],
            "allow_agent_create": bool(meta["allow_agent_create"]) if meta else True,
            "max_agent_sessions": int(meta["max_agent_sessions"]) if meta else 10,
        }

    async def bump_authz_version(self) -> int:
        """Increment and persist the authorization version (§9.7).

        Exposed for callers that must force a strictly higher version before
        re-sending the authoritative snapshot, for example the audit ``fix``.

        Returns:
            The new monotonically increasing version.
        """
        return await self._bump_authz_version()

    async def _bump_authz_version(self) -> int:
        """Increment and persist the authorization version.

        Returns:
            The new monotonically increasing version.
        """
        db = self._conn()
        await db.execute("UPDATE authz_meta SET version = version + 1 WHERE id = 1")
        await db.commit()
        async with db.execute("SELECT version FROM authz_meta WHERE id = 1") as cursor:
            row = await cursor.fetchone()
        return int(row["version"]) if row is not None else 0

    async def raise_authz_version_floor(self, minimum: int) -> int:
        """Raise the authorization counter to at least ``minimum``.

        A peer-side create advances the peer's cached table by one and the peer
        ignores any later ``session.authz`` push that is not strictly higher
        (§9.7). Adopting the version returned by the create reply before the
        local grant bump therefore keeps this endpoint's authoritative pushes
        (including revokes) acceptable. The counter is only ever raised.

        Args:
            minimum: Lowest version the local counter must reach.

        Returns:
            The resulting authorization version.
        """
        db = self._conn()
        await db.execute(
            "UPDATE authz_meta SET version = ? WHERE id = 1 AND version < ?",
            (int(minimum), int(minimum)),
        )
        await db.commit()
        async with db.execute("SELECT version FROM authz_meta WHERE id = 1") as cursor:
            row = await cursor.fetchone()
        return int(row["version"]) if row is not None else 0

    async def set_agent_create_policy(self, allow: bool, max_sessions: int) -> int:
        """Update the agent session-creation policy and bump the version.

        Args:
            allow: Whether agents may create sessions at all.
            max_sessions: Quota for agent-created sessions.

        Returns:
            The new authorization version.
        """
        db = self._conn()
        await db.execute(
            "UPDATE authz_meta SET allow_agent_create = ?, max_agent_sessions = ? WHERE id = 1",
            (1 if allow else 0, max(0, int(max_sessions))),
        )
        await db.commit()
        return await self._bump_authz_version()

    async def grant_session(self, grant: dict) -> int:
        """Authorize one session, returning the new version (§9.7).

        Args:
            grant: Grant fields; requires ``session_id``, ``granted_by``,
                ``granted_by_id``.

        Returns:
            The new authorization version.

        Raises:
            BridgeError: ``session_quota_exceeded`` when an agent-created grant would
                exceed the configured quota.
        """
        db = self._conn()
        now = time.time()
        existing = await self.get_grant(grant["session_id"])
        if existing is None and grant.get("granted_by") == "agent_auto":
            async with db.execute(
                "SELECT COUNT(*) AS n FROM session_grants"
                " WHERE granted_by = 'agent_auto' AND revoked = 0"
            ) as cursor:
                row = await cursor.fetchone()
            async with db.execute(
                "SELECT max_agent_sessions FROM authz_meta WHERE id = 1"
            ) as cursor:
                meta = await cursor.fetchone()
            quota = int(meta["max_agent_sessions"]) if meta is not None else 10
            if int(row["n"]) >= quota:
                raise BridgeError("session_quota_exceeded")
        await db.execute(
            """
            INSERT INTO session_grants (session_id, purpose, title, state, granted_by,
                granted_by_id, expires_at, created_by_task, revoked, archived,
                created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,0,0,?,?)
            ON CONFLICT(session_id) DO UPDATE SET
                purpose = excluded.purpose, title = excluded.title,
                granted_by = excluded.granted_by,
                granted_by_id = excluded.granted_by_id,
                expires_at = excluded.expires_at, revoked = 0,
                updated_at = excluded.updated_at
            """,
            (
                grant["session_id"],
                grant.get("purpose", ""),
                grant.get("title", ""),
                grant.get("state", "idle"),
                grant["granted_by"],
                grant["granted_by_id"],
                grant.get("expires_at"),
                grant.get("created_by_task"),
                now,
                now,
            ),
        )
        await db.commit()
        return await self._bump_authz_version()

    async def revoke_session(self, session_id: str) -> int:
        """Revoke one session authorization, returning the new version.

        Args:
            session_id: Session to revoke.

        Returns:
            The new authorization version.
        """
        db = self._conn()
        await db.execute(
            "UPDATE session_grants SET revoked = 1, updated_at = ? WHERE session_id = ?",
            (time.time(), session_id),
        )
        await db.commit()
        return await self._bump_authz_version()

    async def revoke_agent_sessions(self, granted_by_id: str | None = None) -> int:
        """Revoke every agent-created grant, optionally scoped to one connection.

        Args:
            granted_by_id: Only revoke grants whose ``granted_by_id`` starts with
                this value (used for "reclaim for one connection").

        Returns:
            The new authorization version.
        """
        db = self._conn()
        now = time.time()
        if granted_by_id:
            await db.execute(
                "UPDATE session_grants SET revoked = 1, updated_at = ?"
                " WHERE granted_by = 'agent_auto' AND revoked = 0"
                " AND granted_by_id LIKE ?",
                (now, f"{granted_by_id}%"),
            )
        else:
            await db.execute(
                "UPDATE session_grants SET revoked = 1, updated_at = ?"
                " WHERE granted_by = 'agent_auto' AND revoked = 0",
                (now,),
            )
        await db.commit()
        return await self._bump_authz_version()

    async def get_grant(self, session_id: str) -> dict | None:
        """Fetch one session grant.

        Args:
            session_id: Session identifier.

        Returns:
            Grant dictionary, or ``None``.
        """
        db = self._conn()
        async with db.execute(
            "SELECT * FROM session_grants WHERE session_id = ?", (session_id,)
        ) as cursor:
            row = await cursor.fetchone()
        return _grant_row(row) if row is not None else None

    async def list_grants(self, include_revoked: bool = False) -> list[dict]:
        """List session grants.

        Args:
            include_revoked: Whether revoked grants are returned too.

        Returns:
            Grant dictionaries ordered by creation time.
        """
        db = self._conn()
        sql = "SELECT * FROM session_grants"
        if not include_revoked:
            sql += " WHERE revoked = 0"
        sql += " ORDER BY created_at ASC"
        async with db.execute(sql) as cursor:
            rows = await cursor.fetchall()
        return [_grant_row(row) for row in rows]

    async def is_authorized(self, session_id: str) -> bool:
        """Whether a session is currently authorized for agent use (§9.7).

        Args:
            session_id: Session identifier.

        Returns:
            ``True`` when a non-revoked, non-expired grant exists.
        """
        grant = await self.get_grant(session_id)
        if grant is None or grant["revoked"]:
            return False
        expires_at = grant["expires_at"]
        if expires_at is not None and expires_at <= time.time():
            return False
        return True

    async def record_session_create_request(
        self, request_id: str, session_id: str
    ) -> str:
        """Bind a ``session.create`` idempotency key to its session (§9.7).

        Args:
            request_id: Client-provided idempotency key.
            session_id: Session created for that key.

        Returns:
            The session id bound to ``request_id`` (the existing one on replay).
        """
        db = self._conn()
        async with db.execute(
            "SELECT session_id FROM session_create_requests WHERE request_id = ?",
            (request_id,),
        ) as cursor:
            row = await cursor.fetchone()
        if row is not None:
            return str(row["session_id"])
        await db.execute(
            "INSERT INTO session_create_requests (request_id, session_id, created_at)"
            " VALUES (?,?,?)",
            (request_id, session_id, time.time()),
        )
        await db.commit()
        return session_id

    async def lookup_session_create_request(self, request_id: str) -> str | None:
        """Return the session previously bound to a ``session.create`` request (§9.7).

        Args:
            request_id: Client-provided idempotency key.

        Returns:
            The bound session id, or ``None`` when the key is unused.
        """
        db = self._conn()
        async with db.execute(
            "SELECT session_id FROM session_create_requests WHERE request_id = ?",
            (request_id,),
        ) as cursor:
            row = await cursor.fetchone()
        if row is None or not row["session_id"]:
            return None
        return str(row["session_id"])

    async def set_grant_title(self, session_id: str, title: str) -> None:
        """Rename a granted session (§9.7 ``session.manage`` rename).

        Args:
            session_id: Session identifier.
            title: New human-readable title.
        """
        db = self._conn()
        await db.execute(
            "UPDATE session_grants SET title = ?, updated_at = ? WHERE session_id = ?",
            (title, time.time(), session_id),
        )
        await db.commit()

    async def archive_grant(self, session_id: str) -> None:
        """Archive a granted session (§9.7 ``session.manage`` archive).

        Args:
            session_id: Session identifier.
        """
        db = self._conn()
        await db.execute(
            "UPDATE session_grants SET archived = 1, state = 'cold', updated_at = ?"
            " WHERE session_id = ?",
            (time.time(), session_id),
        )
        await db.commit()

    # -- wake accounting ----------------------------------------------------------------

    async def wake_chain_count(self, root_task_id: str) -> int:
        """Return how many automatic wakes this root task has consumed (§16.6).

        Args:
            root_task_id: Root task identifier.

        Returns:
            The persisted counter.
        """
        db = self._conn()
        async with db.execute(
            "SELECT count FROM wake_chain WHERE root_task_id = ?", (root_task_id,)
        ) as cursor:
            row = await cursor.fetchone()
        return int(row["count"]) if row is not None else 0

    async def bump_wake(self, root_task_id: str) -> int:
        """Increment the wake-chain counter for a root task.

        Args:
            root_task_id: Root task identifier.

        Returns:
            The counter value after incrementing.
        """
        db = self._conn()
        now = time.time()
        await db.execute(
            """
            INSERT INTO wake_chain (root_task_id, count, updated_at) VALUES (?, 1, ?)
            ON CONFLICT(root_task_id) DO UPDATE SET
                count = count + 1, updated_at = excluded.updated_at
            """,
            (root_task_id, now),
        )
        await db.commit()
        return await self.wake_chain_count(root_task_id)

    async def wake_rate_hit(
        self, session_key: str, limit: int, window_s: int = 60
    ) -> bool:
        """Record one wake attempt in a sliding window (§16.6).

        Args:
            session_key: Connection/session key used for the rate window.
            limit: Allowed wakes per window.
            window_s: Window length in seconds.

        Returns:
            ``True`` when the attempt is within the limit, ``False`` when limited.
        """
        db = self._conn()
        now = time.time()
        async with db.execute(
            "SELECT window FROM wake_rate WHERE session_key = ?", (session_key,)
        ) as cursor:
            row = await cursor.fetchone()
        stamps: list[float] = _unjson(row["window"], []) if row is not None else []
        stamps = [stamp for stamp in stamps if now - stamp < window_s]
        if len(stamps) >= limit:
            await db.execute(
                "INSERT OR REPLACE INTO wake_rate (session_key, window, updated_at)"
                " VALUES (?,?,?)",
                (session_key, _json(stamps), now),
            )
            await db.commit()
            return False
        stamps.append(now)
        await db.execute(
            "INSERT OR REPLACE INTO wake_rate (session_key, window, updated_at) VALUES (?,?,?)",
            (session_key, _json(stamps), now),
        )
        await db.commit()
        return True

    async def wake_already_delivered(self, task_id: str, event_type: str) -> bool:
        """Whether this ``(task_id, event_type)`` wake already happened (§10.3).

        Args:
            task_id: Task identifier.
            event_type: Event name such as ``completed``.

        Returns:
            ``True`` when a wake was already delivered for that pair.
        """
        db = self._conn()
        async with db.execute(
            "SELECT 1 FROM wake_dedupe WHERE task_id = ? AND event_type = ?",
            (task_id, event_type),
        ) as cursor:
            row = await cursor.fetchone()
        return row is not None

    async def mark_wake_delivered(self, task_id: str, event_type: str) -> None:
        """Record that a wake was delivered for ``(task_id, event_type)``.

        Args:
            task_id: Task identifier.
            event_type: Event name.
        """
        db = self._conn()
        await db.execute(
            "INSERT OR REPLACE INTO wake_dedupe (task_id, event_type, stamp) VALUES (?,?,?)",
            (task_id, event_type, time.time()),
        )
        await db.commit()

    # -- poll nonce replay ---------------------------------------------------------------

    async def remember_poll_nonce(
        self, sid: str, side: str, nonce: str, ttl_s: int = 300
    ) -> bool:
        """Record a poll nonce, returning whether it is fresh (§7.4).

        Args:
            sid: Session id the poll belongs to.
            side: Requesting side.
            nonce: Base64url nonce.
            ttl_s: Retention for replay detection.

        Returns:
            ``True`` when the nonce is new, ``False`` on replay.
        """
        db = self._conn()
        now = time.time()
        await db.execute("DELETE FROM poll_nonces WHERE stamp < ?", (now - ttl_s,))
        async with db.execute(
            "SELECT 1 FROM poll_nonces WHERE sid = ? AND side = ? AND nonce = ?",
            (sid, side, nonce),
        ) as cursor:
            row = await cursor.fetchone()
        if row is not None:
            await db.commit()
            return False
        await db.execute(
            "INSERT INTO poll_nonces (sid, side, nonce, stamp) VALUES (?,?,?,?)",
            (sid, side, nonce, now),
        )
        await db.commit()
        return True

    # -- maintenance --------------------------------------------------------------------

    async def cleanup_expired(self, retention_days: int) -> int:
        """Delete rows older than the retention window (§10.1).

        Args:
            retention_days: Retention in days.

        Returns:
            Number of deleted task rows.
        """
        db = self._conn()
        cutoff = time.time() - max(1, int(retention_days)) * 86400
        async with db.execute(
            "SELECT COUNT(*) AS n FROM tasks WHERE updated_at < ?", (cutoff,)
        ) as cursor:
            row = await cursor.fetchone()
        removed = int(row["n"]) if row is not None else 0
        await db.execute("DELETE FROM tasks WHERE updated_at < ?", (cutoff,))
        await db.execute("DELETE FROM reply_cache WHERE created_at < ?", (cutoff,))
        await db.execute("DELETE FROM inbound_notify WHERE processed_at < ?", (cutoff,))
        await db.execute(
            "DELETE FROM notify_outbox WHERE delivered = 1 AND created_at < ?",
            (cutoff,),
        )
        await db.execute(
            "DELETE FROM approvals WHERE decided_at IS NOT NULL AND decided_at < ?",
            (cutoff,),
        )
        await db.execute("DELETE FROM wake_dedupe WHERE stamp < ?", (cutoff,))
        await db.commit()
        return removed


def _task_row(row: aiosqlite.Row) -> dict:
    """Convert a task row into a plain dictionary.

    Args:
        row: SQLite row.

    Returns:
        Task dictionary with decoded JSON fields.
    """
    return {
        "task_id": row["task_id"],
        "root_task_id": row["root_task_id"],
        "direction": row["direction"],
        "kind": row["kind"],
        "origin": row["origin"],
        "status": row["status"],
        "eseq": int(row["eseq"]),
        "attempts": int(row["attempts"]),
        "session_id": row["session_id"],
        "purpose": row["purpose"],
        "submit_digest": row["submit_digest"],
        "request_hash": row["request_hash"],
        "payload": _unjson(row["payload"], {}),
        "result": _unjson(row["result"]),
        "error": _unjson(row["error"]),
        "needs_human": bool(row["needs_human"]),
        "created_at": float(row["created_at"]),
        "updated_at": float(row["updated_at"]),
    }


def _approval_row(row: aiosqlite.Row) -> dict:
    """Convert an approval row into a plain dictionary.

    Args:
        row: SQLite row.

    Returns:
        Approval dictionary with decoded JSON fields.
    """
    return {
        "approval_id": row["approval_id"],
        "approval_type": row["approval_type"],
        "task_id": row["task_id"],
        "root_task_id": row["root_task_id"],
        "session_id": row["session_id"],
        "tool": row["tool"],
        "reason": row["reason"],
        "display_reason": _unjson(row["display_reason"], {}),
        "call_id": row["call_id"],
        "request_digest": row["request_digest"],
        "submit_digest": row["submit_digest"],
        "notify_id": row["notify_id"],
        "origin_side": row["origin_side"],
        "source": row["source"] if "source" in row.keys() else "local",
        "gate_scope": row["gate_scope"]
        if "gate_scope" in row.keys()
        else "inbound_release",
        "conn": row["conn"] if "conn" in row.keys() else None,
        "sid": row["sid"] if "sid" in row.keys() else None,
        "released_by_task": row["released_by_task"]
        if "released_by_task" in row.keys()
        else None,
        "evidence": _unjson(row["evidence"], {})
        if "evidence" in row.keys() and row["evidence"]
        else None,
        "expires_at": float(row["expires_at"]),
        "state": row["state"],
        "outcome": row["outcome"],
        "actor": row["actor"],
        "actor_kind": row["actor_kind"],
        "channel": row["channel"],
        "decided_reason": row["decided_reason"],
        "decided_at": float(row["decided_at"]) if row["decided_at"] else None,
        "consumed_by_task": row["consumed_by_task"],
        "consumed_at": float(row["consumed_at"]) if row["consumed_at"] else None,
        "created_at": float(row["created_at"]),
    }


def _decision_row(row: aiosqlite.Row) -> dict:
    """Convert a decision row into a plain dictionary.

    Args:
        row: SQLite row.

    Returns:
        Decision dictionary with decoded JSON fields.
    """
    return {
        "decision_id": row["decision_id"],
        "task_id": row["task_id"],
        "root_task_id": row["root_task_id"],
        "question": row["question"],
        "options": _unjson(row["options"], []),
        "allow_free_text": bool(row["allow_free_text"]),
        "default_option": row["default_option"],
        "expires_at": float(row["expires_at"]),
        "notify_id": row["notify_id"],
        "state": row["state"],
        "choice": row["choice"],
        "free_text": row["free_text"],
        "actor": row["actor"],
        "actor_kind": row["actor_kind"],
        "answered_at": float(row["answered_at"]) if row["answered_at"] else None,
        "created_at": float(row["created_at"]),
    }


def _grant_row(row: aiosqlite.Row) -> dict:
    """Convert a session grant row into a plain dictionary.

    Args:
        row: SQLite row.

    Returns:
        Grant dictionary.
    """
    return {
        "session_id": row["session_id"],
        "purpose": row["purpose"],
        "title": row["title"],
        "state": row["state"],
        "granted_by": row["granted_by"],
        "granted_by_id": row["granted_by_id"],
        "expires_at": float(row["expires_at"]) if row["expires_at"] else None,
        "created_by_task": row["created_by_task"],
        "revoked": bool(row["revoked"]),
        "archived": bool(row["archived"]),
        "created_at": float(row["created_at"]),
        "updated_at": float(row["updated_at"]),
    }


def _grant_payload(row: aiosqlite.Row) -> dict:
    """Render one grant in the ``session.authz`` wire shape (§9.7).

    Args:
        row: SQLite row.

    Returns:
        Wire-shaped grant object.
    """
    grant = _grant_row(row)
    return {
        "session_id": grant["session_id"],
        "purpose": grant["purpose"],
        "title": grant["title"],
        "state": grant["state"],
        "granted_by": grant["granted_by"],
        "granted_by_id": grant["granted_by_id"],
        "expires_at": grant["expires_at"],
        "created_by_task": grant["created_by_task"],
    }


def task_request_hash(params: dict) -> str:
    """Hash the idempotency-relevant fields of a submission (§9.3).

    Two submits with the same ``task_id`` but different content must raise
    ``task_exists`` instead of silently returning the first result.

    Args:
        params: ``task.submit`` parameters.

    Returns:
        Hex SHA-256 of the canonical projection.
    """
    import hashlib

    from .crypto import jcs_frame

    projection = {
        "kind": params.get("kind"),
        "origin": params.get("origin"),
        "input_parts": params.get("input_parts", []),
        "attachments": [
            {
                "kind": item.get("kind"),
                "blob_id": item.get("blob_id"),
                "media_type": item.get("media_type"),
                "bytes": item.get("bytes"),
                "sha256": item.get("sha256"),
            }
            for item in params.get("attachments", [])
        ],
        "tool_hints": params.get("tool_hints", []),
        "session_id": params.get("session_id"),
        "purpose": params.get("purpose"),
        "timeout_s": params.get("timeout_s"),
    }
    return hashlib.sha256(jcs_frame(projection)).hexdigest()


__all__ = ["SCHEMA_VERSION", "Store", "task_request_hash"]
