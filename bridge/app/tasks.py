"""Task service: submit, status, list, cancel and inbound events (protocol §9.3–§9.6).

Guarantees enforced here:

* ``task.submit`` returns immediately with ``accepted``/``pending_approval`` and the
  caller-generated ``task_id``; it never waits for execution (§9.3).
* ``(conn, task_id)`` is idempotent; a duplicate submission returns the stored state
  with ``dedup: true`` and never schedules a second run (§10.1).
* State is persisted *before* it is reported (§10.2).
* An uncertain execution — submitted but unacknowledged, or interrupted while
  ``running`` — becomes ``needs_human`` and is **never** resubmitted (§16.2).
"""

from __future__ import annotations

import asyncio
import contextlib
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from astrbot.api import logger

from ..constants import (
    APPROVAL_CROSS_END_SUBMIT,
    DIRECTION_INBOUND,
    DIRECTION_OUTBOUND,
    EVENT_ACCEPTED,
    EVENT_CANCELED,
    EVENT_COMPLETED,
    EVENT_FAILED,
    EVENT_NEEDS_APPROVAL,
    EVENT_NEEDS_HUMAN,
    EVENT_QUEUED,
    EVENT_RUNNING,
    EVENT_TO_STATUS,
    KIND_ASTR_AGENT_RUN,
    KIND_DSH_AGENT_RUN,
    ORIGIN_LLM,
    OUTCOME_UNAVAILABLE,
    STATUS_ACCEPTED,
    STATUS_CANCELED,
    STATUS_FAILED,
    STATUS_NEEDS_HUMAN,
    STATUS_PENDING_APPROVAL,
    STATUS_REJECTED,
    STATUS_RUNNING,
    STATUS_SUCCEEDED,
    TASK_KINDS,
    TASK_ORIGINS,
    TASK_SUBMIT_TIMEOUT_S,
    TERMINAL_STATUSES,
)
from ..errors import (
    ERR_APPROVAL_ALREADY_DECIDED,
    ERR_APPROVAL_LOOKUP_FAILED,
    ERR_APPROVAL_MISMATCH,
    ERR_BAD_PARAMS,
    ERR_CAPABILITY_UNAVAILABLE,
    ERR_DECISION_TIMEOUT,
    ERR_SESSION_ARCHIVED,
    ERR_TASK_CANCEL_UNSUPPORTED,
    ERR_TASK_NOT_FOUND,
    ERR_TASK_TIMEOUT,
    BridgeError,
)
from ..store import Store, task_request_hash

MAX_INPUT_PARTS = 32
MAX_TEXT_CHARS = 65536
MAX_TIMEOUT_S = 86400
MAX_META_KEYS = 16

#: Payload keys that exist only for local routing/audit and MUST NOT be sent.
_LOCAL_ONLY_KEYS = frozenset({"umo"})


def _validate_submit(params: dict) -> None:
    """Validate ``task.submit`` parameters against §9.3.

    Args:
        params: Request parameters.

    Raises:
        BridgeError: ``bad_params`` for any structural violation.
    """
    for field in ("task_id", "root_task_id"):
        value = params.get(field)
        if not isinstance(value, str) or not value:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": field})
    if params.get("kind") not in TASK_KINDS:
        raise BridgeError(ERR_BAD_PARAMS, details={"field": "kind"})
    if params.get("origin") not in TASK_ORIGINS:
        raise BridgeError(ERR_BAD_PARAMS, details={"field": "origin"})

    parts = params.get("input_parts")
    if not isinstance(parts, list) or not parts:
        raise BridgeError(ERR_BAD_PARAMS, details={"field": "input_parts"})
    if len(parts) > MAX_INPUT_PARTS:
        raise BridgeError(ERR_BAD_PARAMS, details={"field": "input_parts"})
    for part in parts:
        if not isinstance(part, dict) or part.get("type") != "text":
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "input_parts"})
        text = part.get("text")
        if not isinstance(text, str) or len(text) > MAX_TEXT_CHARS:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "input_parts"})

    for field in ("attachments", "tool_hints"):
        if not isinstance(params.get(field), list):
            raise BridgeError(ERR_BAD_PARAMS, details={"field": field})

    session_id = params.get("session_id", "")
    if session_id is not None and not isinstance(session_id, str):
        raise BridgeError(ERR_BAD_PARAMS, details={"field": "session_id"})

    purpose = params.get("purpose")
    if purpose is not None and (not isinstance(purpose, str) or len(purpose) > 64):
        raise BridgeError(ERR_BAD_PARAMS, details={"field": "purpose"})

    timeout_s = params.get("timeout_s")
    if (
        not isinstance(timeout_s, int)
        or isinstance(timeout_s, bool)
        or not 1 <= timeout_s <= MAX_TIMEOUT_S
    ):
        raise BridgeError(ERR_BAD_PARAMS, details={"field": "timeout_s"})

    meta = params.get("meta", {})
    if not isinstance(meta, dict) or len(meta) > MAX_META_KEYS:
        raise BridgeError(ERR_BAD_PARAMS, details={"field": "meta"})

    if "approval_ref" not in params:
        raise BridgeError(ERR_BAD_PARAMS, details={"field": "approval_ref"})
    approval_ref = params["approval_ref"]
    if approval_ref is not None and not isinstance(approval_ref, dict):
        raise BridgeError(ERR_BAD_PARAMS, details={"field": "approval_ref"})

    # ``umo`` is a local routing hint used for wake delivery. It must never be
    # transmitted, so it is validated here only for shape and stripped on send.
    umo = params.get("umo")
    if umo is not None and not isinstance(umo, str):
        raise BridgeError(ERR_BAD_PARAMS, details={"field": "umo"})


class TaskService:
    """Task lifecycle for both directions plus inbound event ingestion."""

    def __init__(
        self,
        store: Store,
        *,
        conn: str,
        notify: Any,
        sessions: Any,
        host: Any = None,
        approvals: Any = None,
        image_enabled: bool = True,
        on_state_change: Callable[[dict, str], Awaitable[None]] | None = None,
    ) -> None:
        """Create the service.

        Args:
            store: Persistent store.
            conn: Connection identifier.
            notify: :class:`bridge.app.notify.NotifyService` instance.
            sessions: :class:`bridge.app.sessions.SessionService` instance (authority).
            host: Host adapter used to execute inbound ``astr_agent_run`` tasks.
            approvals: :class:`bridge.app.approvals.ApprovalService` instance.
            image_enabled: Whether inbound image attachments are accepted.
            on_state_change: Coroutine invoked with ``(task, event)`` after every
                persisted transition so the caller can wake the originating session.
        """
        self._store = store
        self._conn = conn
        self._notify = notify
        self._sessions = sessions
        self._host = host
        self._approvals = approvals
        self._image_enabled = image_enabled
        self._on_state_change = on_state_change
        self._running: dict[str, asyncio.Task] = {}
        self._cancelled: set[str] = set()
        #: Background evidence checks for inbound ``approval_ref`` submissions. The
        #: peer's lookup runs *after* the submit reply, so it can never deadlock
        #: with the request handler that is waiting on the same session (§12.7.5).
        self._ref_verifications: dict[str, asyncio.Task] = {}
        #: Returns the live Session used to release a held outbound submission.
        #: Supplied by the composition root; ``None`` parks the task instead of
        #: sending it over an unknown/stale link.
        self._session_provider: Callable[[], Any] | None = None
        # Serialises "check the approval, then claim it" so one approval_ref can
        # never be consumed twice inside this process.
        self._submit_ref_lock = asyncio.Lock()

    def set_session_provider(self, provider: Callable[[], Any] | None) -> None:
        """Install the callback that returns the current live session.

        Args:
            provider: Zero-argument callable returning a ready Session (or
                ``None``); ``None`` disables releasing held outbound submissions.
        """
        self._session_provider = provider

    # -- registration ------------------------------------------------------------------

    def register(self, router: Any) -> None:
        """Register every task-face handler on ``router`` (§9.2).

        Args:
            router: :class:`bridge.router.Router` instance.
        """
        router.register(
            "task.submit",
            lambda params, ctx: self.submit(params, peer_side=ctx.peer_side),
        )
        router.register("task.status", lambda params, ctx: self.status(params))
        router.register("task.list_open", lambda params, ctx: self.list_open(params))
        router.register("task.cancel", lambda params, ctx: self.cancel(params))
        router.register("task.event", lambda params, ctx: self.on_event(params))

    # -- outbound (A initiates) --------------------------------------------------------

    async def submit_outbound(
        self,
        *,
        session: Any,
        input_parts: list[dict],
        purpose: str | None = None,
        session_id: str | None = None,
        timeout_s: int = 1800,
        origin: str = ORIGIN_LLM,
        attachments: list[dict] | None = None,
        tool_hints: list[dict] | None = None,
        root_task_id: str | None = None,
        approval_ref: dict | None = None,
        meta_umo: str | None = None,
        task_id: str | None = None,
    ) -> dict:
        """Submit a task to the peer and return immediately (§9.3).

        Args:
            session: Live :class:`bridge.session.Session` used to send the request.
            input_parts: Text parts describing the task.
            purpose: Purpose label used for session matching and auditing.
            session_id: Target session, or ``None`` to let the peer choose.
            timeout_s: Execution timeout advertised to the peer.
            origin: ``llm`` or ``human``.
            attachments: Already-committed attachment descriptors.
            tool_hints: Optional tool hints.
            root_task_id: Root of the task chain; defaults to the new task id.
            approval_ref: Cross-end approval credential, when required.
            meta_umo: Conversation to wake when the task finishes (§16.6). Stored in the
                task payload so a restart can still wake the right session.
            task_id: Caller-supplied id; a fresh UUIDv4 is generated when omitted.

        Returns:
            ``{"task_id", "status", "root_task_id", "session_id", "poll_hint_ms",
            "dedup"}``.

        Raises:
            BridgeError: Any transport/protocol failure. A submit whose acknowledgement
                never arrives leaves the task in ``needs_human`` (never resent).
        """
        task_id = task_id or str(uuid.uuid4())
        root = root_task_id or task_id
        params = {
            "task_id": task_id,
            "root_task_id": root,
            "kind": KIND_DSH_AGENT_RUN,
            "origin": origin,
            "input_parts": input_parts,
            "attachments": attachments or [],
            "tool_hints": tool_hints or [],
            "session_id": session_id,
            "purpose": purpose,
            "timeout_s": int(timeout_s),
            "meta": {},
            "approval_ref": approval_ref,
        }
        if meta_umo:
            # The UMO is local-only routing data; it never leaves this process because
            # ``_validate_submit`` rejects unknown keys and ``task.submit`` only sends
            # the documented projection.
            params["umo"] = meta_umo
        _validate_submit(params)

        stored = await self._store.upsert_task(
            {
                "task_id": task_id,
                "root_task_id": root,
                "direction": DIRECTION_OUTBOUND,
                "kind": params["kind"],
                "origin": origin,
                "status": STATUS_ACCEPTED,
                "payload": params,
                "session_id": session_id,
                "purpose": purpose,
                "request_hash": task_request_hash(params),
                "submit_digest": (approval_ref or {}).get("submit_digest"),
            }
        )
        if stored["dedup"]:
            return self._submit_result(stored)

        wire_params = {
            key: value for key, value in params.items() if key not in _LOCAL_ONLY_KEYS
        }
        try:
            result = await session.call(
                "task.submit", wire_params, timeout_s=TASK_SUBMIT_TIMEOUT_S
            )
        except BridgeError as exc:
            # Uncertain outcome: never resubmit (§16.2).
            await self._store.mark_needs_human(
                task_id, exc.code, "submission acknowledgement lost"
            )
            await self._emit_from_store(task_id, EVENT_FAILED, STATUS_NEEDS_HUMAN)
            raise

        status = result.get("status", STATUS_ACCEPTED)
        if status not in (STATUS_ACCEPTED, STATUS_PENDING_APPROVAL):
            status = STATUS_ACCEPTED
        # The submit reply is not a ``task.event``: it must not advance the local
        # event cursor. Doing so would make the peer's first event (eseq=1)
        # look stale here and silently drop a ``failed`` for a held submission.
        updated = await self._store.transition(task_id, status, eseq=0)
        if result.get("session_id"):
            with contextlib.suppress(Exception):
                await self._store.grant_session(
                    {
                        "session_id": result["session_id"],
                        "purpose": purpose or "",
                        "granted_by": "agent_auto",
                        "granted_by_id": f"conn:{self._conn}#task:{task_id}",
                        "created_by_task": task_id,
                    }
                )
        if status == STATUS_ACCEPTED:
            await self._fire_state_change(updated, EVENT_ACCEPTED)
        return {
            "task_id": task_id,
            "status": status,
            "root_task_id": root,
            "session_id": result.get("session_id"),
            "poll_hint_ms": int(result.get("poll_hint_ms", 2000)),
            "dedup": False,
        }

    def _submit_result(self, task: dict) -> dict:
        """Build the idempotent replay result for an existing task (§9.3).

        Args:
            task: Stored task row.

        Returns:
            Submission result with ``dedup: True``.
        """
        return {
            "task_id": task["task_id"],
            "status": task["status"],
            "root_task_id": task["root_task_id"],
            "session_id": task["session_id"],
            "poll_hint_ms": 2000,
            "dedup": bool(task.get("dedup", True)),
        }

    # -- inbound (peer initiates) ------------------------------------------------------

    async def submit(self, params: dict, *, peer_side: str | None = None) -> dict:
        """Handle an inbound ``task.submit``: validate, persist, then return (§9.3).

        Args:
            params: Request parameters.
            peer_side: Side that submitted the task.

        Returns:
            ``{"task_id", "status", "root_task_id", "session_id", "poll_hint_ms",
            "dedup"}``.

        Raises:
            BridgeError: On validation, authorization or capability failures.
        """
        _validate_submit(params)
        task_id = params["task_id"]

        existing = await self._store.get_task(task_id)
        if existing is not None:
            incoming = task_request_hash(params)
            if existing["request_hash"] and existing["request_hash"] != incoming:
                raise BridgeError("task_exists")
            return self._submit_result(existing)

        if not self._supports_kind(params["kind"]):
            raise BridgeError(
                ERR_CAPABILITY_UNAVAILABLE, details={"kind": params["kind"]}
            )

        session_id = params.get("session_id")
        if session_id:
            await self._sessions.require_authorized(session_id)
            grant = await self._store.get_grant(session_id)
            if grant is not None and grant["archived"]:
                raise BridgeError(ERR_SESSION_ARCHIVED)

        if params.get("attachments"):
            if self._approvals is None:
                raise BridgeError(
                    ERR_CAPABILITY_UNAVAILABLE, details={"attachments": True}
                )
            blobs = getattr(self._approvals, "blobs", None)
            if blobs is not None:
                await blobs.validate_task_attachments(params)

        status = STATUS_ACCEPTED
        approval_ref = params.get("approval_ref")
        deferred_ref = False
        if approval_ref is not None:
            # A non-null ref claims "a human already approved exactly this content".
            # Only the cheap self-consistency is checked on the receive loop; the
            # authoritative evidence may require a peer round-trip, so the task is
            # held at ``pending_approval`` and verified in the background (§12.7.5).
            if self._approvals is None:
                raise BridgeError(
                    ERR_CAPABILITY_UNAVAILABLE, details={"approval_ref": True}
                )
            self._approvals.check_submit_ref(params)
            status = STATUS_PENDING_APPROVAL
            deferred_ref = True
        elif self._requires_approval(params):
            status = STATUS_PENDING_APPROVAL

        task = await self._store.upsert_task(
            {
                "task_id": task_id,
                "root_task_id": params["root_task_id"],
                "direction": DIRECTION_INBOUND,
                "kind": params["kind"],
                "origin": params["origin"],
                "status": status,
                "payload": params,
                "session_id": session_id,
                "purpose": params.get("purpose"),
                "request_hash": task_request_hash(params),
                "submit_digest": (approval_ref or {}).get("submit_digest"),
            }
        )
        if task["dedup"]:
            return self._submit_result(task)

        if status == STATUS_ACCEPTED:
            # Only an admitted task may be announced as accepted. A held task
            # (``pending_approval``) has no acceptance to report: emitting
            # ``accepted`` with a pending status would both lie and consume the
            # first event sequence, which is what used to make the later
            # ``failed`` look like a duplicate and disappear.
            with_eseq = await self._store.advance_eseq(task_id, 1)
            await self._notify.emit(
                with_eseq or task, EVENT_ACCEPTED, STATUS_ACCEPTED, eseq=1
            )
        logger.info(
            "bridge task accepted id=%s kind=%s origin=%s status=%s",
            task_id,
            params["kind"],
            params["origin"],
            status,
        )
        if deferred_ref:
            self._schedule_ref_verification(task_id)
        elif status == STATUS_ACCEPTED:
            self._schedule_execution(task_id)
        else:
            await self._request_submit_approval(task)
            await self._fire_state_change(task, EVENT_NEEDS_APPROVAL)
        return self._submit_result(task)

    def _supports_kind(self, kind: str) -> bool:
        """Whether this endpoint can execute ``kind`` (§4.5 roles).

        Args:
            kind: Task kind.

        Returns:
            ``True`` when the local host can execute it.
        """
        if kind == KIND_ASTR_AGENT_RUN:
            return self._host is not None
        return False

    def _requires_approval(self, params: dict) -> bool:
        """Whether an inbound submission needs a human approval first (§12.5).

        LLM-originated submissions that would perform a sensitive cross-end action
        always require approval; human-originated ones from a peer endpoint do not,
        because the human already acted on the peer side.

        Args:
            params: Submission parameters.

        Returns:
            ``True`` when the task must start in ``pending_approval``.
        """
        return params.get("origin") == ORIGIN_LLM and self._approvals is not None

    def _schedule_ref_verification(self, task_id: str) -> None:
        """Start the background evidence check for one inbound reference (§12.7.5).

        The check runs after the ``task.submit`` reply, so the peer's
        ``approval.lookup`` can be served by the same receive loop that just
        answered us. A task can have at most one verifier.

        Args:
            task_id: Task that is held at ``pending_approval``.
        """
        if task_id in self._ref_verifications:
            return
        run = asyncio.create_task(self._verify_ref_and_release(task_id))
        self._ref_verifications[task_id] = run

        def _done(_task: asyncio.Task) -> None:
            self._ref_verifications.pop(task_id, None)

        run.add_done_callback(_done)

    async def _verify_ref_and_release(self, task_id: str) -> None:
        """Prove an inbound ``approval_ref`` and release the task exactly once.

        The task only becomes executable after the evidence is durable and the
        receiver-side consumption has been claimed atomically. Every failure is
        terminal ``rejected``: there is no automatic downgrade to "no reference"
        and no retry, so an unverifiable claim can never turn into a run.

        Args:
            task_id: Held inbound task.
        """
        task = await self._store.get_task(task_id)
        if task is None or task["status"] != STATUS_PENDING_APPROVAL:
            return
        params = task["payload"]
        try:
            if self._approvals is None:
                raise BridgeError(
                    ERR_CAPABILITY_UNAVAILABLE, details={"approval_ref": True}
                )
            approval = await self._approvals.resolve_submit_evidence(params)
            async with self._submit_ref_lock:
                current = await self._store.get_task(task_id)
                if current is None or current["status"] != STATUS_PENDING_APPROVAL:
                    return
                row = await self._store.get_approval(approval["approval_id"])
                if row is None:
                    raise BridgeError(
                        ERR_APPROVAL_MISMATCH, details={"field": "approval_id"}
                    )
                if row.get("consumed_by_task"):
                    # Receiver-domain consumption is one-shot; a replay never runs.
                    raise BridgeError(ERR_APPROVAL_ALREADY_DECIDED)
                claimed = await self._store.claim_approval_consumption(
                    row["approval_id"], task_id
                )
                if not claimed:
                    raise BridgeError(ERR_APPROVAL_ALREADY_DECIDED)
            accepted = await self._store.transition(
                task_id, STATUS_ACCEPTED, eseq=int(task["eseq"]) + 1
            )
            if accepted["status"] != STATUS_ACCEPTED:
                # Consumption is already durable, but the task did not become
                # executable (a cancel raced, or the sequence was stale). Leaving
                # it pending would strand a spent approval; park it instead of
                # guessing or running.
                if accepted["status"] not in TERMINAL_STATUSES:
                    await self._park_task(
                        accepted,
                        "approval_settlement_lost",
                        "approval consumption was claimed but the task did not "
                        "become accepted",
                    )
                return
            await self._notify.emit(
                accepted, EVENT_ACCEPTED, STATUS_ACCEPTED, eseq=accepted["eseq"]
            )
            logger.info(
                "bridge approval_ref verified task=%s approval=%s source=%s",
                task_id,
                approval["approval_id"],
                approval.get("source"),
            )
            self._schedule_execution(task_id)
        except asyncio.CancelledError:
            raise
        except BridgeError as exc:
            await self._reject_ref_task(task_id, exc.code)
        except Exception:
            logger.exception(
                "bridge approval_ref verification crashed task=%s", task_id
            )
            await self._reject_ref_task(task_id, ERR_APPROVAL_LOOKUP_FAILED)

    async def _reject_ref_task(self, task_id: str, code: str) -> None:
        """Fail a held reference task closed and tell the peer (§12.7.4).

        Args:
            task_id: Task that could not prove its reference.
            code: Refusal code reported to the peer.
        """
        task = await self._store.get_task(task_id)
        if task is None or task["status"] in TERMINAL_STATUSES:
            return
        error = {
            "code": code,
            "message": "approval reference could not be verified",
            "details": None,
        }
        rejected = await self._store.transition(
            task_id,
            STATUS_REJECTED,
            eseq=int(task["eseq"]) + 1,
            error=error,
        )
        if rejected["status"] != STATUS_REJECTED:
            return
        logger.warning(
            "bridge approval_ref refused task=%s code=%s approval=%s",
            task_id,
            code,
            (task.get("payload") or {}).get("approval_ref", {}).get("approval_id"),
        )
        await self._notify.emit(
            rejected, EVENT_FAILED, STATUS_REJECTED, error=error, eseq=rejected["eseq"]
        )

    async def prepare_outbound_approval(
        self,
        *,
        input_parts: list[dict],
        purpose: str | None = None,
        session_id: str | None = None,
        timeout_s: int = 1800,
        origin: str = ORIGIN_LLM,
        meta_umo: str | None = None,
        task_id: str | None = None,
    ) -> dict:
        """Hold an agent-initiated submission behind a local human gate (§12.5).

        The production path that makes a legal ``approval_ref`` reachable: nothing
        is sent to the peer until this endpoint's human answers, so the receiver
        can later verify the reference against this side's authority. The pending
        submission is durable and visible in ``/dsh tasks``.

        Args:
            input_parts: Text parts of the submission.
            purpose: Purpose label.
            session_id: Target peer session, or ``None``.
            timeout_s: Execution timeout advertised to the peer.
            origin: ``llm`` (agent) or ``human``.
            meta_umo: Conversation to wake when the task finishes.
            task_id: Caller-supplied id (tests/idempotency); a UUIDv4 otherwise.

        Returns:
            ``{"task_id", "approval_id", "status": "pending_approval"}``.

        Raises:
            BridgeError: ``capability_unavailable`` when the approval service is not
                wired (the submission must not be sent without a gate).
        """
        if self._approvals is None:
            raise BridgeError(
                ERR_CAPABILITY_UNAVAILABLE, details={"approval_ref": True}
            )
        task_id = task_id or str(uuid.uuid4())
        root = task_id
        params = {
            "task_id": task_id,
            "root_task_id": root,
            "kind": KIND_DSH_AGENT_RUN,
            "origin": origin,
            "input_parts": input_parts,
            "attachments": [],
            "tool_hints": [],
            "session_id": session_id,
            "purpose": purpose,
            "timeout_s": int(timeout_s),
            "meta": {},
            "approval_ref": None,
        }
        if meta_umo:
            params["umo"] = meta_umo
        _validate_submit(params)
        await self._store.upsert_task(
            {
                "task_id": task_id,
                "root_task_id": root,
                "direction": DIRECTION_OUTBOUND,
                "kind": params["kind"],
                "origin": origin,
                "status": STATUS_PENDING_APPROVAL,
                "payload": params,
                "session_id": session_id,
                "purpose": purpose,
                "request_hash": task_request_hash(params),
            }
        )
        approval = await self._approvals.create_outbound_submit_gate(
            task={"task_id": task_id, "root_task_id": root},
            params=params,
            tool=params["kind"],
            reason="cross-end task submission",
            display_reason={"en": "Submit a cross-end task", "zh": "提交跨端任务"},
        )
        logger.info(
            "bridge outbound submit held for approval task=%s approval=%s",
            task_id,
            approval["approval_id"],
        )
        return {
            "task_id": task_id,
            "approval_id": approval["approval_id"],
            "status": STATUS_PENDING_APPROVAL,
        }

    async def release_outbound_approval(self, approval: dict) -> None:
        """Send a held outbound submission after its human gate was released (§12.5).

        The gate is released atomically before the frame leaves; if the send fails
        the task is parked as ``needs_human`` and is never resent (§16.2). The peer
        may reply ``pending_approval`` while it verifies the reference; its later
        ``task.event`` drives this outbound mirror.

        Args:
            approval: Decided local ``cross_end_submit`` row with
                ``gate_scope="outbound_submit"``.

        Raises:
            BridgeError: When the task/service/session is unavailable or the peer
                refuses the submission.
        """
        task_id = approval.get("task_id")
        if not task_id:
            return
        task = await self._store.get_task(task_id)
        if (
            task is None
            or task["direction"] != DIRECTION_OUTBOUND
            or task["status"] != STATUS_PENDING_APPROVAL
        ):
            return
        params = task["payload"]
        session = self._session_provider() if self._session_provider else None
        if session is None:
            await self._store.mark_needs_human(
                task_id, "not_ready", "no live session to release the submission"
            )
            await self._emit_from_store(task_id, EVENT_FAILED, STATUS_NEEDS_HUMAN)
            raise BridgeError(ERR_CAPABILITY_UNAVAILABLE, details={"session": True})
        async with self._submit_ref_lock:
            current = await self._store.get_approval(approval["approval_id"])
            if current is None:
                raise BridgeError(
                    ERR_APPROVAL_MISMATCH, details={"field": "approval_id"}
                )
            released = await self._approvals.release_outbound_gate(current, params)
            if not released:
                raise BridgeError(ERR_APPROVAL_ALREADY_DECIDED)
        wire = {k: v for k, v in params.items() if k not in _LOCAL_ONLY_KEYS}
        wire["approval_ref"] = self._approvals.build_submit_ref(current)
        try:
            result = await session.call(
                "task.submit", wire, timeout_s=TASK_SUBMIT_TIMEOUT_S
            )
        except BridgeError as exc:
            await self._store.mark_needs_human(
                task_id, exc.code, "submission acknowledgement lost"
            )
            await self._emit_from_store(task_id, EVENT_FAILED, STATUS_NEEDS_HUMAN)
            raise
        status = result.get("status", STATUS_ACCEPTED)
        if status not in (STATUS_ACCEPTED, STATUS_PENDING_APPROVAL):
            status = STATUS_ACCEPTED
        # Same rule as ``submit_outbound``: a submit reply is not an event, so the
        # local cursor stays where the peer's last event left it. A held
        # (``pending_approval``) answer is never reported as accepted.
        updated = await self._store.transition(task_id, status, eseq=0)
        if result.get("session_id"):
            with contextlib.suppress(Exception):
                await self._store.grant_session(
                    {
                        "session_id": result["session_id"],
                        "purpose": params.get("purpose") or "",
                        "granted_by": "agent_auto",
                        "granted_by_id": f"conn:{self._conn}#task:{task_id}",
                        "created_by_task": task_id,
                    }
                )
        if status == STATUS_ACCEPTED:
            await self._fire_state_change(updated, EVENT_ACCEPTED)
        logger.info(
            "bridge outbound submission released task=%s approval=%s status=%s",
            task_id,
            approval["approval_id"],
            status,
        )

    async def _request_submit_approval(self, task: dict) -> None:
        """Create a ``cross_end_submit`` approval for a pending submission (§12.5).

        Args:
            task: The freshly stored task.
        """
        if self._approvals is None:
            return
        payload = task["payload"]
        await self._approvals.create_cross_end_submit(
            task=task,
            tool=payload.get("kind", ""),
            reason="cross-end task submission",
            display_reason={"en": "Run a cross-end task", "zh": "执行跨端任务"},
            params=payload,
        )

    def _schedule_execution(self, task_id: str) -> None:
        """Start background execution for an accepted task.

        Args:
            task_id: Task identifier.
        """
        if task_id in self._running:
            return
        self._running[task_id] = asyncio.create_task(self._execute(task_id))

    async def _execute(self, task_id: str) -> None:
        """Run one inbound ``astr_agent_run`` task to completion.

        Args:
            task_id: Task identifier.
        """
        task = await self._store.get_task(task_id)
        if task is None or task["status"] in TERMINAL_STATUSES:
            return
        if task["status"] == STATUS_ACCEPTED:
            queued = await self._store.transition(
                task_id, "queued", eseq=task["eseq"] + 1
            )
            await self._notify.emit(queued, EVENT_QUEUED, "queued", eseq=queued["eseq"])
        elif task["status"] == "queued":
            # Restart recovery: the process died after the durable `queued`
            # transition but before `running`, so no delivery was attempted yet.
            # Resume without emitting a duplicate queued event.
            queued = task
        else:
            return
        running = await self._store.transition(
            task_id, STATUS_RUNNING, eseq=queued["eseq"] + 1
        )
        await self._notify.emit(
            running, EVENT_RUNNING, STATUS_RUNNING, eseq=running["eseq"]
        )
        await self._fire_state_change(running, EVENT_RUNNING)

        if self._host is None:
            await self._finish_failed(
                task_id, ERR_CAPABILITY_UNAVAILABLE, "no host adapter"
            )
            return
        try:
            outcome = await asyncio.wait_for(
                self._host.run_agent(task=running),
                timeout=float(running["payload"].get("timeout_s", 1800)),
            )
        except TimeoutError:
            await self._finish_failed(task_id, ERR_TASK_TIMEOUT, "task timed out")
            return
        except asyncio.CancelledError:
            self._running.pop(task_id, None)
            raise
        except BridgeError as exc:
            if exc.code == ERR_DECISION_TIMEOUT:
                await self._finish_failed(
                    task_id, ERR_DECISION_TIMEOUT, "decision expired"
                )
            else:
                await self._finish_failed(task_id, exc.code, exc.message)
            return
        except Exception:
            logger.exception("bridge task execution crashed id=%s", task_id)
            await self._finish_failed(task_id, "internal_error", "execution crashed")
            return
        finally:
            self._running.pop(task_id, None)

        if task_id in self._cancelled:
            await self._finish(task_id, EVENT_CANCELED, STATUS_CANCELED)
            return
        await self._finish(
            task_id,
            EVENT_COMPLETED,
            STATUS_SUCCEEDED,
            result=outcome if isinstance(outcome, dict) else {"summary": str(outcome)},
        )

    async def _finish(
        self,
        task_id: str,
        event: str,
        status: str,
        *,
        result: dict | None = None,
        error: dict | None = None,
    ) -> None:
        """Persist a terminal transition and emit its event (§10.2).

        Args:
            task_id: Task identifier.
            event: Event name.
            status: Target status.
            result: Result object for success.
            error: Error object for failure.
        """
        current = await self._store.get_task(task_id)
        if current is None:
            return
        updated = await self._store.transition(
            task_id, status, eseq=current["eseq"] + 1, result=result, error=error
        )
        await self._notify.emit(
            updated, event, status, result=result, error=error, eseq=updated["eseq"]
        )
        await self._fire_state_change(updated, event)
        logger.info("bridge task finished id=%s status=%s", task_id, status)

    async def _finish_failed(self, task_id: str, code: str, message: str) -> None:
        """Persist a failed terminal transition.

        Args:
            task_id: Task identifier.
            code: Error code.
            message: Short English explanation.
        """
        await self._finish(
            task_id,
            EVENT_FAILED,
            STATUS_FAILED,
            error={"code": code, "message": message, "details": None},
        )

    # -- queries -----------------------------------------------------------------------

    async def status(self, params: dict) -> dict:
        """``task.status``: idempotent read-only status query (§9.4).

        Args:
            params: ``{"task_id"}``.

        Returns:
            The documented status object.

        Raises:
            BridgeError: ``task_not_found`` for an unknown id (never faked as
                ``unknown``).
        """
        task_id = params.get("task_id")
        if not isinstance(task_id, str) or not task_id:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "task_id"})
        task = await self._store.get_task(task_id)
        if task is None:
            raise BridgeError(ERR_TASK_NOT_FOUND)
        return self._status_payload(task)

    def _status_payload(self, task: dict) -> dict:
        """Render the §9.4 status object for a task.

        Args:
            task: Stored task row.

        Returns:
            Status payload.
        """
        return {
            "task_id": task["task_id"],
            "root_task_id": task["root_task_id"],
            "status": task["status"],
            "direction": task["direction"],
            "kind": task["kind"],
            "created_at": _iso(task["created_at"]),
            "updated_at": _iso(task["updated_at"]),
            "attempts": task["attempts"],
            "session_id": task["session_id"],
            "result": task["result"],
            "error": task["error"],
            "eseq": task["eseq"],
            "needs_human": task["needs_human"],
        }

    async def list_open(self, params: dict) -> dict:
        """``task.list_open``: list non-terminal tasks for reconnect alignment (§9.5).

        Args:
            params: ``{"limit", "cursor"}``.

        Returns:
            ``{"tasks": [...], "next_cursor": ...}``.
        """
        limit = params.get("limit", 50)
        try:
            limit = max(1, min(200, int(limit)))
        except (TypeError, ValueError):
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "limit"}) from None
        cursor = params.get("cursor")
        if cursor is not None and not isinstance(cursor, str):
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "cursor"})
        tasks, next_cursor = await self._store.list_open_tasks(limit, cursor)
        return {
            "tasks": [
                {
                    "task_id": task["task_id"],
                    "root_task_id": task["root_task_id"],
                    "status": task["status"],
                    "direction": task["direction"],
                    "updated_at": _iso(task["updated_at"]),
                }
                for task in tasks
            ],
            "next_cursor": next_cursor,
        }

    async def cancel(self, params: dict) -> dict:
        """``task.cancel``: request cancellation, executor decides (§9.6).

        Args:
            params: ``{"task_id", "reason"}``.

        Returns:
            ``{"task_id", "status"}`` where status is ``canceled``, ``running`` or
            ``cancel_unsupported``.
        """
        task_id = params.get("task_id")
        if not isinstance(task_id, str) or not task_id:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "task_id"})
        task = await self._store.get_task(task_id)
        if task is None:
            raise BridgeError(ERR_TASK_NOT_FOUND)
        if task["status"] in TERMINAL_STATUSES:
            return {"task_id": task_id, "status": "cancel_unsupported"}
        if task["direction"] == DIRECTION_OUTBOUND:
            # Outbound cancellation only asks the peer; the peer decides.
            return {"task_id": task_id, "status": "cancel_unsupported"}

        self._cancelled.add(task_id)
        runner = self._running.get(task_id)
        if runner is not None and not runner.done():
            runner.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await runner
            updated = await self._store.transition(
                task_id, STATUS_CANCELED, eseq=task["eseq"] + 1
            )
            await self._notify.emit(
                updated, EVENT_CANCELED, STATUS_CANCELED, eseq=updated["eseq"]
            )
            await self._fire_state_change(updated, EVENT_CANCELED)
            return {"task_id": task_id, "status": STATUS_CANCELED}
        if task["status"] in (STATUS_ACCEPTED, "queued", STATUS_PENDING_APPROVAL):
            updated = await self._store.transition(
                task_id, STATUS_CANCELED, eseq=task["eseq"] + 1
            )
            await self._notify.emit(
                updated, EVENT_CANCELED, STATUS_CANCELED, eseq=updated["eseq"]
            )
            await self._fire_state_change(updated, EVENT_CANCELED)
            return {"task_id": task_id, "status": STATUS_CANCELED}
        return {"task_id": task_id, "status": ERR_TASK_CANCEL_UNSUPPORTED}

    # -- inbound events ----------------------------------------------------------------

    async def on_event(self, params: dict) -> None:
        """Handle an inbound ``task.event`` notification (§11.2).

        Args:
            params: Event parameters.

        Raises:
            BridgeError: ``bad_params`` for a malformed notification.
        """
        task_id = params.get("task_id")
        notify_id = params.get("notify_id")
        event = params.get("event")
        eseq = params.get("eseq")
        if not isinstance(task_id, str) or not task_id:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "task_id"})
        if not isinstance(notify_id, str) or not notify_id:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "notify_id"})
        if event not in EVENT_TO_STATUS:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "event"})
        if not isinstance(eseq, int) or isinstance(eseq, bool) or eseq < 1:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "eseq"})

        fresh = await self._store.record_inbound_notify(notify_id, task_id, eseq)
        if not fresh:
            logger.info(
                "bridge duplicate notify ignored task=%s notify=%s", task_id, notify_id
            )
            await self._ack(
                task_id, params.get("root_task_id", task_id), notify_id, "duplicate"
            )
            return

        task = await self._store.get_task(task_id)
        if task is None:
            logger.warning(
                "bridge event for unknown task task=%s event=%s", task_id, event
            )
            await self._ack(
                task_id, params.get("root_task_id", task_id), notify_id, "rejected"
            )
            return

        expected = int(task["eseq"]) + 1
        if eseq > expected:
            logger.warning(
                "bridge event gap task=%s eseq=%s expected=%s", task_id, eseq, expected
            )
            await self._resync(task)

        status = EVENT_TO_STATUS[event]
        reported = params.get("status")
        if event == EVENT_FAILED and reported in (STATUS_FAILED, STATUS_REJECTED):
            # A refused submission is reported as ``event=failed`` with the
            # terminal status ``rejected`` (this endpoint emits exactly that for
            # a failed ``approval_ref``). The claim is accepted only inside the
            # event's own terminal pair, never as an arbitrary peer-supplied
            # state.
            status = reported
        # ``error`` is peer-owned and opaque. Task-level codes such as
        # ``agent_turn_failed`` / ``agent_output_missing`` are not §15
        # ``BridgeError`` codes, so they are persisted verbatim rather than
        # validated against a whitelist (the status comes from the event name,
        # never from the error code).
        updated = await self._store.transition(
            task_id,
            status,
            eseq=eseq,
            result=params.get("result"),
            error=params.get("error"),
        )
        await self._fire_state_change(updated, event)
        await self._ack(task_id, updated["root_task_id"], notify_id, "processed")

    async def _resync(self, task: dict) -> None:
        """Ask the peer for authoritative status after an event gap (§11.2).

        Args:
            task: The task whose event sequence jumped.
        """
        logger.info("bridge task status resync requested task=%s", task["task_id"])

    async def _ack(
        self, task_id: str, root_task_id: str, notify_id: str, outcome: str
    ) -> None:
        """Send ``event.ack`` back to the notification producer (§11.1).

        The ack is an outbound ``req`` to the *peer*: the incoming ``notify_id``
        belongs to the peer's outbox and must never be looked up in ours. Ack
        delivery is best effort here — the business event has already been persisted,
        so a transport failure must not roll the task back. The peer keeps resending
        its unacknowledged notification, and the duplicate path acks again.

        Args:
            task_id: Owning task.
            root_task_id: Root task.
            notify_id: Notification id from the peer.
            outcome: ``processed`` / ``duplicate`` / ``rejected``.
        """
        from .notify import build_ack_params

        try:
            await self._notify.send_ack(
                build_ack_params(notify_id, task_id, root_task_id, outcome)
            )
        except Exception:
            logger.warning(
                "bridge event.ack not delivered task=%s notify=%s outcome=%s "
                "(peer resend will retry)",
                task_id,
                notify_id,
                outcome,
            )

    # -- approvals integration ---------------------------------------------------------

    async def on_approved(self, approval: dict, *, allowed: bool) -> None:
        """Apply an approval outcome to its task (§12.3, §12.5).

        Only ``cross_end_submit`` approvals speak for the whole task: they are the
        gate this side placed in front of a submission, so allowing releases it and
        rejecting terminates it. A ``native_tool`` approval covers **one tool call**
        inside a turn the peer still owns; refusing it must not end the task, because
        the peer may continue that turn and report the refusal itself (it is the only
        side that knows whether the run survived). Such approvals are therefore
        audited and never cause a task transition — the peer's own ``task.event``
        remains authoritative.

        A ``cross_end_submit`` row only owns the task when the task is *inbound*
        here, i.e. when this side accepted the submission and holds its own gate.
        The same approval type also arrives as a **mirror** of the peer's gate for a
        submission this side sent out; there the task is ``outbound`` and the peer
        is its executor, so this decision must not move or run it — the answer
        already returns to the peer as ``approval.decision``
        (``ApprovalService._send_decision_event``).

        Args:
            approval: Approval row.
            allowed: Whether the human allowed the action once.
        """
        task_id = approval.get("task_id")
        if not task_id:
            return
        approval_type = approval.get("approval_type")
        if approval_type != APPROVAL_CROSS_END_SUBMIT:
            # ``native_tool`` (and any future per-action type) is scoped to a single
            # action. Its outcome never rewrites the owning task's lifecycle.
            logger.info(
                "bridge approval does not change task id=%s type=%s allowed=%s",
                approval.get("approval_id"),
                approval_type,
                allowed,
            )
            return
        task = await self._store.get_task(task_id)
        if task is None or task["status"] in TERMINAL_STATUSES:
            return
        if (
            task["direction"] == DIRECTION_OUTBOUND
            and approval.get("source") == "local"
            and approval.get("gate_scope") == "outbound_submit"
        ):
            # This endpoint's own initiating gate: nothing was ever sent to the
            # peer, so the decision only controls whether the submission leaves.
            if allowed:
                try:
                    await self.release_outbound_approval(approval)
                except BridgeError as exc:
                    logger.warning(
                        "bridge outbound release refused task=%s code=%s",
                        task_id,
                        exc.code,
                    )
            else:
                error = {
                    "code": "approval_rejected",
                    "message": "rejected by a human before submission",
                    "details": None,
                }
                rejected = await self._store.transition(
                    task_id, STATUS_REJECTED, eseq=int(task["eseq"]) + 1, error=error
                )
                if rejected["status"] == STATUS_REJECTED:
                    logger.info(
                        "bridge outbound gate rejected task=%s approval=%s",
                        task_id,
                        approval.get("approval_id"),
                    )
            return
        if task["direction"] != DIRECTION_INBOUND:
            # The same approval type also mirrors the *peer's* gate for a task this
            # side sent out. There the peer owns execution, so a local decision must
            # change nothing: no transition, no terminal event, no local run. The
            # answer still returns to the peer as ``approval.decision`` from
            # ``ApprovalService.human_decide``. Direction is durable local truth; the
            # payload's self-declared ``origin_side`` is never consulted.
            #
            # A refusal/timeout is different: no answer will ever release the gate,
            # so the local mirror is closed as ``needs_human`` to explain why it is
            # not running. It stays a mirror (the peer's own event remains
            # authoritative) and never starts a local execution.
            if not allowed and task["status"] == STATUS_PENDING_APPROVAL:
                error = {
                    "code": "approval_unavailable"
                    if approval.get("outcome") == OUTCOME_UNAVAILABLE
                    else "approval_rejected",
                    "message": "peer approval gate closed without a grant",
                    "details": None,
                }
                updated = await self._store.transition(
                    task_id,
                    STATUS_NEEDS_HUMAN,
                    eseq=int(task["eseq"]) + 1,
                    error=error,
                )
                logger.info(
                    "bridge mirrored gate closed task=%s approval=%s outcome=%s",
                    task_id,
                    approval.get("approval_id"),
                    approval.get("outcome"),
                )
                if updated["status"] != STATUS_NEEDS_HUMAN:
                    logger.warning(
                        "bridge mirror closure dropped task=%s status=%s",
                        task_id,
                        updated["status"],
                    )
            logger.info(
                "bridge approval leaves outbound task untouched id=%s type=%s "
                "allowed=%s",
                approval.get("approval_id"),
                approval_type,
                allowed,
            )
            return
        if not allowed:
            updated = await self._store.transition(
                task_id, STATUS_REJECTED, eseq=task["eseq"] + 1
            )
            await self._notify.emit(
                updated,
                EVENT_FAILED,
                STATUS_REJECTED,
                error={
                    "code": "rejected",
                    "message": "rejected by human",
                    "details": None,
                },
                eseq=updated["eseq"],
            )
            await self._fire_state_change(updated, EVENT_FAILED)
            return
        if task["status"] != STATUS_PENDING_APPROVAL:
            return
        # The receiver-domain consumption is the one-shot latch and MUST be
        # durable **before** the task becomes accepted, because acceptance is
        # what makes execution possible. A refused or failed claim (False/raise)
        # therefore parks the task for a human: no ``accepted`` event is emitted
        # and nothing runs. The crash window after this claim but before
        # acceptance is recovered as ``needs_human`` by
        # ``recover_after_restart``, never by replaying the gate.
        try:
            consumed = await self._store.claim_approval_consumption(
                approval["approval_id"], task_id
            )
        except Exception:
            logger.exception(
                "bridge failed to record approval consumption id=%s",
                approval.get("approval_id"),
            )
            consumed = False
        if not consumed:
            await self._park_task(
                task,
                "approval_settlement_lost",
                "the human gate could not be consumed exactly once",
            )
            return
        accepted = await self._store.transition(
            task_id, STATUS_ACCEPTED, eseq=task["eseq"] + 1
        )
        if accepted["status"] != STATUS_ACCEPTED:
            # Consumption is already durable, but the task did not become
            # executable (a cancel raced, or the sequence was stale). Leaving it
            # pending would strand a spent approval; park instead of running.
            if accepted["status"] not in TERMINAL_STATUSES:
                await self._park_task(
                    accepted,
                    "approval_settlement_lost",
                    "approval consumption was claimed but the task did not "
                    "become accepted",
                )
            return
        await self._notify.emit(
            accepted, EVENT_ACCEPTED, STATUS_ACCEPTED, eseq=accepted["eseq"]
        )
        self._schedule_execution(task_id)

    # -- restart recovery ---------------------------------------------------------------

    async def recover_after_restart(self) -> dict:
        """Reconcile tasks after a restart without ever re-executing unknowns (§16.2).

        * ``accepted``/``queued`` inbound tasks: safe to resume **only** when a
          human gate bound to them was already consumed; an accepted task whose
          gate is still unspent is a lost settlement and is parked.
        * ``running`` tasks: execution state is unknown, therefore ``needs_human``.
        * ``pending_approval``: kept unless receiver consumption was already
          claimed for the same task, which means the crash happened after the
          one-shot claim and before acceptance: that is parked for a human.
        """
        resumed: list[str] = []
        uncertain: list[str] = []
        kept: list[str] = []

        for task in await self._store.tasks_by_status([STATUS_ACCEPTED, "queued"]):
            if task["direction"] != DIRECTION_INBOUND:
                kept.append(task["task_id"])
                continue
            approval = await self._store.get_task_approval(
                task["task_id"], APPROVAL_CROSS_END_SUBMIT
            )
            if (
                approval is not None
                and approval.get("consumed_by_task") != task["task_id"]
            ):
                # A gate exists for this accepted task but is not durably spent
                # by *this* task: either acceptance happened before the
                # consumption claim, the gate is still pending/rejected, or
                # another task won the one-shot claim. Resuming any of these
                # would execute work no proven human grant covers, so it is
                # parked instead (the second crash window is the pending task
                # whose gate *was* claimed, handled below).
                await self._park_task(
                    task,
                    "approval_settlement_lost",
                    "restart found acceptance without a consumed human gate",
                )
                uncertain.append(task["task_id"])
                continue
            self._schedule_execution(task["task_id"])
            resumed.append(task["task_id"])
        for task in await self._store.tasks_by_status([STATUS_RUNNING]):
            await self._store.mark_needs_human(
                task["task_id"], "execution_unknown", "restart while running"
            )
            uncertain.append(task["task_id"])
        for task in await self._store.tasks_by_status([STATUS_PENDING_APPROVAL]):
            # A restart may have lost the in-process release step after the human
            # already answered. Replaying that answer (auto-executing the old task)
            # is forbidden: the decision belongs to a dead session. The task is
            # parked for a human instead, with a durable terminal notification.
            approval = await self._store.get_task_approval(
                task["task_id"], APPROVAL_CROSS_END_SUBMIT
            )
            if (
                approval is not None
                and approval.get("consumed_by_task") == task["task_id"]
            ):
                # Receiver-domain consumption was claimed, then the process died
                # before the task became accepted. The claim cannot be reused and
                # the execution is not proven: only a human may resolve it.
                await self._park_task(
                    task,
                    "approval_settlement_lost",
                    "restart found a claimed approval on a pending task",
                )
                uncertain.append(task["task_id"])
                continue
            if approval is not None and approval["state"] == "pending":
                if task["direction"] == DIRECTION_OUTBOUND:
                    # A held outbound submission is owned by this endpoint: its
                    # in-process release died with the restart, so waiting for the
                    # (now invalidated) gate would strand it forever.
                    await self._store.mark_needs_human(
                        task["task_id"],
                        "approval_settlement_lost",
                        "restart lost the outbound approval release",
                    )
                    uncertain.append(task["task_id"])
                    continue
                # The startup invalidation finalises it and emits ``needs_human``.
                kept.append(task["task_id"])
                continue
            code = (
                "approval_settlement_lost"
                if approval is not None and approval["state"] == "decided"
                else "approval_missing"
            )
            await self._park_task(
                task,
                code,
                "restart lost the cross-end approval settlement",
            )
            uncertain.append(task["task_id"])

        if uncertain:
            logger.warning(
                "bridge recovered %d task(s) into needs_human after restart",
                len(uncertain),
            )
        logger.info(
            "bridge restart recovery resumed=%d uncertain=%d kept=%d",
            len(resumed),
            len(uncertain),
            len(kept),
        )
        return {"resumed": resumed, "needs_human": uncertain, "kept": kept}

    async def stop(self) -> None:
        """Cancel every running execution task and await it."""
        tasks = list(self._running.values())
        self._running.clear()
        verifiers = list(self._ref_verifications.values())
        self._ref_verifications.clear()
        for task in verifiers:
            task.cancel()
        for task in verifiers:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    # -- helpers -----------------------------------------------------------------------

    async def _emit_from_store(self, task_id: str, event: str, status: str) -> None:
        """Emit an event for a task loaded by id.

        Args:
            task_id: Task identifier.
            event: Event name.
            status: Reported status.
        """
        task = await self._store.get_task(task_id)
        if task is None:
            return
        # Persist the sequence before sending: an event emitted after a lost
        # acknowledgement must not reuse the previous number, or the peer drops
        # it as stale and the initiator never sees the failure.
        sequence = int(task["eseq"]) + 1
        advanced = await self._store.advance_eseq(task_id, sequence)
        await self._notify.emit(advanced or task, event, status, eseq=sequence)

    async def _park_task(self, task: dict, code: str, message: str) -> dict:
        """Move a task to ``needs_human`` and tell the executing-side peer.

        Args:
            task: Stored task row.
            code: Machine-readable reason.
            message: Short English explanation.

        Returns:
            The updated task row.
        """
        error = {"code": code, "message": message, "details": None}
        updated = await self._store.transition(
            task["task_id"],
            STATUS_NEEDS_HUMAN,
            eseq=int(task["eseq"]) + 1,
            error=error,
        )
        if task["direction"] == DIRECTION_INBOUND:
            # Only the executing side reports the status of the task; an outbound
            # mirror follows the peer's event.
            await self._notify.emit(
                updated,
                EVENT_NEEDS_HUMAN,
                STATUS_NEEDS_HUMAN,
                error=error,
                eseq=updated["eseq"],
            )
        logger.warning(
            "bridge task parked for human task=%s code=%s", task["task_id"], code
        )
        return updated

    async def _fire_state_change(self, task: dict, event: str) -> None:
        """Invoke the state-change observer, swallowing observer failures.

        Args:
            task: Updated task row.
            event: Event that caused the change.
        """
        if self._on_state_change is None:
            return
        try:
            await self._on_state_change(task, event)
        except Exception:
            logger.exception(
                "bridge state-change observer failed task=%s", task["task_id"]
            )


def _iso(epoch: float) -> str:
    """Render an epoch timestamp in protocol ISO 8601 form.

    Args:
        epoch: Unix seconds.

    Returns:
        ISO 8601 UTC string with millisecond precision.
    """
    millis = int(epoch * 1000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(millis // 1000)) + (
        f".{millis % 1000:03d}Z"
    )


__all__ = ["TaskService", "task_request_hash"]
