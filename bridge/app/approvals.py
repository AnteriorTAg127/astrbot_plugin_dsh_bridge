"""Approval and business-decision service (protocol §12, §9.8).

Hard rules implemented here (code-review items, §12.6):

1. No code path approves automatically — not on retry, not on timeout, not from a
   default value. Timeout always resolves to ``rejected``.
2. Only ``actor_kind == "human"`` may produce a decision; agents are rejected with
   ``agent_cannot_approve`` / ``agent_cannot_decide``.
3. ``unavailable`` and ``cancelled`` fail closed, exactly like ``rejected``.
4. The first decision wins; later ones are dropped as ``already_decided``.
5. ``submit_digest`` is recomputed from the actual submission before execution, so
   "approved content == submitted content" is verifiable (§12.5).
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from astrbot.api import logger

from ..constants import (
    ACTOR_HUMAN,
    APPROVAL_ALLOWING_OUTCOMES,
    APPROVAL_BUSINESS_DECISION,
    APPROVAL_CROSS_END_SUBMIT,
    APPROVAL_NATIVE_TOOL,
    APPROVAL_OUTCOMES,
    APPROVAL_TYPES,
    CHANNEL_TIMEOUT,
    EVENT_NEEDS_HUMAN,
    MSG_APPROVAL_DECISION,
    MSG_APPROVAL_LOOKUP,
    OUTCOME_ALLOWED_ONCE,
    OUTCOME_REJECTED,
    OUTCOME_UNAVAILABLE,
    SIDE_B,
    STATUS_NEEDS_HUMAN,
    STATUS_PENDING_APPROVAL,
)
from ..crypto import input_parts_digest, jcs_frame, request_digest, submit_digest
from ..errors import (
    ERR_AGENT_CANNOT_APPROVE,
    ERR_AGENT_CANNOT_DECIDE,
    ERR_APPROVAL_ALREADY_DECIDED,
    ERR_APPROVAL_DIGEST_MISMATCH,
    ERR_APPROVAL_EVIDENCE_MISSING,
    ERR_APPROVAL_EXPIRED,
    ERR_APPROVAL_LOOKUP_FAILED,
    ERR_APPROVAL_MISMATCH,
    ERR_BAD_PARAMS,
    ERR_CAPABILITY_UNAVAILABLE,
    ERR_TASK_NOT_FOUND,
    BridgeError,
)
from ..session import utc_iso_ms
from ..store import Store


def build_submit_projection(params: dict) -> dict:
    """Build the §12.5 projection object used to compute ``submit_digest``.

    The projection deliberately excludes ``approval_ref`` itself, otherwise the
    digest would be self-referential.

    Args:
        params: ``task.submit`` parameters.

    Returns:
        Projection object ready for :func:`bridge.crypto.submit_digest`.
    """
    attachments = [
        {
            "kind": item.get("kind"),
            "blob_id": item.get("blob_id"),
            "media_type": item.get("media_type"),
            "bytes": item.get("bytes"),
            "sha256": item.get("sha256"),
        }
        for item in params.get("attachments", [])
    ]
    return {
        "task_id": params.get("task_id"),
        "root_task_id": params.get("root_task_id"),
        "kind": params.get("kind"),
        "origin": params.get("origin"),
        "session_id": params.get("session_id"),
        "purpose": params.get("purpose"),
        "timeout_s": params.get("timeout_s"),
        "input_parts_digest": input_parts_digest(params.get("input_parts", [])),
        "attachments": attachments,
        "tool_hints": params.get("tool_hints", []),
    }


def compute_submit_digest(params: dict) -> str:
    """Compute the digest a human approves together with the submission (§12.5).

    Args:
        params: ``task.submit`` parameters.

    Returns:
        Base64url digest.
    """
    return submit_digest(build_submit_projection(params))


class ApprovalService:
    """Approval queue, decision queue and their wire handlers."""

    def __init__(
        self,
        store: Store,
        *,
        conn: str,
        side: str,
        approval_timeout_s: int,
        notify_channels: list[str],
        notify: Any,
        on_approval_decided: Callable[[dict, bool], Awaitable[None]] | None = None,
        on_decision_answered: Callable[[dict], Awaitable[None]] | None = None,
        on_human_notify: Callable[[dict], Awaitable[None]] | None = None,
        blobs: Any = None,
        peer_side: str | None = None,
        native_tool_origin: str | None = None,
    ) -> None:
        """Create the service.

        Args:
            store: Persistent store.
            conn: Connection identifier.
            side: Local protocol side.
            approval_timeout_s: ``approval_timeout_seconds`` (default 1800).
            notify_channels: Configured notification channels (``im`` / ``web``).
            notify: :class:`bridge.app.notify.NotifyService` for outbound events.
            on_approval_decided: Coroutine with ``(approval, allowed)`` invoked after a
                decision is recorded so the task can proceed or stop.
            on_decision_answered: Coroutine invoked with the answered decision.
            on_human_notify: Coroutine used to ping a human (IM/web).
            blobs: :class:`bridge.app.blobs.BlobService` for attachment validation.
            peer_side: Trusted protocol side of the peer. The composition root SHOULD
                pass ``Session.peer_side`` after the handshake, or call
                :meth:`bind_peer_side`; ``None`` keeps the A-side default ``"B"``
                (the only side that produces ``native_tool`` requests). A value taken
                from a message payload MUST NOT be passed here.
            native_tool_origin: Trusted side allowed to originate ``native_tool``
                requests on this connection. Defaults to ``"B"``; A never produces
                them itself, so the local side is always excluded.
        """
        self._store = store
        self._conn = conn
        self._side = side
        self._timeout_s = approval_timeout_s
        self._channels = notify_channels
        self._notify = notify
        self._on_approval_decided = on_approval_decided
        self._on_decision_answered = on_decision_answered
        self._on_human_notify = on_human_notify
        self.blobs = blobs
        self._peer_side = peer_side
        self._native_tool_origin = native_tool_origin or SIDE_B
        #: Authenticated connection/session identity currently bound by the
        #: composition root. Lookup only answers for these exact values (§12.7).
        self._conn = conn
        self._sid: str | None = None
        #: ``(message, params, timeout_s) -> dict`` used by the *receiving* role
        #: to query the peer's authoritative approval row. Supplied by assembly
        #: from the live session; ``None`` means lookup is unsupported here.
        self._peer_call: Any = None
        #: Authenticated capability set of the peer, supplied by assembly from
        #: ``Session.peer_caps``. Remote evidence may only be requested when the
        #: peer actually advertised ``approval.lookup``; an unknown capability
        #: is a refusal, never an optimistic attempt.
        self._peer_caps: dict | None = None

    # -- registration ------------------------------------------------------------------

    def register(self, router: Any) -> None:
        """Register every approval/decision handler on ``router`` (§9.2).

        Args:
            router: :class:`bridge.router.Router` instance.
        """
        router.register(
            "approval.request", lambda params, ctx: self.handle_request(params, ctx=ctx)
        )
        router.register(
            "approval.decision",
            lambda params, ctx: self.handle_decision(params, ctx=ctx),
        )
        router.register("approval.lookup", lambda params, ctx: self.lookup(params))
        router.register("decision.answer", lambda params, ctx: self.answer(params))

    def bind_peer_side(self, peer_side: str | None) -> None:
        """Record the authenticated peer side for source checks (see ``handle_request``).

        The value MUST come from the handshake transcript (``Session.peer_side``),
        never from a message payload. Passing ``None`` falls back to the default
        ``native_tool`` origin (``"B"``).

        Args:
            peer_side: Protocol side authenticated for the current connection.
        """
        self._peer_side = peer_side or None

    def bind_peer_caps(self, caps: dict | None) -> None:
        """Record the authenticated peer capability set (§4.5, §12.7.4).

        Only the handshake's ``caps`` is accepted: the composition root passes
        ``Session.peer_caps``. A missing capability is treated as "does not
        support ``approval.lookup``" and remote evidence resolution fails closed.

        Args:
            caps: Peer capability object from the authenticated handshake, or
                ``None`` when there is no live handshake.
        """
        self._peer_caps = caps if isinstance(caps, dict) else None

    def _peer_supports_lookup(self) -> bool:
        """Whether the authenticated peer allows an ``approval.lookup`` attempt.

        Unknown caps are *unsupported*: assembly binds ``Session.peer_caps`` on
        every ready handshake, so ``None`` here means the trusted capability set
        is missing (before the handshake, or after the link was lost). An
        optimistic query would leak a request to a peer that may not answer, so
        the lookup fails closed instead.

        Returns:
            ``True`` only when the bound handshake ``features`` contains
            ``approval.lookup``.
        """
        if self._peer_caps is None:
            return False
        features = self._peer_caps.get("features")
        return isinstance(features, list) and "approval.lookup" in features

    def bind_session(self, conn: str, sid: str | None) -> None:
        """Bind the authenticated session identity used by the evidence rules (§12.7).

        A lookup answer is only valid for the session that is live *now*; after a
        reconnect the new ``sid`` makes every old row unanswerable, which is the
        fail-closed behaviour the protocol requires. Passing ``None`` clears the
        binding (the link is down), so no lookup can answer until a new handshake.

        Args:
            conn: Connection identifier.
            sid: Session id of the authenticated handshake, or ``None``.
        """
        self._conn = conn
        self._sid = sid or None
        if sid is None:
            # No live session: a receiving-side lookup must not even try.
            self._peer_call = None
            self._peer_caps = None

    def session_identity(self) -> tuple[str, str] | None:
        """Return ``(conn, sid)`` when a session is bound, else ``None``.

        Returns:
            The current identity or ``None``.
        """
        if isinstance(self._sid, str) and self._sid:
            return self._conn, self._sid
        return None

    def set_peer_call(self, call: Any) -> None:
        """Install the live-session call hook used for ``approval.lookup``.

        The hook MUST be bound to exactly one session and MUST fail once that
        session is no longer ready/current. Passing ``None`` disables remote
        lookup (fail-closed: references cannot be verified).

        Args:
            call: ``async (message, params, timeout_s) -> dict`` or ``None``.
        """
        self._peer_call = call

    # -- approvals ---------------------------------------------------------------------

    def _trusted_native_origin(self) -> str:
        """Return the trusted origin side for ``native_tool`` requests.

        Trust comes **only** from assembly: the value the composition root passes to
        the constructor or to :meth:`bind_peer_side`, taken from the authenticated
        handshake (``Session.peer_side``, derived from the signed ``hello`` /
        ``auth_ack``). It is deliberately **not** read from
        ``MessageContext.peer_side``: today that field is filled straight from the
        forwarded payload (``router.py`` reads ``msg["_peer_side"]``), and no session
        code stamps it, so treating it as evidence would be trusting the wire. The
        explicit default is ``"B"`` — A never produces native tool approvals itself.

        Returns:
            The trusted side string.
        """
        if isinstance(self._peer_side, str) and self._peer_side:
            return self._peer_side
        return self._native_tool_origin

    def is_local_origin(self, approval: dict) -> bool:
        """Whether an approval row was opened by this endpoint, not mirrored.

        A local gate is answered by this side's human only; its decision must not
        be reflected back to the peer as ``approval.decision`` (the peer never
        asked, and would treat it as a mirrored gate). Conversely a peer-originated
        row may not be answered by a decision event from that same peer.

        Args:
            approval: Stored approval row.

        Returns:
            ``True`` when ``origin_side`` is this endpoint's side.
        """
        return approval.get("origin_side") == self._side

    async def handle_request(self, params: dict, *, ctx: Any = None) -> dict:
        """Handle an inbound ``approval.request``: queue it and notify a human (§12.2).

        ``native_tool`` requests are accepted only when the *trusted* peer side is
        the producing side (``B``). Trust is supplied by assembly
        (``peer_side=...`` / :meth:`bind_peer_side`), never by the payload's
        ``origin_side`` / ``_peer_side``: those are attacker-controlled text, which is
        also why ``ctx`` is not consulted here (its ``peer_side`` is filled from the
        forwarded payload). A still never creates ``native_tool`` requests itself.

        Args:
            params: Approval request parameters.
            ctx: Router message context, accepted for registration parity only.

        Returns:
            ``{"approval_id", "accepted": True, "dedup": bool}``.

        Raises:
            BridgeError: ``capability_unavailable`` when this endpoint cannot handle
                the type or the trusted source is wrong, ``approval_expired`` when
                already overdue, ``approval_mismatch`` when ``request_digest`` does
                not equal the digest recomputed from the real fields.
        """
        approval_id = params.get("approval_id")
        approval_type = params.get("approval_type")
        if not isinstance(approval_id, str) or not approval_id:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "approval_id"})
        if approval_type not in APPROVAL_TYPES:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "approval_type"})
        # Trusted source side for this message. It comes from assembly only (the
        # constructor or ``bind_peer_side``), i.e. from the authenticated handshake —
        # never from the payload or from the router context fed by it.
        trusted = self._trusted_native_origin()
        if approval_type == APPROVAL_NATIVE_TOOL:
            # Native tool approvals are produced by the peer (DSH) only. A never
            # produces them itself, so the local side can never be the origin, and a
            # payload's ``origin_side`` cannot make an untrusted connection trusted.
            if trusted != self._native_tool_origin or trusted == self._side:
                logger.warning(
                    "bridge refused native_tool request from untrusted side=%s id=%s",
                    trusted,
                    approval_id,
                )
                raise BridgeError(
                    ERR_CAPABILITY_UNAVAILABLE, details={"type": approval_type}
                )

        digest = params.get("request_digest")
        if not isinstance(digest, str) or not digest:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "request_digest"})
        # Hash exactly the fields the sender hashed: absent optional values enter as
        # ``None`` (never as a rewritten default), otherwise a legitimate request
        # would be refused for a difference the sender never made.
        expected = request_digest_for(
            params.get("tool"),
            params.get("reason"),
            params.get("call_id"),
            params.get("session_id"),
            params.get("task_id"),
        )
        if expected != digest:
            logger.warning(
                "bridge approval request digest mismatch id=%s type=%s",
                approval_id,
                approval_type,
            )
            raise BridgeError(
                ERR_APPROVAL_MISMATCH, details={"field": "request_digest"}
            )

        expires_at_raw = params.get("expires_at")
        expires_at = self._parse_iso(expires_at_raw)
        if expires_at is None:
            expires_at = time.time() + self._timeout_s
        if expires_at <= time.time():
            raise BridgeError(ERR_APPROVAL_EXPIRED)

        stored = await self._store.put_approval(
            {
                "approval_id": approval_id,
                "approval_type": approval_type,
                "task_id": params.get("task_id"),
                "root_task_id": params.get("root_task_id"),
                "session_id": params.get("session_id"),
                "tool": params.get("tool"),
                # A legal request may carry ``reason: null``. The digest above is
                # computed over that null and stays unchanged; only the stored,
                # displayed value is coerced, because ``approvals.reason`` is
                # ``TEXT NOT NULL``.
                "reason": params.get("reason") or "",
                "display_reason": params.get("display_reason") or {},
                "call_id": params.get("call_id"),
                "request_digest": digest,
                "notify_id": params.get("notify_id"),
                # Stamped from the authenticated connection, not from the payload.
                "origin_side": trusted,
                # This row records a question the *peer* opened; it is a mirror,
                # never authority for a lookup answer (§12.7.3).
                "source": "peer_request",
                "gate_scope": "inbound_release",
                "expires_at": expires_at,
            }
        )
        if not stored["dedup"]:
            await self._notify_human(stored)
            logger.info(
                "bridge approval queued id=%s type=%s task=%s",
                approval_id,
                approval_type,
                stored["task_id"],
            )
        return {"approval_id": approval_id, "accepted": True, "dedup": stored["dedup"]}

    async def invalidate_native_pending(self, reason: str = "unavailable") -> list[str]:
        """Fail closed every approval whose answer channel just died.

        Covers both approval kinds whose pending question is bound to a live
        process/session:

        * ``native_tool`` — the peer's pending promise is process-local;
        * ``cross_end_submit`` — the held submission was gated on a question that
          this connection can no longer deliver/answer.

        After a restart, a disconnect or a new ``sid`` none of them may stay
        answerable, and none may be resumed into an execution. Pending rows become
        ``unavailable``; a local held task is moved to ``needs_human`` and the peer
        receives a durable ``task.event`` so it does not poll forever. A mirrored
        gate (outbound task) is only marked ``needs_human`` locally: this side is
        not its executor and must not invent a terminal state for the peer.

        Locally scoped bookkeeping only: no wire field, no AAD, no protocol change.

        Args:
            reason: Audit reason recorded on each invalidated row.

        Returns:
            The ``approval_id`` values that were invalidated.
        """
        invalidated = await self._store.invalidate_pending_approvals(
            [APPROVAL_NATIVE_TOOL, APPROVAL_CROSS_END_SUBMIT], reason=reason
        )
        for approval_id in invalidated:
            approval = await self._store.get_approval(approval_id)
            if (
                approval is None
                or approval["approval_type"] != APPROVAL_CROSS_END_SUBMIT
            ):
                continue
            task_id = approval.get("task_id")
            if not task_id:
                continue
            task = await self._store.get_task(task_id)
            if task is None or task["status"] != STATUS_PENDING_APPROVAL:
                continue
            error = {
                "code": "approval_unavailable",
                "message": f"approval channel lost ({reason})",
                "details": None,
            }
            updated = await self._store.transition(
                task_id, STATUS_NEEDS_HUMAN, eseq=int(task["eseq"]) + 1, error=error
            )
            if task["direction"] == "inbound":
                # The peer owns the submission and is polling this side: tell it
                # the gate is gone so it can park the task instead of waiting.
                await self._notify.emit(
                    updated,
                    EVENT_NEEDS_HUMAN,
                    STATUS_NEEDS_HUMAN,
                    error=error,
                    eseq=updated["eseq"],
                )
            logger.info(
                "bridge approval gate closed task=%s approval=%s reason=%s direction=%s",
                task_id,
                approval_id,
                reason,
                task["direction"],
            )
        if invalidated:
            logger.info(
                "bridge invalidated %d pending approval(s) reason=%s",
                len(invalidated),
                reason,
            )
        return invalidated

    async def handle_decision(self, params: dict, *, ctx: Any = None) -> None:
        """Handle an inbound ``approval.decision`` event (§12.3).

        Args:
            params: Decision parameters.
            ctx: Router message context, accepted for registration parity only.

        Raises:
            BridgeError: ``agent_cannot_approve`` for non-human actors,
                ``approval_mismatch`` when ``request_digest`` differs from the stored
                digest, ``bad_params`` for malformed fields.
        """
        actor_kind = params.get("actor_kind")
        if actor_kind != ACTOR_HUMAN:
            logger.warning(
                "bridge rejected non-human approval decision actor_kind=%s", actor_kind
            )
            raise BridgeError(ERR_AGENT_CANNOT_APPROVE)
        approval_id = params.get("approval_id")
        if not isinstance(approval_id, str) or not approval_id:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "approval_id"})
        outcome = params.get("outcome")
        if outcome not in APPROVAL_OUTCOMES:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "outcome"})

        stored = await self._store.get_approval(approval_id)
        if stored is None:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "approval_id"})
        if self.is_local_origin(stored):
            # A gate this side opened is answered by its own human. A decision
            # event from the peer would let it release our held task.
            logger.warning(
                "bridge refused peer decision for local approval id=%s", approval_id
            )
            raise BridgeError(ERR_APPROVAL_MISMATCH, details={"field": "approval_id"})
        # §12.3: the decision must be bound to exactly the request it answers.
        if params.get("request_digest") != stored["request_digest"]:
            logger.warning(
                "bridge approval decision digest mismatch id=%s outcome=%s",
                approval_id,
                outcome,
            )
            raise BridgeError(
                ERR_APPROVAL_MISMATCH, details={"field": "request_digest"}
            )

        identity = self.session_identity()
        applied, reason = await self._store.decide_approval(
            approval_id,
            {
                "outcome": outcome,
                "actor": params.get("actor"),
                "actor_kind": actor_kind,
                "channel": params.get("channel"),
                "reason": params.get("reason"),
            },
            conn=identity[0] if identity else None,
            sid=identity[1] if identity else None,
        )
        if not applied:
            logger.info(
                "bridge approval decision ignored id=%s reason=%s", approval_id, reason
            )
            return
        approval = await self._store.get_approval(approval_id)
        if approval is None:
            return
        await self._apply(approval)

    async def lookup(self, params: dict) -> dict:
        """Answer ``approval.lookup`` with authoritative evidence (§12.7.3).

        This is the **authority** role: only a gate this endpoint opened itself
        (``source="local"``) and decided on the *current* authenticated session is
        answered. A mirror of the peer's gate is not authority, an old row without
        ``conn``/``sid``/``submit_digest`` is not evidence, and a new ``sid`` makes
        every older decision unanswerable. The method is strictly read-only.

        Args:
            params: ``{"approval_id", "task_id", "root_task_id", "session_id",
                "submit_digest"}``.

        Returns:
            The evidence object described by §12.7.2.

        Raises:
            BridgeError: ``bad_params`` for malformed fields,
                ``approval_mismatch`` for unknown/other-type rows or binding
                mismatches, ``approval_evidence_missing`` for incomplete/old/session-
                mismatched evidence, ``approval_expired`` past the deadline, and
                ``approval_already_decided`` when the gate was released to another task.
        """
        approval_id = params.get("approval_id")
        if not isinstance(approval_id, str) or not approval_id:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "approval_id"})
        task_id = params.get("task_id")
        root_task_id = params.get("root_task_id")
        expected_digest = params.get("submit_digest")
        if not isinstance(task_id, str) or not task_id:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "task_id"})
        if not isinstance(root_task_id, str) or not root_task_id:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "root_task_id"})
        if "session_id" not in params:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "session_id"})
        if not isinstance(expected_digest, str) or not expected_digest:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "submit_digest"})

        approval = await self._store.get_approval(approval_id)
        if (
            approval is None
            or approval["approval_type"] != APPROVAL_CROSS_END_SUBMIT
            or approval.get("source") != "local"
            or approval.get("origin_side") != self._side
        ):
            # Unknown ids, foreign gate types and mirrored peer gates are all
            # "not authority for this query"; never reveal which.
            raise BridgeError(ERR_APPROVAL_MISMATCH, details={"field": "approval_id"})

        if not self._evidence_complete(approval):
            logger.warning(
                "bridge lookup refused incomplete evidence id=%s source=%s",
                approval_id,
                approval.get("source"),
            )
            raise BridgeError(ERR_APPROVAL_EVIDENCE_MISSING)

        identity = self.session_identity()
        if (
            identity is None
            or approval.get("conn") != identity[0]
            or approval.get("sid") != identity[1]
        ):
            # A decision made on an older session is not evidence for this one.
            logger.warning(
                "bridge lookup refused session-mismatched evidence id=%s", approval_id
            )
            raise BridgeError(ERR_APPROVAL_EVIDENCE_MISSING)

        if approval["expires_at"] <= time.time():
            raise BridgeError(ERR_APPROVAL_EXPIRED)

        released = approval.get("released_by_task")
        if not released:
            # The gate exists but was never released to a submission.
            raise BridgeError(
                ERR_APPROVAL_MISMATCH, details={"field": "released_by_task"}
            )
        if released != task_id:
            raise BridgeError(ERR_APPROVAL_ALREADY_DECIDED)

        if (
            approval.get("task_id") != task_id
            or approval.get("root_task_id") != root_task_id
            or approval.get("session_id") != params.get("session_id")
            or approval.get("submit_digest") != expected_digest
        ):
            raise BridgeError(ERR_APPROVAL_MISMATCH, details={"field": "binding"})

        if (
            approval.get("outcome") not in APPROVAL_ALLOWING_OUTCOMES
            or approval.get("actor_kind") != ACTOR_HUMAN
        ):
            raise BridgeError(ERR_APPROVAL_MISMATCH, details={"field": "outcome"})

        return {
            "approval_id": approval["approval_id"],
            "approval_type": approval["approval_type"],
            "state": "decided",
            "outcome": approval["outcome"],
            "actor": approval.get("actor"),
            "actor_kind": approval.get("actor_kind"),
            "channel": approval.get("channel"),
            "decided_at": self._iso(approval["decided_at"])
            if approval.get("decided_at")
            else None,
            "expires_at": self._iso(approval["expires_at"]),
            "task_id": approval.get("task_id"),
            "root_task_id": approval.get("root_task_id"),
            "session_id": approval.get("session_id"),
            "request_digest": approval.get("request_digest"),
            "submit_digest": approval.get("submit_digest"),
            "conn": approval.get("conn"),
            "sid": approval.get("sid"),
            "side": self._side,
            "released_by_task": released,
        }

    def _evidence_complete(self, approval: dict) -> bool:
        """Whether a row carries the durable evidence §12.7 requires.

        Args:
            approval: Stored approval row.

        Returns:
            ``True`` only when decision, human actor, digest and session identity
            are all present. Old rows are readable but never usable as evidence.
        """
        return bool(
            approval.get("approval_type") == APPROVAL_CROSS_END_SUBMIT
            and approval.get("state") == "decided"
            and approval.get("outcome") in APPROVAL_OUTCOMES
            and approval.get("actor_kind") == ACTOR_HUMAN
            and isinstance(approval.get("actor"), str)
            and approval["actor"]
            and approval.get("submit_digest")
            and approval.get("conn")
            and approval.get("sid")
            and approval.get("decided_at")
        )

    def check_submit_ref(self, params: dict) -> None:
        """Validate the self-consistency of an ``approval_ref`` (no store, no network).

        This is only the cheap gate: the reference must name an id, carry the digest
        of *this* submission, claim a human and not be expired. It proves nothing
        about a real human decision; evidence is resolved separately.

        Args:
            params: ``task.submit`` parameters carrying ``approval_ref``.

        Raises:
            BridgeError: ``approval_mismatch`` / ``approval_digest_mismatch`` /
                ``agent_cannot_approve`` / ``approval_expired`` on a malformed ref.
        """
        ref = params.get("approval_ref")
        if not isinstance(ref, dict):
            raise BridgeError(ERR_APPROVAL_MISMATCH, details={"field": "approval_ref"})
        approval_id = ref.get("approval_id")
        if not isinstance(approval_id, str) or not approval_id:
            raise BridgeError(ERR_APPROVAL_MISMATCH, details={"field": "approval_id"})
        if ref.get("actor_kind") != ACTOR_HUMAN:
            raise BridgeError(ERR_AGENT_CANNOT_APPROVE)
        expires_at = self._parse_iso(ref.get("expires_at"))
        if expires_at is None or expires_at <= time.time():
            raise BridgeError(ERR_APPROVAL_EXPIRED)
        expected = compute_submit_digest(params)
        if ref.get("submit_digest") != expected:
            raise BridgeError(ERR_APPROVAL_DIGEST_MISMATCH)

    async def resolve_submit_evidence(self, params: dict) -> dict:
        """Prove an inbound ``approval_ref`` and return the evidence row (§12.5/§12.7.4).

        Local evidence is used only when it is complete, bound to exactly this
        submission and to the live session. Otherwise the peer's authority is
        queried on the *current* session; the response is re-checked against the
        session captured before the call and then persisted as a ``peer_lookup``
        mirror. Any failure is fail-closed: there is no fallback to "treat it as
        no reference" and no way for the ref's self-declared fields to authorize.

        Args:
            params: ``task.submit`` parameters carrying ``approval_ref``.

        Returns:
            The local evidence row or the freshly imported mirror row.

        Raises:
            BridgeError: ``approval_lookup_failed`` when the query cannot be made
                or the session raced, the authoritative refusal codes when the peer
                refused, and ``approval_evidence_missing`` when an imported mirror
                could not be stored.
        """
        ref = params.get("approval_ref")
        if not isinstance(ref, dict):
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "approval_ref"})
        approval_id = ref.get("approval_id")
        if not isinstance(approval_id, str) or not approval_id:
            raise BridgeError(ERR_APPROVAL_MISMATCH, details={"field": "approval_id"})

        local = await self._store.get_approval(approval_id)
        if local is not None and self._local_evidence_usable(local):
            self._check_evidence_bindings(params, local, ref)
            return local

        if self._peer_call is None or not self._peer_supports_lookup():
            logger.warning(
                "bridge approval lookup unsupported id=%s task=%s",
                approval_id,
                params.get("task_id"),
            )
            raise BridgeError(ERR_APPROVAL_LOOKUP_FAILED)
        identity = self.session_identity()
        if identity is None:
            raise BridgeError(ERR_APPROVAL_LOOKUP_FAILED)
        # Capture the authenticated peer side with the session identity: both
        # must still be the same when the answer returns (§12.7.4 step 1/3).
        peer_side = self._peer_side
        if not isinstance(peer_side, str) or not peer_side:
            raise BridgeError(ERR_APPROVAL_LOOKUP_FAILED)

        request = {
            "approval_id": approval_id,
            "task_id": params.get("task_id"),
            "root_task_id": params.get("root_task_id"),
            "session_id": params.get("session_id"),
            "submit_digest": compute_submit_digest(params),
        }
        try:
            evidence = await self._peer_call(MSG_APPROVAL_LOOKUP, request, 15.0)
        except BridgeError as exc:
            if exc.code == ERR_APPROVAL_EVIDENCE_MISSING:
                # The only refusal the receiver reports verbatim; every other
                # authority error is a failed lookup per §12.7.5.
                logger.warning(
                    "bridge approval lookup refused id=%s code=%s",
                    approval_id,
                    exc.code,
                )
                raise
            logger.warning(
                "bridge approval lookup failed id=%s code=%s", approval_id, exc.code
            )
            raise BridgeError(ERR_APPROVAL_LOOKUP_FAILED) from exc
        except Exception as exc:
            logger.warning(
                "bridge approval lookup error id=%s error=%s",
                approval_id,
                type(exc).__name__,
            )
            raise BridgeError(ERR_APPROVAL_LOOKUP_FAILED) from exc

        # The session and the authenticated peer side may have changed while the
        # answer was in flight. Only the same captured session can be evidence.
        if self.session_identity() != identity or self._peer_side != peer_side:
            logger.warning(
                "bridge approval lookup session raced id=%s task=%s",
                approval_id,
                params.get("task_id"),
            )
            raise BridgeError(ERR_APPROVAL_LOOKUP_FAILED)

        self._verify_evidence_response(params, evidence, identity, peer_side, ref)
        mirror = {
            "approval_id": approval_id,
            "approval_type": APPROVAL_CROSS_END_SUBMIT,
            "task_id": evidence.get("task_id"),
            "root_task_id": evidence.get("root_task_id"),
            "session_id": evidence.get("session_id"),
            "tool": None,
            "reason": "",
            "display_reason": {},
            "call_id": None,
            "request_digest": evidence.get("request_digest") or "",
            "submit_digest": evidence.get("submit_digest"),
            "notify_id": None,
            "origin_side": evidence.get("side"),
            "conn": evidence.get("conn"),
            "sid": evidence.get("sid"),
            "released_by_task": evidence.get("released_by_task"),
            "evidence": evidence,
            "expires_at": self._parse_iso(evidence.get("expires_at"))
            or time.time() - 1,
            "outcome": evidence.get("outcome"),
            "actor": evidence.get("actor"),
            "actor_kind": evidence.get("actor_kind"),
            "channel": evidence.get("channel"),
            "decided_reason": None,
            "decided_at_epoch": self._parse_iso(evidence.get("decided_at")),
        }
        stored = await self._store.import_approval_mirror(mirror)
        if stored is None:
            logger.warning(
                "bridge approval mirror could not be persisted id=%s", approval_id
            )
            raise BridgeError(ERR_APPROVAL_EVIDENCE_MISSING)
        return stored

    def _local_evidence_usable(self, approval: dict) -> bool:
        """Whether a stored row is complete local evidence for an inbound ref.

        An ``outbound_submit`` gate belongs to the opposite role (this endpoint was
        the initiator) and MUST NOT authorize an inbound submission. A local
        receiving-side gate or a previously imported ``peer_lookup`` mirror may,
        once its evidence is complete and bound to the live session; the local
        deadline is checked by :meth:`_check_evidence_bindings`, so an overdue
        gate is reported as ``approval_expired`` (never as a lookup failure or a
        grant).

        Args:
            approval: Stored approval row.

        Returns:
            ``True`` when the row can be used without a remote query.
        """
        if approval.get("source") == "local":
            if approval.get("gate_scope") == "outbound_submit":
                return False
        if not self._evidence_complete(approval):
            return False
        identity = self.session_identity()
        if (
            identity is None
            or approval.get("conn") != identity[0]
            or approval.get("sid") != identity[1]
        ):
            return False
        # Expiry is checked by ``_check_evidence_bindings`` so the caller sees the
        # specific ``approval_expired`` refusal instead of a generic lookup failure.
        return True

    def _check_evidence_bindings(self, params: dict, approval: dict, ref: dict) -> None:
        """Compare local evidence with the actual submission and the ref.

        Args:
            params: ``task.submit`` parameters.
            approval: Evidence row.
            ref: ``approval_ref`` from the submission.

        Raises:
            BridgeError: ``approval_mismatch`` / ``approval_digest_mismatch`` /
                ``agent_cannot_approve`` / ``approval_expired`` on any difference.
        """
        if ref.get("actor_kind") != ACTOR_HUMAN:
            raise BridgeError(ERR_AGENT_CANNOT_APPROVE)
        expected = compute_submit_digest(params)
        if ref.get("submit_digest") != expected:
            raise BridgeError(ERR_APPROVAL_DIGEST_MISMATCH)
        if approval.get("submit_digest") != expected:
            raise BridgeError(ERR_APPROVAL_DIGEST_MISMATCH)
        if (
            approval.get("task_id") != params.get("task_id")
            or approval.get("root_task_id") != params.get("root_task_id")
            or approval.get("session_id") != params.get("session_id")
        ):
            raise BridgeError(ERR_APPROVAL_MISMATCH, details={"field": "task_id"})
        if approval.get("outcome") not in APPROVAL_ALLOWING_OUTCOMES:
            raise BridgeError(ERR_APPROVAL_MISMATCH, details={"field": "outcome"})
        if approval.get("actor_kind") != ACTOR_HUMAN:
            raise BridgeError(ERR_AGENT_CANNOT_APPROVE)
        if approval["expires_at"] <= time.time():
            raise BridgeError(ERR_APPROVAL_EXPIRED)

    def _verify_evidence_response(
        self,
        params: dict,
        evidence: Any,
        identity: tuple[str, str],
        peer_side: str,
        ref: dict,
    ) -> None:
        """Validate one authoritative lookup answer against the real submission.

        Nothing from the ref is trusted here except the id it named; the content
        digest is recomputed from ``params`` and compared with both the answer and
        the ref. The answer's session identity must equal the one captured before
        the query, and its ``side`` must equal the authenticated peer side.

        Args:
            params: ``task.submit`` parameters.
            evidence: Decoded lookup result.
            identity: ``(conn, sid)`` captured before the call.
            peer_side: Authenticated peer side captured before the call.
            ref: ``approval_ref`` from the submission.

        Raises:
            BridgeError: ``approval_mismatch`` on any binding/type/actor problem,
                ``approval_digest_mismatch`` for the content digest,
                ``approval_expired`` past the deadline.
        """
        if not isinstance(evidence, dict):
            raise BridgeError(ERR_APPROVAL_LOOKUP_FAILED)
        expected = compute_submit_digest(params)
        if ref.get("submit_digest") != expected:
            raise BridgeError(ERR_APPROVAL_DIGEST_MISMATCH)
        if evidence.get("submit_digest") != expected:
            raise BridgeError(ERR_APPROVAL_DIGEST_MISMATCH)
        if (
            evidence.get("approval_id")
            != params.get("approval_ref", {}).get("approval_id")
            or evidence.get("approval_type") != APPROVAL_CROSS_END_SUBMIT
            or evidence.get("state") != "decided"
            or evidence.get("outcome") != OUTCOME_ALLOWED_ONCE
            or evidence.get("actor_kind") != ACTOR_HUMAN
        ):
            raise BridgeError(ERR_APPROVAL_MISMATCH, details={"field": "evidence"})
        if (
            evidence.get("task_id") != params.get("task_id")
            or evidence.get("root_task_id") != params.get("root_task_id")
            or evidence.get("session_id") != params.get("session_id")
            or evidence.get("released_by_task") != params.get("task_id")
        ):
            raise BridgeError(ERR_APPROVAL_MISMATCH, details={"field": "binding"})
        if evidence.get("conn") != identity[0] or evidence.get("sid") != identity[1]:
            raise BridgeError(ERR_APPROVAL_EVIDENCE_MISSING)
        if evidence.get("side") != peer_side:
            # An unknown or changed peer side is never accepted as evidence.
            raise BridgeError(ERR_APPROVAL_MISMATCH, details={"field": "side"})
        expires_at = self._parse_iso(evidence.get("expires_at"))
        if expires_at is None or expires_at <= time.time():
            raise BridgeError(ERR_APPROVAL_EXPIRED)

    def build_submit_ref(self, approval: dict) -> dict:
        """Build the wire ``approval_ref`` for a locally released gate (§12.5).

        Args:
            approval: Decided local ``cross_end_submit`` row.

        Returns:
            Reference dictionary carrying the approval id, full content digest,
            human actor and deadline.
        """
        return {
            "approval_id": approval["approval_id"],
            "submit_digest": approval["submit_digest"],
            "actor": approval.get("actor"),
            "actor_kind": approval.get("actor_kind"),
            "decided_at": self._iso(approval["decided_at"])
            if approval.get("decided_at")
            else self._iso(time.time()),
            "expires_at": self._iso(approval["expires_at"]),
        }

    async def release_outbound_gate(self, approval: dict, params: dict) -> bool:
        """Verify a decided local gate and atomically release it for one submission.

        Args:
            approval: Decided local approval row.
            params: Wire ``task.submit`` parameters the gate is being released for.

        Returns:
            ``True`` when the release was recorded by this call.

        Raises:
            BridgeError: ``approval_mismatch`` / ``approval_expired`` /
                ``agent_cannot_approve`` when the gate may not be released.
        """
        if (
            approval.get("approval_type") != APPROVAL_CROSS_END_SUBMIT
            or approval.get("source") != "local"
            or approval.get("gate_scope") != "outbound_submit"
            or approval.get("origin_side") != self._side
        ):
            raise BridgeError(ERR_APPROVAL_MISMATCH, details={"field": "approval_id"})
        if (
            approval.get("state") != "decided"
            or approval.get("outcome") not in APPROVAL_ALLOWING_OUTCOMES
            or approval.get("actor_kind") != ACTOR_HUMAN
        ):
            raise BridgeError(ERR_APPROVAL_MISMATCH, details={"field": "outcome"})
        if approval["expires_at"] <= time.time():
            raise BridgeError(ERR_APPROVAL_EXPIRED)
        identity = self.session_identity()
        if (
            identity is None
            or approval.get("conn") != identity[0]
            or approval.get("sid") != identity[1]
        ):
            raise BridgeError(ERR_APPROVAL_EVIDENCE_MISSING)
        if approval.get("submit_digest") != compute_submit_digest(params):
            raise BridgeError(ERR_APPROVAL_DIGEST_MISMATCH)
        return await self._store.claim_approval_release(
            approval["approval_id"], params["task_id"]
        )

    async def human_decide(
        self,
        approval_id: str,
        *,
        allowed: bool,
        actor: str,
        channel: str,
        reason: str | None = None,
    ) -> tuple[bool, str | None]:
        """Record a human decision taken locally (web page or command).

        This is the only way an approval becomes ``allowed-once`` from this side.

        Args:
            approval_id: Approval identifier.
            allowed: ``True`` for ``allowed-once``, ``False`` for ``rejected``.
            actor: Human identity, e.g. ``astrbot_admin:alice``.
            channel: ``im`` or ``web``.
            reason: Optional reason text.

        Returns:
            ``(applied, reason)`` from the store.

        Raises:
            BridgeError: ``agent_cannot_approve`` when ``actor`` is not human-shaped.
        """
        if not actor or ":agent" in actor or actor.startswith("agent:"):
            raise BridgeError(ERR_AGENT_CANNOT_APPROVE)
        outcome = "allowed-once" if allowed else OUTCOME_REJECTED
        identity = self.session_identity()
        applied, fail_reason = await self._store.decide_approval(
            approval_id,
            {
                "outcome": outcome,
                "actor": actor,
                "actor_kind": ACTOR_HUMAN,
                "channel": channel,
                "reason": reason,
            },
            conn=identity[0] if identity else None,
            sid=identity[1] if identity else None,
        )
        if not applied:
            return False, fail_reason
        approval = await self._store.get_approval(approval_id)
        if approval is None:
            return False, "not_found"
        await self._apply(approval)
        # Only a *mirrored* peer gate is answered over the wire. A locally opened
        # gate is settled here; echoing its outcome back as ``approval.decision``
        # would tell the peer to settle a request it never asked about.
        if not self.is_local_origin(approval):
            await self._send_decision_event(approval)
        return True, None

    async def _apply(self, approval: dict) -> None:
        """Notify the owning task that an approval was decided.

        Args:
            approval: Decided approval row.
        """
        allowed = approval["outcome"] in APPROVAL_ALLOWING_OUTCOMES
        if self._on_approval_decided is None:
            return
        try:
            await self._on_approval_decided(approval, allowed)
        except Exception:
            logger.exception(
                "bridge approval application failed id=%s", approval["approval_id"]
            )

    async def _send_decision_event(self, approval: dict) -> None:
        """Send ``approval.decision`` to the requesting endpoint (§12.3).

        Args:
            approval: Decided approval row.
        """
        notify_id = str(uuid.uuid4())
        params = {
            "approval_id": approval["approval_id"],
            "task_id": approval["task_id"],
            "outcome": approval["outcome"],
            "actor": approval["actor"],
            "actor_kind": approval["actor_kind"],
            "channel": approval["channel"],
            "reason": approval["decided_reason"],
            "decided_at": self._iso(approval["decided_at"] or time.time()),
            "request_digest": approval["request_digest"],
            "notify_id": notify_id,
        }
        await self._notify.emit_event(
            notify_id,
            MSG_APPROVAL_DECISION,
            params,
            approval["task_id"] or "",
            approval["root_task_id"] or approval["task_id"] or "",
        )

    async def create_cross_end_submit(
        self,
        *,
        task: dict,
        tool: str,
        reason: str,
        display_reason: dict,
        params: dict,
    ) -> dict:
        """Create a ``cross_end_submit`` approval for an inbound task (§12.5).

        Args:
            task: Stored task awaiting approval.
            tool: Action label shown to the approver.
            reason: Asker-supplied reason.
            display_reason: Localised reason strings.
            params: Original submission parameters.

        Returns:
            The stored approval row.
        """
        approval_id = str(uuid.uuid4())
        digest = request_digest(
            {
                "tool": tool,
                "reason": reason,
                "call_id": None,
                "session_id": params.get("session_id"),
                "task_id": params.get("task_id"),
            }
        )
        stored = await self._store.put_approval(
            {
                "approval_id": approval_id,
                "approval_type": APPROVAL_CROSS_END_SUBMIT,
                "task_id": task["task_id"],
                "root_task_id": task["root_task_id"],
                "session_id": params.get("session_id"),
                "tool": tool,
                "reason": reason,
                "display_reason": display_reason,
                "call_id": None,
                "request_digest": digest,
                # The complete approved content, not just the task/session label.
                # A submitted ``approval_ref`` must reproduce this digest before the
                # gate may release anything.
                "submit_digest": compute_submit_digest(params),
                "notify_id": None,
                "origin_side": self._side,
                "source": "local",
                "gate_scope": "inbound_release",
                "expires_at": time.time() + self._timeout_s,
            }
        )
        await self._notify_human(stored)
        return stored

    async def create_outbound_submit_gate(
        self,
        *,
        task: dict,
        params: dict,
        tool: str,
        reason: str,
        display_reason: dict,
    ) -> dict:
        """Open the initiating human gate for a submission this side will send (§12.5).

        This is the production path that makes a valid ``approval_ref`` reachable:
        the agent-initiated submission is not sent at all until a human on this
        endpoint answers, and the answer is bound to the complete projected content
        (``submit_digest``) and to the live session.

        Args:
            task: Pending outbound task row.
            params: Wire ``task.submit`` parameters (without ``approval_ref``).
            tool: Action label shown to the approver.
            reason: Asker-supplied reason.
            display_reason: Localised reason strings.

        Returns:
            The stored approval row.
        """
        approval_id = str(uuid.uuid4())
        digest = request_digest(
            {
                "tool": tool,
                "reason": reason,
                "call_id": None,
                "session_id": params.get("session_id"),
                "task_id": params.get("task_id"),
            }
        )
        stored = await self._store.put_approval(
            {
                "approval_id": approval_id,
                "approval_type": APPROVAL_CROSS_END_SUBMIT,
                "task_id": task["task_id"],
                "root_task_id": task["root_task_id"],
                "session_id": params.get("session_id"),
                "tool": tool,
                "reason": reason,
                "display_reason": display_reason,
                "call_id": None,
                "request_digest": digest,
                "submit_digest": compute_submit_digest(params),
                "notify_id": None,
                "origin_side": self._side,
                "source": "local",
                "gate_scope": "outbound_submit",
                "expires_at": time.time() + self._timeout_s,
            }
        )
        await self._notify_human(stored)
        return stored

    async def verify_submit_digest(self, params: dict) -> None:
        """Verify ``approval_ref.submit_digest`` against the real submission (§12.5).

        Args:
            params: ``task.submit`` parameters including ``approval_ref``.

        Raises:
            BridgeError: ``approval_digest_mismatch`` when the approved content and the
                submitted content differ; ``approval_expired`` when the approval is
                past its ``expires_at``.
        """
        approval_ref = params.get("approval_ref")
        if approval_ref is None:
            return
        if not isinstance(approval_ref, dict):
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "approval_ref"})
        expected = approval_ref.get("submit_digest")
        if not isinstance(expected, str) or not expected:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "submit_digest"})
        if approval_ref.get("actor_kind") != ACTOR_HUMAN:
            raise BridgeError(ERR_AGENT_CANNOT_APPROVE)
        expires_at = self._parse_iso(approval_ref.get("expires_at"))
        if expires_at is not None and expires_at <= time.time():
            raise BridgeError(ERR_APPROVAL_EXPIRED)
        actual = compute_submit_digest(params)
        if actual != expected:
            logger.warning(
                "bridge submit digest mismatch task=%s", params.get("task_id")
            )
            raise BridgeError(ERR_APPROVAL_DIGEST_MISMATCH)
        approval_id = approval_ref.get("approval_id")
        if not isinstance(approval_id, str) or not approval_id:
            raise BridgeError(ERR_APPROVAL_MISMATCH, details={"field": "approval_id"})
        approval = await self._store.get_approval(approval_id)
        if approval is None:
            raise BridgeError(ERR_APPROVAL_MISMATCH, details={"field": "approval_id"})
        # The ref must reproduce the digest that was persisted *when the human
        # approved*. Recomputing the digest alone would only prove that the
        # submitter can hash its own payload.
        stored_digest = approval.get("submit_digest")
        if not isinstance(stored_digest, str) or not stored_digest:
            logger.warning(
                "bridge approval has no submit_digest evidence id=%s", approval_id
            )
            raise BridgeError(ERR_APPROVAL_MISMATCH, details={"field": "submit_digest"})
        if stored_digest != expected:
            logger.warning(
                "bridge approval digest differs from approved content id=%s",
                approval_id,
            )
            raise BridgeError(ERR_APPROVAL_DIGEST_MISMATCH)
        if approval["approval_type"] != APPROVAL_CROSS_END_SUBMIT:
            raise BridgeError(ERR_APPROVAL_MISMATCH, details={"field": "approval_type"})
        if not self.is_local_origin(approval):
            # A mirror of the peer's gate is not evidence for a submission here.
            raise BridgeError(ERR_APPROVAL_MISMATCH, details={"field": "approval_id"})
        if approval.get("session_id") != params.get("session_id"):
            raise BridgeError(ERR_APPROVAL_MISMATCH, details={"field": "session_id"})
        if (
            approval["state"] != "decided"
            or approval["outcome"] not in APPROVAL_ALLOWING_OUTCOMES
        ):
            raise BridgeError(ERR_APPROVAL_MISMATCH, details={"field": "outcome"})
        if approval["actor_kind"] != ACTOR_HUMAN:
            raise BridgeError(ERR_AGENT_CANNOT_APPROVE)
        if approval["expires_at"] <= time.time():
            raise BridgeError(ERR_APPROVAL_EXPIRED)
        if approval.get("consumed_by_task"):
            raise BridgeError(ERR_APPROVAL_ALREADY_DECIDED)

    # -- business decisions ------------------------------------------------------------

    async def create_decision(
        self,
        *,
        task: dict,
        question: str,
        options: list[dict],
        allow_free_text: bool = False,
        default_option: str | None = None,
        timeout_s: int | None = None,
    ) -> dict:
        """Suspend a task with a ``decision.request`` (§9.8).

        Args:
            task: Task that needs the decision.
            question: Human-readable question.
            options: ``[{"id", "label", "consequence"}]``.
            allow_free_text: Whether free text answers are accepted.
            default_option: Optional default (never applied automatically).
            timeout_s: Override for the expiry.

        Returns:
            The stored decision row.
        """
        decision_id = str(uuid.uuid4())
        notify_id = str(uuid.uuid4())
        expires_at = time.time() + (
            timeout_s if timeout_s is not None else self._timeout_s
        )
        stored = await self._store.put_decision(
            {
                "decision_id": decision_id,
                "task_id": task["task_id"],
                "root_task_id": task["root_task_id"],
                "question": question,
                "options": options,
                "allow_free_text": allow_free_text,
                "default_option": default_option,
                "expires_at": expires_at,
                "notify_id": notify_id,
            }
        )
        from ..constants import MSG_DECISION_REQUEST

        await self._notify.emit_event(
            notify_id,
            MSG_DECISION_REQUEST,
            {
                "decision_id": decision_id,
                "task_id": task["task_id"],
                "root_task_id": task["root_task_id"],
                "question": question,
                "options": options,
                "allow_free_text": allow_free_text,
                "default_option": default_option,
                "expires_at": self._iso(expires_at),
                "notify_id": notify_id,
            },
            task["task_id"],
            task["root_task_id"],
        )
        await self._notify_human(
            {
                "approval_id": decision_id,
                "approval_type": APPROVAL_BUSINESS_DECISION,
                "task_id": task["task_id"],
                "tool": "decision",
                "reason": question,
                "display_reason": {"en": "Decision required", "zh": "需要业务决策"},
                "expires_at": expires_at,
            }
        )
        return stored

    async def answer(self, params: dict) -> dict:
        """Handle ``decision.answer``: the first human answer wins (§9.8).

        Args:
            params: ``{"decision_id", "choice", "free_text", "actor", "actor_kind"}``.

        Returns:
            ``{"decision_id", "applied", "reason"}``.

        Raises:
            BridgeError: ``agent_cannot_decide`` when the actor is not human.
        """
        if params.get("actor_kind") != ACTOR_HUMAN:
            raise BridgeError(ERR_AGENT_CANNOT_DECIDE)
        decision_id = params.get("decision_id")
        if not isinstance(decision_id, str) or not decision_id:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "decision_id"})
        applied, reason = await self._store.answer_decision(
            decision_id,
            {
                "choice": params.get("choice"),
                "free_text": params.get("free_text"),
                "actor": params.get("actor"),
                "actor_kind": params.get("actor_kind"),
            },
        )
        if not applied:
            return {"decision_id": decision_id, "applied": False, "reason": reason}
        decision = await self._store.get_decision(decision_id)
        if decision is not None and self._on_decision_answered is not None:
            try:
                await self._on_decision_answered(decision)
            except Exception:
                logger.exception(
                    "bridge decision application failed id=%s", decision_id
                )
        return {"decision_id": decision_id, "applied": True, "reason": None}

    async def human_answer_decision(
        self,
        decision_id: str,
        *,
        choice: str,
        actor: str,
        free_text: str | None = None,
    ) -> tuple[bool, str | None]:
        """Record a human answer taken from the local UI or a command.

        Args:
            decision_id: Decision identifier.
            choice: Chosen option id (or free text value).
            actor: Human identity.
            free_text: Optional free text.

        Returns:
            ``(applied, reason)``.
        """
        applied, reason = await self._store.answer_decision(
            decision_id,
            {
                "choice": choice,
                "free_text": free_text,
                "actor": actor,
                "actor_kind": ACTOR_HUMAN,
            },
        )
        if applied:
            decision = await self._store.get_decision(decision_id)
            if decision is not None and self._on_decision_answered is not None:
                await self._on_decision_answered(decision)
        return applied, reason

    # -- background loops --------------------------------------------------------------

    async def timeout_loop(self, interval_s: float = 5.0) -> None:
        """Expire approvals and decisions on schedule (§12.4, §9.8).

        Timeout always means **rejected**; a timed-out approval additionally moves its
        task to ``needs_human``.

        Args:
            interval_s: Scan interval.
        """
        import asyncio

        while True:
            try:
                for approval in await self._store.expire_approvals():
                    logger.warning(
                        "bridge approval timed out -> rejected id=%s",
                        approval["approval_id"],
                    )
                    expired = await self._store.get_approval(approval["approval_id"])
                    if expired is None:
                        continue
                    await self._apply(expired)
                    if expired["approval_type"] == APPROVAL_NATIVE_TOOL:
                        # §12.4: the peer must learn the request died, otherwise its
                        # pending promise hangs until its own signal/timeout. This is
                        # best effort — an undeliverable decision still leaves the row
                        # ``undelivered``; it never turns into a grant.
                        try:
                            await self._send_decision_event(expired)
                        except Exception:
                            logger.exception(
                                "bridge failed to send timeout decision id=%s",
                                expired["approval_id"],
                            )
                    await self._notify_human(expired, timed_out=True)
                for decision in await self._store.expire_decisions():
                    logger.warning(
                        "bridge decision timed out id=%s task=%s",
                        decision["decision_id"],
                        decision["task_id"],
                    )
                    await self._on_decision_timeout(decision)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("bridge approval timeout loop iteration failed")
            await asyncio.sleep(interval_s)

    async def _on_decision_timeout(self, decision: dict) -> None:
        """Report one expired decision to the owner callback (§9.8).

        The service does not settle the owning task itself; it forwards the
        timeout once, exactly like a human answer, with ``timed_out=True``.

        Args:
            decision: Expired decision row.
        """
        if self._on_decision_answered is None:
            return
        try:
            await self._on_decision_answered({**decision, "timed_out": True})
        except Exception:
            logger.exception(
                "bridge decision timeout handling failed id=%s", decision["decision_id"]
            )

    # -- notifying humans --------------------------------------------------------------

    async def _notify_human(self, approval: dict, *, timed_out: bool = False) -> None:
        """Ping a human through the configured channels (§12.2, PRD §6.6.7).

        Args:
            approval: Approval or decision row to announce.
            timed_out: Whether this is a timeout announcement.
        """
        if self._on_human_notify is None:
            return
        try:
            await self._on_human_notify(
                {
                    "approval_id": approval.get("approval_id"),
                    "approval_type": approval.get("approval_type"),
                    "task_id": approval.get("task_id"),
                    "tool": approval.get("tool"),
                    "reason": approval.get("reason"),
                    "display_reason": approval.get("display_reason"),
                    "expires_at": approval.get("expires_at"),
                    "timed_out": timed_out,
                    "channels": list(self._channels),
                    "origin_side": approval.get("origin_side"),
                }
            )
        except Exception:
            logger.exception("bridge human notification failed")

    # -- helpers -----------------------------------------------------------------------

    @staticmethod
    def _parse_iso(value: Any) -> float | None:
        """Parse an ISO 8601 UTC timestamp into epoch seconds.

        Args:
            value: ``2026-10-29T12:00:00.000Z`` style string, or ``None``.

        Returns:
            Epoch seconds, or ``None`` when the value is absent/invalid.
        """
        if not isinstance(value, str) or not value:
            return None
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            from datetime import datetime

            return datetime.fromisoformat(text).timestamp()
        except ValueError:
            return None

    @staticmethod
    def _iso(epoch: float) -> str:
        """Render epoch seconds as protocol ISO 8601 UTC milliseconds.

        Args:
            epoch: Unix seconds.

        Returns:
            ISO string.
        """
        millis = int(epoch * 1000)
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(millis // 1000)) + (
            f".{millis % 1000:03d}Z"
        )


def is_allowing_outcome(outcome: str | None) -> bool:
    """Whether an approval outcome permits execution (§12.3).

    ``unavailable`` and ``cancelled`` MUST be treated as rejection.

    Args:
        outcome: Outcome string.

    Returns:
        ``True`` only for ``allowed-once``.
    """
    return outcome in APPROVAL_ALLOWING_OUTCOMES


def is_fail_closed_outcome(outcome: str | None) -> bool:
    """Whether an outcome must be interpreted as refusal.

    Args:
        outcome: Outcome string.

    Returns:
        ``True`` for ``rejected`` / ``cancelled`` / ``unavailable`` / unknown values.
    """
    return outcome not in APPROVAL_ALLOWING_OUTCOMES


def request_digest_for(
    tool: str,
    reason: str,
    call_id: str | None,
    session_id: str | None,
    task_id: str | None,
) -> str:
    """Compute the ``request_digest`` binding an approval to its request (§12.2).

    Args:
        tool: Tool or action name.
        reason: Asker-supplied reason.
        call_id: Provider call id, when available.
        session_id: Session the request belongs to.
        task_id: Task the request belongs to.

    Returns:
        Base64url digest.
    """
    return request_digest(
        {
            "tool": tool,
            "reason": reason,
            "call_id": call_id,
            "session_id": session_id,
            "task_id": task_id,
        }
    )


def jcs_approval_digest(payload: dict) -> str:
    """Canonical digest used in audit logs for approval payloads.

    Args:
        payload: Approval payload.

    Returns:
        Hex SHA-256 of the canonical frame encoding.
    """
    import hashlib

    return hashlib.sha256(jcs_frame(payload)).hexdigest()


__all__ = [
    "ApprovalService",
    "build_submit_projection",
    "compute_submit_digest",
    "is_allowing_outcome",
    "is_fail_closed_outcome",
    "jcs_approval_digest",
    "request_digest_for",
    "CHANNEL_TIMEOUT",
    "ERR_TASK_NOT_FOUND",
    "OUTCOME_UNAVAILABLE",
    "utc_iso_ms",
]
