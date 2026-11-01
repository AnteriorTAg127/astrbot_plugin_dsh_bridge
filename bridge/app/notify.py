"""Notification service: at-least-once delivery, acks, wake chain and rate guards.

Implements protocol §10.3 (persist → send → retry with the documented backoff),
§11.1 (``event.ack``), §11.3 (resend as a *new* envelope with the same business
object) and §16.6 (wake chain limit, rate limit, dedupe).

Nothing in this module ever decides that a notification may be dropped: an
exhausted notification becomes ``undelivered`` and its task becomes
``needs_human`` so a human can act (§11.3).
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from collections.abc import Awaitable, Callable

from astrbot.api import logger

from ..constants import (
    EVENT_MESSAGES,
    KIND_EVT,
    MSG_EVENT_ACK,
    MSG_TASK_EVENT,
    NOTIFY_BACKOFF_S,
    NOTIFY_MAX_ATTEMPTS,
    STATUS_NEEDS_HUMAN,
    WAKE_EVENTS,
)
from ..errors import (
    ERR_BAD_PARAMS,
    ERR_EVENT_NOT_FOUND,
    ERR_WAKE_CHAIN_EXCEEDED,
    ERR_WAKE_RATE_LIMITED,
    BridgeError,
)
from ..session import utc_iso_ms
from ..store import Store


class NotifyService:
    """Outbox-driven notification emitter with wake accounting."""

    def __init__(
        self,
        store: Store,
        *,
        conn: str,
        wake_max_chain: int = 8,
        wake_rate_per_minute: int = 10,
        on_task_event: Callable[[dict], Awaitable[None]] | None = None,
        on_undelivered: Callable[[dict, str], Awaitable[None]] | None = None,
        on_event: Callable[[dict, dict, str, str], Awaitable[None]] | None = None,
        on_ack_request: Callable[[dict], Awaitable[dict]] | None = None,
    ) -> None:
        """Create the service.

        Args:
            store: Persistent store.
            conn: Connection identifier used for rate limiting keys.
            wake_max_chain: ``wake_max_chain`` configuration (§16.6).
            wake_rate_per_minute: ``wake_rate_per_minute`` configuration (§16.6).
            on_task_event: Coroutine invoked with the ``task.event`` parameters when a
                notification of that name is ready to send. It must perform the actual
                ``session.send_message``.
            on_undelivered: Coroutine invoked with ``(task, reason)`` when retries are
                exhausted, so the caller can mark the task ``needs_human``.
            on_event: Coroutine ``(params, row, task_id, root_task_id)`` used to send
                any other *existing* event message (``approval.decision``,
                ``decision.request``, …). It receives the outbox row so the caller can
                render the real envelope. Without it those messages keep failing and
                end up ``undelivered`` — there is no silent drop.
            on_ack_request: Coroutine ``(params)`` used to send an ``event.ack`` to the
                peer as a real ``req``. Distinct from :meth:`on_ack`, which handles an
                ack *received* from the peer.
        """
        self._store = store
        self._conn = conn
        self._wake_max_chain = wake_max_chain
        self._wake_rate = wake_rate_per_minute
        self._on_task_event = on_task_event
        self._on_undelivered = on_undelivered
        self._on_event = on_event
        self._on_ack_request = on_ack_request
        self._task: asyncio.Task | None = None

    # -- emitting ----------------------------------------------------------------------

    async def emit(
        self,
        task: dict,
        event: str,
        status: str,
        *,
        result: dict | None = None,
        error: dict | None = None,
        decision: dict | None = None,
        approval: dict | None = None,
        eseq: int | None = None,
    ) -> str:
        """Persist then send one ``task.event`` notification (§11.2).

        The outbox row is written before the send attempt so a crash cannot lose the
        event; delivery retries continue in :meth:`resend_loop`.

        Args:
            task: Task row the event belongs to.
            event: Event name (``completed``/``failed``/…).
            status: Resulting task status.
            result: Result object for ``completed``.
            error: Error object for ``failed``.
            decision: Inline decision payload for ``needs_decision``.
            approval: Inline approval payload for ``needs_approval``.
            eseq: Explicit event sequence; defaults to ``task.eseq + 1``.

        Returns:
            The new ``notify_id``.
        """
        notify_id = str(uuid.uuid4())
        sequence = int(eseq if eseq is not None else int(task.get("eseq", 0)) + 1)
        params = {
            "task_id": task["task_id"],
            "root_task_id": task["root_task_id"],
            "eseq": sequence,
            "event": event,
            "status": status,
            "notify_id": notify_id,
            "result": result,
            "error": error,
            "decision": decision,
            "approval": approval,
        }
        await self._store.enqueue_notify(
            notify_id,
            task["task_id"],
            task["root_task_id"],
            MSG_TASK_EVENT,
            params,
        )
        await self._deliver_now(notify_id)
        return notify_id

    async def emit_event(
        self,
        notify_id: str,
        message: str,
        params: dict,
        task_id: str,
        root_task_id: str,
    ) -> None:
        """Queue an arbitrary event message (``approval.decision`` etc.) and send it.

        Args:
            notify_id: Unique notification id.
            message: Message name.
            params: Message parameters.
            task_id: Owning task (may be an empty string for approvals without tasks).
            root_task_id: Root task for accounting.
        """
        await self._store.enqueue_notify(
            notify_id, task_id or "", root_task_id or task_id or "", message, params
        )
        await self._deliver_now(notify_id)

    async def _deliver_now(self, notify_id: str) -> None:
        """Attempt to send one queued notification immediately.

        Args:
            notify_id: Notification id.
        """
        row = await self._store.get_notify(notify_id)
        if row is None or row["delivered"] or row["undelivered"]:
            return
        try:
            await self._send(row)
        except Exception:
            logger.exception(
                "bridge immediate notify send failed notify_id=%s", notify_id
            )
            await self._schedule_retry(notify_id, row["attempts"])

    async def _send(self, row: dict) -> None:
        """Hand one outbox row to the transport callback.

        Args:
            row: Outbox row.

        Raises:
            RuntimeError: When no send callback is configured, or the message name is
                not part of the event vocabulary (§9.2).
        """
        if row["message"] == MSG_TASK_EVENT:
            if self._on_task_event is None:
                raise RuntimeError("no task.event sender configured")
            await self._on_task_event(row["params"])
            return
        if row["message"] in EVENT_MESSAGES:
            # ``approval.decision`` / ``decision.request`` / ``session.authz`` / blob
            # events: real event messages that need a real send. Retries and the
            # ``undelivered`` escalation below stay in force — nothing is dropped
            # and nothing is auto-allowed.
            if self._on_event is None:
                raise RuntimeError(f"no event sender configured for {row['message']}")
            await self._on_event(
                row["params"], row, row["task_id"], row["root_task_id"]
            )
            return
        raise RuntimeError(f"unsupported notify message {row['message']}")

    async def _schedule_retry(self, notify_id: str, attempts: int) -> None:
        """Record a failed attempt and either schedule the next one or give up.

        Args:
            notify_id: Notification id.
            attempts: Attempts already made.
        """
        row = await self._store.get_notify(notify_id)
        if row is None:
            return
        next_attempt = attempts + 1
        if next_attempt >= NOTIFY_MAX_ATTEMPTS:
            await self._store.mark_undelivered(notify_id)
            logger.warning(
                "bridge notification undelivered notify_id=%s task=%s attempts=%s",
                notify_id,
                row["task_id"],
                next_attempt,
            )
            task = (
                await self._store.get_task(row["task_id"]) if row["task_id"] else None
            )
            if task is not None:
                await self._store.mark_needs_human(
                    task["task_id"],
                    "undelivered_notification",
                    "peer never acknowledged",
                )
                refreshed = await self._store.get_task(task["task_id"])
                if refreshed is not None and self._on_undelivered is not None:
                    await self._on_undelivered(refreshed, "undelivered_notification")
            return
        delay = NOTIFY_BACKOFF_S[min(next_attempt, len(NOTIFY_BACKOFF_S) - 1)]
        import time

        await self._store.reschedule_notify(
            notify_id, next_attempt, time.time() + delay
        )

    async def resend_loop(self, interval_s: float = 1.0) -> None:
        """Continuously retry pending notifications (§10.3).

        Args:
            interval_s: Poll interval between outbox scans.
        """
        while True:
            try:
                pending = await self._store.pending_notifies(limit=32)
                for row in pending:
                    try:
                        await self._send(row)
                    except Exception:
                        logger.warning(
                            "bridge notify retry failed notify_id=%s", row["notify_id"]
                        )
                        await self._schedule_retry(row["notify_id"], row["attempts"])
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("bridge resend loop iteration failed")
            await asyncio.sleep(interval_s)

    def start(self) -> None:
        """Start the background resend loop as a task."""
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self.resend_loop())

    async def stop(self) -> None:
        """Cancel and await the background resend loop."""
        task = self._task
        self._task = None
        if task is None:
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task

    # -- acknowledgement ---------------------------------------------------------------

    async def send_ack(self, params: dict) -> dict:
        """Send ``event.ack`` to the peer as a real ``req`` (§11.1).

        This is the outbound direction. It is deliberately separate from
        :meth:`on_ack`, which consumes an ack *from* the peer and marks the matching
        local outbox row delivered — calling that here would look the peer's
        ``notify_id`` up in our own outbox and fail with ``event_not_found``.

        Args:
            params: ``{"notify_id", "task_id", "root_task_id", "outcome"}`` built by
                :func:`build_ack_params`.

        Returns:
            The peer's ``rep.result`` object.

        Raises:
            RuntimeError: When no ack sender is configured.
            BridgeError: Whatever the sender raises (``not_ready``, ``timeout``, …);
                the peer resends the event, and the duplicate path acks again.
        """
        if self._on_ack_request is None:
            raise RuntimeError("no event.ack sender configured")
        return await self._on_ack_request(params)

    async def on_ack(self, params: dict) -> dict:
        """Handle ``event.ack`` from the peer (§11.1).

        Args:
            params: ``{"notify_id", "task_id", "root_task_id", "outcome"}``.

        Returns:
            ``{"notify_id", "delivered": True}``.

        Raises:
            BridgeError: ``event_not_found`` for an unknown notification.
        """
        notify_id = params.get("notify_id")
        if not isinstance(notify_id, str) or not notify_id:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "notify_id"})
        row = await self._store.get_notify(notify_id)
        if row is None:
            raise BridgeError(ERR_EVENT_NOT_FOUND)
        if not row["delivered"]:
            await self._store.mark_delivered(notify_id)
        outcome = params.get("outcome", "processed")
        logger.info(
            "bridge notification acked notify_id=%s outcome=%s duplicate=%s",
            notify_id,
            outcome,
            row["delivered"],
        )
        return {"notify_id": notify_id, "delivered": True}

    # -- wake guards -------------------------------------------------------------------

    async def guard_wake(self, task: dict, event: str, session_key: str) -> bool:
        """Apply the wake-chain and rate guards before delivering a wake (§16.6).

        The persistent ``(task_id, event)`` dedupe is checked before any budget: a
        repeated notification stays idempotent even when the wake chain is already
        exhausted, where raising would wrongly escalate the task to ``needs_human``.
        Only a genuinely new wake consumes chain/rate budget.

        Args:
            task: Task that triggered the wake.
            event: Event name.
            session_key: Connection/session key used for the rate window.

        Returns:
            ``True`` when a new wake may be delivered, ``False`` when this
            ``(task_id, event)`` pair was already delivered — the caller must then
            skip delivery entirely (no IM, no ``record_wake``).

        Raises:
            BridgeError: ``wake_chain_exceeded`` or ``wake_rate_limited`` for a new
                wake; the caller must convert these into ``needs_human`` rather than
                retrying. A duplicate returns ``False`` without raising.
        """
        if event not in WAKE_EVENTS:
            return False
        if await self._store.wake_already_delivered(task["task_id"], event):
            logger.info("bridge wake deduped task=%s event=%s", task["task_id"], event)
            return False
        root_id = task["root_task_id"]
        chain = await self._store.wake_chain_count(root_id)
        if chain >= self._wake_max_chain:
            logger.warning(
                "bridge wake chain exhausted root=%s count=%s", root_id, chain
            )
            raise BridgeError(ERR_WAKE_CHAIN_EXCEEDED)
        if not await self._store.wake_rate_hit(
            f"{self._conn}:{session_key}", self._wake_rate
        ):
            logger.warning(
                "bridge wake rate limited conn=%s session=%s", self._conn, session_key
            )
            raise BridgeError(ERR_WAKE_RATE_LIMITED)
        return True

    async def record_wake(self, task: dict, event: str) -> int:
        """Persist a delivered wake and return the new chain length.

        Args:
            task: Task that triggered the wake.
            event: Event name.

        Returns:
            Updated chain counter.
        """
        await self._store.mark_wake_delivered(task["task_id"], event)
        return await self._store.bump_wake(task["root_task_id"])

    async def handle_wake_guard_failure(self, task: dict, code: str) -> dict | None:
        """Convert a guard failure into ``needs_human`` (§16.6).

        Args:
            task: Task that could not be woken.
            code: The guard error code.

        Returns:
            The updated task, or ``None`` when it is already terminal.
        """
        logger.warning(
            "bridge wake guard tripped task=%s code=%s -> needs_human",
            task["task_id"],
            code,
        )
        return await self._store.mark_needs_human(
            task["task_id"], code, "automatic wake stopped"
        )


def build_event_params(
    task: dict,
    event: str,
    status: str,
    notify_id: str,
    eseq: int,
    *,
    result: dict | None = None,
    error: dict | None = None,
    decision: dict | None = None,
    approval: dict | None = None,
) -> dict:
    """Build the ``task.event`` parameter object (§11.2).

    Args:
        task: Task row.
        event: Event name.
        status: Resulting status.
        notify_id: Notification id.
        eseq: Event sequence number.
        result: Optional result object.
        error: Optional error object.
        decision: Optional inline decision payload.
        approval: Optional inline approval payload.

    Returns:
        Parameter dictionary with every documented field present.
    """
    return {
        "task_id": task["task_id"],
        "root_task_id": task["root_task_id"],
        "eseq": eseq,
        "event": event,
        "status": status,
        "notify_id": notify_id,
        "result": result,
        "error": error,
        "decision": decision,
        "approval": approval,
    }


def build_ack_params(
    notify_id: str, task_id: str, root_task_id: str, outcome: str = "processed"
) -> dict:
    """Build the ``event.ack`` parameter object (§11.1).

    Args:
        notify_id: Notification being acknowledged.
        task_id: Owning task.
        root_task_id: Root task.
        outcome: ``processed`` / ``duplicate`` / ``rejected``.

    Returns:
        Parameter dictionary.
    """
    return {
        "notify_id": notify_id,
        "task_id": task_id,
        "root_task_id": root_task_id,
        "outcome": outcome,
    }


def inbound_event_message(params: dict) -> dict:
    """Wrap ``task.event`` parameters into an ``evt`` message object (§9.1).

    Args:
        params: ``task.event`` parameters.

    Returns:
        Message object ready for ``Session.send_message``.
    """
    return {
        "k": KIND_EVT,
        "m": MSG_TASK_EVENT,
        "id": str(uuid.uuid4()),
        "ts": utc_iso_ms(),
        "params": params,
    }


def inbound_ack_message(params: dict) -> dict:
    """Wrap ``event.ack`` parameters into a ``req`` message object (§11.1).

    Args:
        params: ``event.ack`` parameters.

    Returns:
        Request message object.
    """

    return {
        "k": "req",
        "m": MSG_EVENT_ACK,
        "id": str(uuid.uuid4()),
        "ts": utc_iso_ms(),
        "params": params,
    }


__all__ = [
    "NotifyService",
    "build_ack_params",
    "build_event_params",
    "inbound_ack_message",
    "inbound_event_message",
    "STATUS_NEEDS_HUMAN",
]
