"""Message router: ``req``/``rep``/``evt`` dispatch with idempotent reply caching.

Implements protocol §9.1 (message object validation), §9.2 (closed message
vocabulary and kind constraints) and §10.1 (the ``(conn, m, id)`` idempotency
key). Business errors never escape into the transport: they become
``rep{ok:false}`` replies (§1.3).
"""

from __future__ import annotations

import inspect
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from astrbot.api import logger

from .constants import (
    EVENT_MESSAGES,
    KIND_EVT,
    KIND_REP,
    KIND_REQ,
    REQUEST_MESSAGES,
)
from .errors import (
    ERR_BAD_PARAMS,
    ERR_INTERNAL_ERROR,
    ERR_UNKNOWN_MESSAGE,
    ERR_UNKNOWN_MESSAGE_KIND,
    BridgeError,
)
from .session import now_ms, utc_iso_ms

#: Handler signature: ``async (params, ctx) -> dict``.
Handler = Callable[[dict, "MessageContext"], Awaitable[dict]]


@dataclass
class MessageContext:
    """Metadata about the message currently being handled.

    Attributes:
        conn: Connection identifier.
        kind: ``req`` or ``evt``.
        message: Message name.
        message_id: Message ``id`` (the idempotency key for requests).
        ts: Sender timestamp string.
        peer_side: Protocol side of the sender, when known.
    """

    conn: str
    kind: str
    message: str
    message_id: str
    ts: str
    peer_side: str | None = None


class ReplyCache:
    """In-memory TTL cache of request replies keyed by ``(conn, m, id)``.

    The persistent store keeps the same keys across restarts; this cache avoids a
    database round-trip for the hot path. Both layers enforce "execute once".
    """

    def __init__(self, ttl_s: int, max_entries: int = 4096) -> None:
        """Create the cache.

        Args:
            ttl_s: Time-to-live for each cached reply.
            max_entries: Hard cap; the oldest entries are evicted first.
        """
        self._ttl = ttl_s
        self._max = max_entries
        self._entries: dict[tuple[str, str, str], tuple[float, dict]] = {}

    def get(self, key: tuple[str, str, str]) -> dict | None:
        """Return a cached reply, dropping it when expired.

        Args:
            key: ``(conn, m, id)`` tuple.

        Returns:
            The cached reply object, or ``None``.
        """
        item = self._entries.get(key)
        if item is None:
            return None
        stamp, reply = item
        if (now_ms() / 1000.0) - stamp > self._ttl:
            self._entries.pop(key, None)
            return None
        return reply

    def put(self, key: tuple[str, str, str], reply: dict) -> None:
        """Store a reply, evicting the oldest entry when full.

        Args:
            key: ``(conn, m, id)`` tuple.
            reply: Reply object to cache.
        """
        if len(self._entries) >= self._max:
            oldest = min(self._entries, key=lambda item: self._entries[item][0])
            self._entries.pop(oldest, None)
        self._entries[key] = (now_ms() / 1000.0, reply)

    def clear(self) -> None:
        """Drop every cached reply."""
        self._entries.clear()


class Router:
    """Dispatch validated messages to registered handlers.

    Registration is by message name; kind constraints come from the closed
    vocabulary so a handler can never answer an ``evt`` or emit an event for a
    request-only name.
    """

    def __init__(
        self, store: Any = None, *, conn: str = "", reply_ttl_s: int = 86400
    ) -> None:
        """Create the router.

        Args:
            store: Optional persistent store exposing ``cache_reply`` /
                ``get_cached_reply``. When ``None`` only the in-memory cache is used.
            conn: Connection identifier used for the idempotency key.
            reply_ttl_s: Reply cache TTL, matching ``IDEMPOTENT_REPLY_TTL_S``.
        """
        self._handlers: dict[str, Handler] = {}
        self._store = store
        self._conn = conn
        self._cache = ReplyCache(ttl_s=reply_ttl_s)
        self._executed: dict[tuple[str, str, str], int] = {}

    def register(self, message: str, handler: Handler) -> None:
        """Register the handler for one message name.

        Args:
            message: Message name from §9.2.
            handler: ``async (params, ctx) -> dict`` callable.

        Raises:
            ValueError: When the name or callable is invalid.
        """
        if not isinstance(message, str) or not message:
            raise ValueError("message name must be a non-empty string")
        if not callable(handler):
            raise ValueError("handler must be callable")
        if message in self._handlers:
            logger.warning("bridge router overriding handler for %s", message)
        self._handlers[message] = handler

    def registered(self) -> list[str]:
        """Return the sorted list of registered message names."""
        return sorted(self._handlers)

    async def dispatch(self, msg: dict) -> dict | None:
        """Validate and handle one inbound message object.

        Args:
            msg: Message object already decrypted and shape-checked by the session.

        Returns:
            A ``rep`` object for ``req`` messages, ``None`` for ``evt`` messages.

        Raises:
            None: Business failures are converted into ``rep{ok:false}``.
        """
        kind = msg.get("k")
        if kind not in (KIND_REQ, KIND_EVT):
            raise BridgeError(ERR_UNKNOWN_MESSAGE_KIND)
        message = msg.get("m")
        message_id = msg.get("id")
        if not isinstance(message, str) or not message:
            raise BridgeError(ERR_UNKNOWN_MESSAGE)
        if not isinstance(message_id, str) or not message_id:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "id"})
        params = msg.get("params")
        if not isinstance(params, dict):
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "params"})

        handler = self._handlers.get(message)
        if handler is None:
            if kind == KIND_EVT:
                logger.warning("bridge dropping unknown event m=%s", message)
                return None
            return _error_reply(
                message,
                message_id,
                BridgeError(ERR_UNKNOWN_MESSAGE, details={"m": message}),
            )

        if kind == KIND_EVT and message in REQUEST_MESSAGES:
            logger.warning("bridge event used a request-only name m=%s", message)
            return None
        if kind == KIND_REQ and message in EVENT_MESSAGES:
            return _error_reply(
                message,
                message_id,
                BridgeError(ERR_UNKNOWN_MESSAGE_KIND, details={"m": message}),
            )

        ctx = MessageContext(
            conn=self._conn,
            kind=kind,
            message=message,
            message_id=message_id,
            ts=str(msg.get("ts", "")),
            peer_side=msg.get("_peer_side"),
        )

        if kind == KIND_EVT:
            try:
                await _invoke(handler, params, ctx)
            except BridgeError as exc:
                logger.warning(
                    "bridge event handler failed m=%s code=%s", message, exc.code
                )
            except Exception:
                logger.exception("bridge event handler crashed m=%s", message)
            return None

        cache_key = (self._conn, message, message_id)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        if self._store is not None:
            stored = await self._store.get_cached_reply("|".join(cache_key))
            if stored is not None:
                stored.setdefault("_cache_hit", True)
                self._cache.put(cache_key, stored)
                return stored

        self._executed[cache_key] = self._executed.get(cache_key, 0) + 1
        try:
            result = await _invoke(handler, params, ctx)
            reply = {
                "k": KIND_REP,
                "m": message,
                "id": str(uuid.uuid4()),
                "reply_to": message_id,
                "ts": utc_iso_ms(),
                "ok": True,
                "result": result if isinstance(result, dict) else {},
            }
        except BridgeError as exc:
            reply = _error_reply(message, message_id, exc)
        except Exception:
            logger.exception("bridge request handler crashed m=%s", message)
            reply = _error_reply(message, message_id, BridgeError(ERR_INTERNAL_ERROR))

        self._cache.put(cache_key, reply)
        if self._store is not None:
            await self._store.cache_reply("|".join(cache_key), reply)
        return reply

    def execution_count(self, message: str, message_id: str) -> int:
        """Return how many times a handler ran for one request (§10.1 assertions).

        Args:
            message: Message name.
            message_id: Request id.

        Returns:
            Number of handler invocations (0 or 1 in normal operation).
        """
        return self._executed.get((self._conn, message, message_id), 0)

    def reset_counters(self) -> None:
        """Clear the invocation counters used by tests and diagnostics."""
        self._executed.clear()


async def _invoke(handler: Handler, params: dict, ctx: MessageContext) -> dict:
    """Call a handler that may be sync or async.

    Args:
        handler: Registered handler.
        params: Request parameters.
        ctx: Message context.

    Returns:
        The handler result (an empty dict for ``None``).
    """
    outcome = handler(params, ctx)
    if inspect.isawaitable(outcome):
        outcome = await outcome
    return outcome if isinstance(outcome, dict) else {}


def _error_reply(message: str, message_id: str, error: BridgeError) -> dict:
    """Build a ``rep{ok:false}`` object (§9.1).

    Args:
        message: Message name being answered.
        message_id: Request id being answered.
        error: The error to report.

    Returns:
        Reply object.
    """
    return {
        "k": KIND_REP,
        "m": message,
        "id": str(uuid.uuid4()),
        "reply_to": message_id,
        "ts": utc_iso_ms(),
        "ok": False,
        "error": error.to_payload(),
    }


__all__ = ["Handler", "MessageContext", "ReplyCache", "Router"]
