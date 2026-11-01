"""Router tests: idempotent replies, orphan replies, kind constraints, errors.

Covers protocol §1.3 (business errors never break the transport), §9.1/§9.2
(message shapes and closed vocabulary) and §10.1 (``(conn, m, id)`` idempotency).
"""

from __future__ import annotations

import pytest

from bridge.errors import BridgeError
from bridge.router import MessageContext, ReplyCache, Router
from bridge.session import make_message

CONN = "default"


def _request(message: str, params: dict, message_id: str = "11111111-1111-4111-8111-111111111111") -> dict:
    """Build a ``req`` object for dispatch."""
    return {
        "k": "req",
        "m": message,
        "id": message_id,
        "ts": "2026-10-29T11:30:00.000Z",
        "params": params,
    }


def _event(message: str, params: dict, message_id: str = "22222222-2222-4222-8222-222222222222") -> dict:
    """Build an ``evt`` object for dispatch."""
    return {
        "k": "evt",
        "m": message,
        "id": message_id,
        "ts": "2026-10-29T11:30:00.000Z",
        "params": params,
    }


@pytest.mark.asyncio
async def test_request_returns_ok_reply() -> None:
    """A registered request handler produces ``rep{ok:true}`` with the result."""
    router = Router(conn=CONN)

    async def handler(params: dict, ctx: MessageContext) -> dict:
        return {"task_id": params["task_id"], "status": "accepted"}

    router.register("task.submit", handler)
    reply = await router.dispatch(_request("task.submit", {"task_id": "t1"}))
    assert reply is not None
    assert reply["k"] == "rep"
    assert reply["m"] == "task.submit"
    assert reply["reply_to"] == "11111111-1111-4111-8111-111111111111"
    assert reply["ok"] is True
    assert reply["result"] == {"task_id": "t1", "status": "accepted"}


@pytest.mark.asyncio
async def test_business_error_becomes_failed_reply_not_an_exception() -> None:
    """A ``BridgeError`` is reported as ``rep{ok:false}`` without raising (§1.3)."""
    router = Router(conn=CONN)

    async def handler(params: dict, ctx: MessageContext) -> dict:
        raise BridgeError("task_not_found")

    router.register("task.status", handler)
    reply = await router.dispatch(_request("task.status", {"task_id": "x"}))
    assert reply is not None
    assert reply["ok"] is False
    assert reply["error"]["code"] == "task_not_found"
    assert reply["error"]["message"] == "unknown task"


@pytest.mark.asyncio
async def test_unexpected_exception_becomes_internal_error() -> None:
    """An unhandled exception must not escape the router."""
    router = Router(conn=CONN)

    async def handler(params: dict, ctx: MessageContext) -> dict:
        raise RuntimeError("boom")

    router.register("task.status", handler)
    reply = await router.dispatch(_request("task.status", {}))
    assert reply is not None
    assert reply["error"]["code"] == "internal_error"


@pytest.mark.asyncio
async def test_repeated_request_executes_handler_once() -> None:
    """The same ``(conn, m, id)`` runs the handler exactly once (§10.1)."""
    router = Router(conn=CONN)
    calls = {"count": 0}

    async def handler(params: dict, ctx: MessageContext) -> dict:
        calls["count"] += 1
        return {"n": calls["count"]}

    router.register("task.status", handler)
    first = await router.dispatch(_request("task.status", {}, message_id="dup-1"))
    second = await router.dispatch(_request("task.status", {}, message_id="dup-1"))
    assert calls["count"] == 1
    assert first == second
    assert router.execution_count("task.status", "dup-1") == 1


@pytest.mark.asyncio
async def test_different_ids_execute_independently() -> None:
    """Distinct request ids are handled separately."""
    router = Router(conn=CONN)
    calls = {"count": 0}

    async def handler(params: dict, ctx: MessageContext) -> dict:
        calls["count"] += 1
        return {}

    router.register("task.status", handler)
    await router.dispatch(_request("task.status", {}, message_id="a"))
    await router.dispatch(_request("task.status", {}, message_id="b"))
    assert calls["count"] == 2


@pytest.mark.asyncio
async def test_persistent_cache_hit_skips_handler() -> None:
    """A reply found in the persistent store prevents re-execution across restarts."""

    class Store:
        """Minimal store double exposing only the reply cache."""

        def __init__(self) -> None:
            self.rows: dict[str, dict] = {}
            self.puts = 0

        async def get_cached_reply(self, key: str):
            return self.rows.get(key)

        async def cache_reply(self, key: str, reply: dict) -> None:
            self.puts += 1
            self.rows[key] = reply

    store = Store()
    router_one = Router(store=store, conn=CONN)
    executed = {"count": 0}

    async def handler(params: dict, ctx: MessageContext) -> dict:
        executed["count"] += 1
        return {"value": 1}

    router_one.register("task.status", handler)
    await router_one.dispatch(_request("task.status", {}, message_id="persisted"))
    assert executed["count"] == 1
    assert store.puts == 1

    # A fresh router (simulating a process restart) must reuse the stored reply.
    router_two = Router(store=store, conn=CONN)
    router_two.register("task.status", handler)
    reply = await router_two.dispatch(_request("task.status", {}, message_id="persisted"))
    assert executed["count"] == 1
    assert reply is not None and reply["ok"] is True


@pytest.mark.asyncio
async def test_unknown_request_returns_unknown_message() -> None:
    """An unregistered request name yields ``unknown_message``."""
    router = Router(conn=CONN)
    reply = await router.dispatch(_request("not.a.message", {}))
    assert reply is not None
    assert reply["error"]["code"] == "unknown_message"


@pytest.mark.asyncio
async def test_unknown_event_is_dropped_silently() -> None:
    """An unregistered event name yields no reply and no exception (§17)."""
    router = Router(conn=CONN)
    reply = await router.dispatch(_event("not.an.event", {}))
    assert reply is None


@pytest.mark.asyncio
async def test_event_handler_errors_are_swallowed() -> None:
    """Event handlers may fail without breaking the session."""
    router = Router(conn=CONN)

    async def handler(params: dict, ctx: MessageContext) -> dict:
        raise BridgeError("bad_params")

    router.register("task.event", handler)
    assert await router.dispatch(_event("task.event", {})) is None


@pytest.mark.asyncio
async def test_request_only_name_as_event_is_dropped() -> None:
    """A request-only name delivered as ``evt`` is dropped (§9.1)."""
    router = Router(conn=CONN)

    async def handler(params: dict, ctx: MessageContext) -> dict:
        return {}

    router.register("task.submit", handler)
    assert await router.dispatch(_event("task.submit", {})) is None


@pytest.mark.asyncio
async def test_event_only_name_as_request_is_rejected() -> None:
    """An event-only name delivered as ``req`` is refused (§9.1)."""
    router = Router(conn=CONN)

    async def handler(params: dict, ctx: MessageContext) -> dict:
        return {}

    router.register("task.event", handler)
    reply = await router.dispatch(_request("task.event", {}))
    assert reply is not None
    assert reply["error"]["code"] == "unknown_message_kind"


@pytest.mark.asyncio
async def test_invalid_message_shapes_raise() -> None:
    """Structurally invalid message objects raise protocol errors."""
    router = Router(conn=CONN)
    with pytest.raises(BridgeError) as kind_exc:
        await router.dispatch({"k": "bogus", "m": "task.status", "id": "x", "params": {}})
    assert kind_exc.value.code == "unknown_message_kind"

    with pytest.raises(BridgeError) as name_exc:
        await router.dispatch({"k": "req", "m": "", "id": "x", "params": {}})
    assert name_exc.value.code == "unknown_message"

    with pytest.raises(BridgeError) as params_exc:
        await router.dispatch({"k": "req", "m": "task.status", "id": "x", "params": None})
    assert params_exc.value.code == "bad_params"


@pytest.mark.asyncio
async def test_sync_handler_is_supported() -> None:
    """Handlers may be synchronous."""
    router = Router(conn=CONN)

    def handler(params: dict, ctx: MessageContext) -> dict:
        return {"sync": True}

    router.register("task.status", handler)
    reply = await router.dispatch(_request("task.status", {}))
    assert reply is not None
    assert reply["result"] == {"sync": True}


@pytest.mark.asyncio
async def test_handler_context_carries_connection_metadata() -> None:
    """The context exposes connection, kind, name and message id."""
    router = Router(conn=CONN)
    captured: dict = {}

    async def handler(params: dict, ctx: MessageContext) -> dict:
        captured.update(
            {
                "conn": ctx.conn,
                "kind": ctx.kind,
                "message": ctx.message,
                "id": ctx.message_id,
            }
        )
        return {}

    router.register("task.status", handler)
    await router.dispatch(_request("task.status", {}, message_id="ctx-1"))
    assert captured == {
        "conn": CONN,
        "kind": "req",
        "message": "task.status",
        "id": "ctx-1",
    }


def test_reply_cache_expires_entries() -> None:
    """Cached replies disappear once the TTL elapses."""
    cache = ReplyCache(ttl_s=60)
    key = (CONN, "task.status", "id")
    cache.put(key, {"ok": True})
    assert cache.get(key) is not None
    # Age the entry beyond the TTL instead of sleeping.
    stamp, reply = cache._entries[key]
    cache._entries[key] = (stamp - 61, reply)
    assert cache.get(key) is None


def test_reply_cache_evicts_oldest_when_full() -> None:
    """The cache keeps at most ``max_entries`` items."""
    cache = ReplyCache(ttl_s=60, max_entries=2)
    cache.put((CONN, "m", "1"), {"n": 1})
    cache.put((CONN, "m", "2"), {"n": 2})
    cache.put((CONN, "m", "3"), {"n": 3})
    assert cache.get((CONN, "m", "3")) is not None
    assert len(cache._entries) == 2


def test_make_message_builds_valid_objects() -> None:
    """``make_message`` emits §9.1 compliant objects."""
    request = make_message("req", "task.status", params={"task_id": "t"})
    assert request["k"] == "req"
    assert request["params"] == {"task_id": "t"}
    assert "reply_to" not in request

    event = make_message("evt", "task.event", params={"notify_id": "n"})
    assert event["k"] == "evt"

    reply = make_message("rep", "task.status", result={"ok": 1}, reply_to="abc")
    assert reply["reply_to"] == "abc"
    assert reply["ok"] is True

    with pytest.raises(BridgeError):
        make_message("bogus", "task.status")
