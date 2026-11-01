#!/usr/bin/env python3
"""A-side (AstrBot) peer process for the business round-trip acceptance suite.

Test scaffolding only: it does **not** re-implement the bridge. It boots the real
plugin through its real entry point — ``DshBridgePlugin.initialize()`` — so the
production assembly runs unchanged: real ``Store`` (SQLite in a temporary
directory), real ``SessionService``, ``NotifyService``, ``TaskService``,
``ApprovalService``, ``Router``, real ``TransportManager``, real ``Session`` over a
real loopback WebSocket, and the real background loops (notify resend, approval
timeout, blob cleanup, maintenance).

Two host boundaries are stubbed, and only those, marked ``M``:

* ``DshBridgePlugin._execute_task`` — the AstrBot OpenAPI/agent run. The real
  implementation posts to ``POST /api/v1/chat`` on a live AstrBot; with no model
  or AstrBot instance available here it is replaced by a recorder returning a
  whitelisted result. Everything above it (scheduling, transitions, events,
  wakes) is the real code.
* ``context.send_message`` — the IM wake sink. Recorded, not delivered.

Connection wiring
-----------------
``--mode direct`` (default) reproduces ``DshBridgePlugin._run_connection`` step for
step from the same real pieces — ``SessionConfig`` → ``Session`` →
``TransportHooks`` → ``TransportManager.bring_up`` → ``session.start`` →
``run_heartbeat`` — with the plugin's own callbacks, but *without* the manager's
``run_forever`` loop. That loop has its own dedicated case
(``--mode plugin``, the fully production path); keeping it out of the shared
fixture stops one connection-loop defect from masking every business case.

No store write is forced, no transition is bypassed and no human gate is skipped.

Control channel: commands are JSON lines on stdin; events are JSON lines appended
to the file named by ``DSH_BR_A_EVENTS`` (cross-platform, no fd passing).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import sys
import time
from typing import Any

A_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
# ``main.py`` uses package-relative imports (``from .bridge...``), so it must be
# imported under its real package name, with the plugins directory on the path.
A_PARENT = os.path.dirname(A_ROOT)
A_PACKAGE = os.path.basename(A_ROOT)
if A_PARENT not in sys.path:
    sys.path.insert(0, A_PARENT)


def emit(event: dict) -> None:
    """Append one control event.

    Args:
        event: JSON-serialisable event object.
    """
    target = os.environ.get("DSH_BR_A_EVENTS")
    if not target:
        return
    with open(target, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False) + "\n")
        handle.flush()


class StubPlatform:
    """Platform instance double matching the acceptance UMO's platform id."""

    def __init__(self, platform_id: str) -> None:
        """Create the double.

        Args:
            platform_id: Value returned by ``meta().id``.
        """
        self._platform_id = platform_id

    def meta(self) -> Any:
        """Return the metadata the real host matches against.

        Returns:
            An object carrying the platform instance id.
        """
        from types import SimpleNamespace

        return SimpleNamespace(id=self._platform_id)


class HostContext:
    """Minimal stand-in for the AstrBot plugin context (``M``).

    It supplies only what the assembly reads: the LLM tool registry, the web-route
    registration, the platform lookup, the config mapping and the active-message
    sink. The sink records wakes instead of delivering them.
    """

    def __init__(self) -> None:
        """Create an empty recorder with the acceptance platform registered."""
        self.llm_tools: list[str] = []
        self.web_routes: list[str] = []
        self.wakes: list[dict] = []
        self._config: dict[str, Any] = {"admins_id": []}
        self.platforms: dict[str, StubPlatform] = {
            "acceptance": StubPlatform("acceptance")
        }

    def add_llm_tools(self, *tools: Any) -> None:
        """Record registered LLM tools.

        Args:
            tools: Tool instances.
        """
        self.llm_tools = [getattr(tool, "name", type(tool).__name__) for tool in tools]

    def register_web_api(self, route: str, *args: Any, **kwargs: Any) -> None:
        """Record a registered dashboard route.

        Args:
            route: Route path.
            args: Positional payload (handler, methods, description).
            kwargs: Keyword payload.
        """
        self.web_routes.append(route)

    def get_config(self) -> dict[str, Any]:
        """Return the plugin config mapping.

        Returns:
            Config dict.
        """
        return self._config

    async def get_using_provider_async(self, umo: str | None = None) -> Any:
        """Return the active chat provider (none in this harness).

        Args:
            umo: Session the provider would belong to.

        Returns:
            ``None``.
        """
        return None

    def get_platform_inst(self, platform_id: str) -> Any:
        """Resolve a platform exactly like the real ``Context``.

        Args:
            platform_id: Platform instance id to look up.

        Returns:
            The matching platform double, or ``None``.
        """
        return self.platforms.get(platform_id)

    async def send_message(self, umo: str, chain: Any) -> bool:
        """Record one active message instead of delivering it (``M``).

        Args:
            umo: Target conversation.
            chain: Message chain.

        Returns:
            ``True``: the recorded wake is a successful host verdict.
        """
        self.wakes.append(
            {"umo": umo, "chain": type(chain).__name__, "ts": time.time()}
        )
        return True


class ExecutionRecorder:
    """Recording stand-in for one AstrBot agent run (``M``).

    It neither calls a model nor a real AstrBot: it proves only that the bridge
    reached the point of executing, exactly how many times, and for which task.
    """

    def __init__(self) -> None:
        """Create an empty recorder."""
        self.calls: list[dict] = []

    async def run(self, *, task: dict) -> dict:
        """Record one execution and return a whitelisted result.

        Args:
            task: Stored task row.

        Returns:
            Result restricted to the protocol whitelist.
        """
        self.calls.append(
            {
                "task_id": task["task_id"],
                "origin": task.get("origin"),
                "at": time.time(),
            }
        )
        return {
            "summary": "业务用例执行完成",
            "text": "ok",
            "attachments": [],
            "degraded": [],
        }


class Connection:
    """One real A-side session over a real loopback WebSocket carrier.

    Mirrors ``DshBridgePlugin._run_connection`` step for step with the same real
    classes and the plugin's own callbacks, minus the manager's ``run_forever``
    loop (which ``--mode plugin`` exercises through the real entry point).
    """

    def __init__(self, plugin: Any, conn: dict, config: dict) -> None:
        """Prepare one connection.

        Args:
            plugin: The real plugin instance.
            conn: Normalised connection record.
            config: Plugin config mapping.
        """
        self.plugin = plugin
        self.conn = conn
        self.config = config
        self.session: Any = None
        self.manager: Any = None
        self._heartbeat: asyncio.Task | None = None

    async def up(self) -> None:
        """Build the carrier, bind the session and run the handshake."""
        from astrbot_plugin_dsh_bridge.bridge.session import (
            Role,
            Session,
            SessionConfig,
        )
        from astrbot_plugin_dsh_bridge.bridge.transport.base import TransportHooks
        from astrbot_plugin_dsh_bridge.bridge.transport.manager import TransportManager

        plugin = self.plugin
        conn = self.conn
        cfg = SessionConfig(
            conn=conn["conn_id"],
            side="A",
            role=Role.RESPONDER,
            transport=conn["transport"],
            psk_id=conn["psk_id"],
            psk_secret=conn["psk_secret"],
            heartbeat_s=5,
            caps=plugin._capabilities.caps(),
            version="0.1.0",
            host_id="astrbot",
            addr=conn["host"],
            port=conn["port"],
            path=conn["path"],
            mode=conn["mode"],
            tls_enabled=conn["tls"],
            reconnect_max_backoff=2,
        )
        session = Session(
            cfg,
            None,
            plugin._on_session_message,
            plugin._on_security_event,
            on_state=plugin._on_session_state,
        )
        plugin._session = session
        self.session = session

        async def attach(transport: Any) -> None:
            session._transport = transport  # noqa: SLF001 - composition wiring

        hooks = TransportHooks(
            on_plain=session.handle_plain,
            on_envelope=session.handle_envelope,
            on_probe=plugin._on_probe,
            on_state=plugin._set_connection_state,
            on_activity=session.touch,
        )
        manager = TransportManager(
            cfg, hooks, preferred=conn["transport"], fallbacks=[], on_transport=attach
        )
        plugin._manager = manager
        self.manager = manager
        await manager.bring_up()
        await session.start()
        self._heartbeat = asyncio.create_task(session.run_heartbeat())

    async def wait_ready(self, timeout_s: float = 25.0) -> bool:
        """Wait until the handshake completes.

        Args:
            timeout_s: Maximum wait.

        Returns:
            ``True`` when the session became ready.
        """
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self.session is not None and self.session.state.value == "ready":
                return True
            await asyncio.sleep(0.02)
        return False

    async def down(self) -> None:
        """Close the session and release the carrier."""
        if self._heartbeat is not None:
            self._heartbeat.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._heartbeat
            self._heartbeat = None
        if self.session is not None:
            with contextlib.suppress(Exception):
                await self.session.close("draining", "harness_down")
            self.session = None
            self.plugin._session = None
        if self.manager is not None:
            with contextlib.suppress(Exception):
                await self.manager.stop()
            self.manager = None
            self.plugin._manager = None


async def main() -> int:
    """Boot the plugin, then serve control commands until ``close``.

    Returns:
        Process exit code.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--data-root", required=True)
    parser.add_argument("--conn", default="business")
    parser.add_argument("--psk-id", required=True)
    parser.add_argument("--psk-secret", required=True)
    parser.add_argument("--mode", default="direct", choices=("direct", "plugin"))
    parser.add_argument("--handshake-timeout", type=float, default=25.0)
    args = parser.parse_args()

    # The plugin resolves its persistent directory through this helper; pointing it
    # at this process's temporary root keeps the run off the real installation.
    from astrbot.core.utils import astrbot_path as _astrbot_path

    _astrbot_path.get_astrbot_plugin_data_path = lambda: args.data_root

    module = __import__(f"{A_PACKAGE}.main", fromlist=["DshBridgePlugin"])
    DshBridgePlugin = module.DshBridgePlugin

    recorder = ExecutionRecorder()
    DshBridgePlugin._execute_task = lambda self, task: recorder.run(task=task)

    context = HostContext()
    conn = {
        "conn_id": args.conn,
        "conn_mode": "listen",
        "conn_transport": "ws",
        "conn_transport_fallback": [],
        "conn_host": "127.0.0.1",
        "conn_port": args.port,
        "conn_path": "/dsh-bridge",
        "conn_psk_id": args.psk_id,
        "conn_psk_secret": args.psk_secret,
        "conn_allow_agent_create": True,
        "conn_max_agent_sessions": 10,
    }
    config = {
        "dashboard_enabled": False,
        "approval_timeout_seconds": int(
            os.environ.get("DSH_BR_APPROVAL_TIMEOUT", "600")
        ),
        "heartbeat_interval": 5,
        "reconnect_max_backoff": 2,
        "connections": [conn],
    }
    if args.mode == "direct":
        # Take the plugin's own normalisation of the raw record, then withhold the
        # connection so ``initialize()`` does not start the manager's reconnect loop;
        # ``Connection`` below wires the same pieces by hand.
        primary = DshBridgePlugin(context, config)._primary()
        assert primary is not None
        config["connections"] = []

    plugin = DshBridgePlugin(context, config)
    await plugin.initialize()

    connection: Connection | None = None
    if args.mode == "direct":
        connection = Connection(plugin, primary, config)
        await connection.up()

    deadline = time.monotonic() + args.handshake_timeout
    ready = False
    while time.monotonic() < deadline:
        session = plugin._session
        if session is not None and session.state.value == "ready":
            ready = True
            break
        await asyncio.sleep(0.02)

    emit(
        {
            "event": "ready" if ready else "start_error",
            "mode": args.mode,
            "sid": plugin._session.sid if plugin._session else None,
            "conn": args.conn,
            "state": str(plugin._connection_state),
        }
    )
    if not ready:
        if connection is not None:
            await connection.down()
        await plugin.terminate()
        return 3

    async def snapshot() -> dict:
        """Collect every observable business fact on this side.

        Returns:
            Snapshot dictionary.
        """
        store = plugin._store
        assert store is not None
        tasks = []
        for status in (
            "accepted",
            "pending_approval",
            "queued",
            "running",
            "succeeded",
            "failed",
            "rejected",
            "canceled",
            "needs_human",
        ):
            for task in await store.tasks_by_status([status]):
                tasks.append(
                    {
                        "task_id": task["task_id"],
                        "status": task["status"],
                        "direction": task["direction"],
                        "origin": task.get("origin"),
                        "eseq": task["eseq"],
                        "needs_human": bool(task.get("needs_human")),
                        "error": (task.get("error") or {}).get("code"),
                        "session_id": task.get("session_id"),
                    }
                )
        # Read-only introspection of the outbox: the store exposes no list method,
        # and observation must not go through a mutation helper.
        notifies = []
        async with store._conn().execute(  # noqa: SLF001 - read-only observation
            "SELECT notify_id, message, task_id, attempts, delivered, undelivered"
            " FROM notify_outbox ORDER BY created_at ASC"
        ) as cursor:
            for row in await cursor.fetchall():
                notifies.append(
                    {
                        "notify_id": row["notify_id"],
                        "message": row["message"],
                        "delivered": bool(row["delivered"]),
                        "undelivered": bool(row["undelivered"]),
                        "attempts": int(row["attempts"]),
                        "task_id": row["task_id"],
                    }
                )
        grants = await plugin._sessions_svc.admin_grants()
        approvals = []
        if plugin._approvals is not None:
            for approval in await store.list_approvals(limit=100):
                approvals.append(
                    {
                        "approval_id": approval["approval_id"],
                        "approval_type": approval["approval_type"],
                        "state": approval["state"],
                        "task_id": approval.get("task_id"),
                        "outcome": approval.get("outcome"),
                        "channel": approval.get("channel"),
                        "source": approval.get("source"),
                        "gate_scope": approval.get("gate_scope"),
                        "conn": approval.get("conn"),
                        "sid": approval.get("sid"),
                        "released_by_task": approval.get("released_by_task"),
                        "consumed_by_task": approval.get("consumed_by_task"),
                        "submit_digest": approval.get("submit_digest"),
                    }
                )
        return {
            "event": "snapshot",
            "state": plugin._session.state.value if plugin._session else "none",
            "sid": plugin._session.sid if plugin._session else None,
            "tasks": tasks,
            "notifies": notifies,
            "grants": grants,
            "approvals": approvals,
            "wakes": context.wakes,
            "executions": recorder.calls,
            "llm_tools": context.llm_tools,
        }

    async def expire_now() -> dict:
        """Run one approval-expiry sweep through the same code the loop uses.

        Returns:
            Reply payload.
        """
        assert plugin._approvals is not None and plugin._store is not None
        expired = await plugin._store.expire_approvals()
        for approval in expired:
            row = await plugin._store.get_approval(approval["approval_id"])
            if row is None:
                continue
            await plugin._approvals._apply(row)  # noqa: SLF001 - the loop's own call
            if row["approval_type"] == "native_tool":
                with contextlib.suppress(Exception):
                    await plugin._approvals._send_decision_event(row)  # noqa: SLF001
        return {"event": "expired", "count": len(expired)}

    async def execute(cmd: dict) -> dict:
        """Run one control command.

        Args:
            cmd: Command object with ``op``.

        Returns:
            Reply payload.
        """
        op = cmd.get("op")
        if op == "snapshot":
            return await snapshot()
        if op == "grant":
            version = await plugin._sessions_svc.admin_grant(
                str(cmd["session_id"]),
                purpose=str(cmd.get("purpose", "")),
                title=str(cmd.get("title", "")),
                granted_by_id="business-acceptance",
            )
            return {"event": "granted", "version": version}
        if op == "revoke":
            version = await plugin._sessions_svc.admin_revoke(str(cmd["session_id"]))
            return {"event": "revoked", "version": version}
        if op == "archive":
            result = await plugin._sessions_svc.manage_session(
                {"session_id": str(cmd["session_id"]), "action": "archive"}
            )
            return {"event": "archived", "result": result}
        if op == "submit":
            session = plugin._session
            assert plugin._tasks is not None and session is not None
            try:
                result = await plugin._tasks.submit_outbound(
                    session=session,
                    input_parts=[{"type": "text", "text": str(cmd["text"])}],
                    origin=str(cmd.get("origin", "human")),
                    purpose=cmd.get("purpose") or None,
                    session_id=cmd.get("session_id"),
                    timeout_s=int(cmd.get("timeout_s", 300)),
                    meta_umo=cmd.get("umo"),
                    task_id=cmd.get("task_id"),
                )
                return {"event": "submitted", "ok": True, "result": result}
            except Exception as exc:  # noqa: BLE001 - reported to the harness verbatim
                return {
                    "event": "submitted",
                    "ok": False,
                    "code": getattr(exc, "code", type(exc).__name__),
                }
        if op == "submit_gated":
            # Production path: the real LLM tool adapter opens a human gate and sends
            # nothing until a human answers. Calling the adapter (not the plugin
            # method) proves the schema/parameters reach the gate unchanged.
            class _Event:
                unified_msg_origin = str(
                    cmd.get("umo") or "acceptance:FriendMessage:chat:1"
                )

            tool = module.DshSubmitTaskTool(plugin)
            text = await tool(
                _Event(),
                str(cmd["text"]),
                str(cmd.get("purpose", "")),
                None if cmd.get("omit_session") else cmd.get("session_id"),
            )
            rows = await plugin._store.tasks_by_status(["pending_approval"])
            outbound = [row for row in rows if row["direction"] == "outbound"]
            task = outbound[-1] if outbound else None
            approval = (
                await plugin._store.get_task_approval(
                    task["task_id"], "cross_end_submit"
                )
                if task is not None
                else None
            )
            return {
                "event": "gated",
                "text": text,
                "task": task,
                "approval_id": approval["approval_id"] if approval else None,
                "entry": type(tool).__name__,
                "tool_name": tool.name,
                "session_id": task.get("session_id") if task else None,
                "purpose": task.get("purpose") if task else None,
            }
        if op == "decide":
            assert plugin._approvals is not None
            applied, reason = await plugin._approvals.human_decide(
                str(cmd["approval_id"]),
                allowed=bool(cmd.get("allowed", True)),
                actor=str(cmd.get("actor", "acceptance-operator")),
                channel=str(cmd.get("channel", "web")),
                reason=cmd.get("reason"),
            )
            return {"event": "decided", "applied": applied, "reason": reason}
        if op == "expire_now":
            return await expire_now()
        if op == "wait_task":
            want = set(cmd.get("statuses", []))
            deadline_at = time.monotonic() + float(cmd.get("timeout_s", 25))
            assert plugin._store is not None
            while time.monotonic() < deadline_at:
                task = await plugin._store.get_task(str(cmd["task_id"]))
                if task is not None and (not want or task["status"] in want):
                    return {"event": "task", "task": task}
                await asyncio.sleep(0.02)
            task = await plugin._store.get_task(str(cmd["task_id"]))
            return {"event": "task_timeout", "task": task}
        if op == "wait_executions":
            count = int(cmd.get("count", 1))
            deadline_at = time.monotonic() + float(cmd.get("timeout_s", 25))
            while time.monotonic() < deadline_at:
                if len(recorder.calls) >= count:
                    return {
                        "event": "executed",
                        "count": len(recorder.calls),
                        "calls": recorder.calls,
                    }
                await asyncio.sleep(0.02)
            return {
                "event": "execution_timeout",
                "count": len(recorder.calls),
                "calls": recorder.calls,
            }
        if op == "down":
            if connection is None:
                return {"event": "down", "ok": False, "reason": "plugin_mode"}
            await connection.down()
            return {"event": "down", "ok": True}
        if op == "up":
            if connection is None:
                return {"event": "up", "ok": False, "reason": "plugin_mode"}
            await connection.up()
            return {
                "event": "up",
                "ok": await connection.wait_ready(float(cmd.get("timeout_s", 25))),
            }
        if op == "close":
            if connection is not None:
                await connection.down()
            await plugin.terminate()
            return {"event": "closed"}
        return {"event": "unknown_op", "op": op}

    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(reader), sys.stdin
    )
    while True:
        line = await reader.readline()
        if not line:
            break
        text = line.decode("utf-8").strip()
        if not text:
            continue
        cmd = json.loads(text)
        try:
            reply = await execute(cmd)
        except Exception as exc:  # noqa: BLE001 - reported to the harness verbatim
            reply = {
                "event": "error",
                "code": getattr(exc, "code", type(exc).__name__),
                "detail": str(exc)[:300],
            }
        reply["id"] = cmd.get("id")
        emit(reply)
        if cmd.get("op") == "close":
            break

    if connection is not None:
        with contextlib.suppress(Exception):
            await connection.down()
    with contextlib.suppress(Exception):
        await plugin.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
