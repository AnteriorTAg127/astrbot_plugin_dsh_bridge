"""AstrBot plugin entry point: composition root for the DSH bridge (v0.1).

This file only wires the four layers together (protocol §1.1) and exposes the plugin
surface: lifecycle, ``/dsh`` commands, LLM tools and the Dashboard status page APIs.
Business logic lives in ``bridge/app/*``, protocol logic in ``bridge/session.py`` and
carrier logic in ``bridge/transport/*``.

Governance invariants enforced here:

* The AstrBot OpenAPI key never leaves this process (§16.3 rule 6).
* No cron job is ever created, modified or triggered; task execution goes through
  ``POST /api/v1/chat`` only (§16.4).
* Approvals and business decisions require a human actor; no code path auto-approves.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import time
import uuid
from pathlib import Path
from typing import Any

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star
from astrbot.api.web import error_response, json_response, request
from astrbot.core.agent.tool import FunctionTool
from astrbot.core.utils.astrbot_path import get_astrbot_plugin_data_path

from .bridge.app.approvals import ApprovalService
from .bridge.app.blobs import BlobService
from .bridge.app.notify import NotifyService, inbound_event_message
from .bridge.app.sessions import SessionService
from .bridge.app.tasks import TaskService
from .bridge.constants import (
    APPROVAL_ALLOWING_OUTCOMES,
    DEFAULT_WAKE_MAX_CHAIN,
    DEFAULT_WAKE_RATE_PER_MINUTE,
    DIRECTION_OUTBOUND,
    IMAGE_MIME_TYPES,
    KIND_DSH_AGENT_RUN,
    MSG_EVENT_ACK,
    ORIGIN_HUMAN,
    ORIGIN_LLM,
    STATUS_ACCEPTED,
    STATUS_NEEDS_HUMAN,
    TERMINAL_STATUSES,
    TRANSPORT_WEBHOOK,
    WAKE_EVENTS,
)
from .bridge.crypto import handshake_key, mac_object, psk_master
from .bridge.errors import (
    ERR_APPROVAL_LOOKUP_FAILED,
    ERR_NOT_READY,
    ERR_PSK_NOT_CONFIGURED,
    BridgeError,
)
from .bridge.host.capabilities import HostCapabilities
from .bridge.host.openapi import OpenApiHost, build_message_parts
from .bridge.host.platform import PlatformHost
from .bridge.router import Router
from .bridge.session import (
    Role,
    Session,
    SessionConfig,
    SessionState,
    make_message,
    utc_iso_ms,
)
from .bridge.store import Store
from .bridge.transport.base import TransportHooks
from .bridge.transport.manager import TransportManager

PLUGIN_NAME = "astrbot_plugin_dsh_bridge"
VIEW_NAME = "bridge"
CONN_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
MAX_WAKE_TEXT = 2000
#: Trust anchor used while no handshake-authenticated peer side exists. It is not a
#: protocol side, so ``ApprovalService`` refuses ``native_tool`` approvals instead of
#: falling back to its permissive ``"B"`` default (see ``_rekey_approval_trust``).
UNVERIFIED_PEER_SIDE = "-"


def _bool(value: Any, default: bool = False) -> bool:
    """Coerce a config value to bool.

    Args:
        value: Raw configuration value.
        default: Fallback when the value is not boolean-like.

    Returns:
        The boolean value.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(value, int):
        return bool(value)
    return default


def _int(value: Any, default: int, *, minimum: int = 0, maximum: int = 1 << 31) -> int:
    """Coerce a config value to a bounded int.

    Args:
        value: Raw configuration value.
        default: Fallback when conversion fails.
        minimum: Lower bound.
        maximum: Upper bound.

    Returns:
        The bounded integer.
    """
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, number))


def _str(value: Any, default: str = "") -> str:
    """Coerce a config value to str.

    Args:
        value: Raw configuration value.
        default: Fallback when the value is not a string.

    Returns:
        The string value.
    """
    return value if isinstance(value, str) else default


def _list(value: Any, default: list) -> list:
    """Coerce a config value to a list.

    Args:
        value: Raw configuration value.
        default: Fallback values.

    Returns:
        The list value.
    """
    return list(value) if isinstance(value, list) else list(default)


def utc_iso_ms_from(epoch: float) -> str:
    """Render epoch seconds as protocol ISO 8601 UTC milliseconds.

    Args:
        epoch: Unix seconds.

    Returns:
        ISO string with millisecond precision.
    """
    millis = int(epoch * 1000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(millis // 1000)) + (
        f".{millis % 1000:03d}Z"
    )


class DshBridgePlugin(Star):
    """DSH bridge plugin: assembly, lifecycle and user-facing surface."""

    def __init__(self, context: Context, config: Any = None) -> None:
        """Store dependencies; no I/O happens here.

        Args:
            context: AstrBot plugin context.
            config: Plugin configuration (``AstrBotConfig``), optional for tests.
        """
        super().__init__(context)
        self._config = config
        self._store: Store | None = None
        self._sessions_svc: SessionService | None = None
        self._notify: NotifyService | None = None
        self._tasks: TaskService | None = None
        self._approvals: ApprovalService | None = None
        self._blobs: BlobService | None = None
        self._openapi: OpenApiHost | None = None
        self._platform: PlatformHost | None = None
        self._capabilities: HostCapabilities | None = None
        self._router: Router | None = None
        self._session: Session | None = None
        #: One session per activated carrier, keyed by ``id(transport)``. The manager
        #: binds a fresh session before each ``start()`` and releases it before the
        #: carrier stops, so a reconnect/fallback never reuses stale nonces/``sid``
        #: (§7.5, ``fallback-runtime-fix.md`` §5).
        self._sessions: dict[int, Session] = {}
        self._manager: TransportManager | None = None
        #: Handshake configuration of the one live connection, kept so a fallback
        #: (re-)activation can build a *fresh* session with the same PSK but new
        #: nonces/``sid`` (§7.5, ``fallback-runtime-fix.md`` §5).
        self._session_cfg: SessionConfig | None = None
        self._hooks: TransportHooks | None = None
        self._heartbeat_task: asyncio.Task | None = None
        self._heartbeat_session: Session | None = None
        self._background: list[asyncio.Task] = []
        self._data_dir: Path | None = None
        self._started = False
        self._connection_state = "disconnected"
        self._connection_reason = "not_started"
        self._llm_tools_registered = False
        self._trusted_peer: str | None = None
        self._trusted_sid: str | None = None
        #: Serialises the whole wake decision (reachability check, dedupe/chain/rate
        #: guard, send and record) so concurrent state changes cannot both pass the
        #: guard and send the same ``(task_id, event)`` twice.
        self._wake_lock = asyncio.Lock()
        self._sweeps: list[asyncio.Task] = []
        #: In-flight ``event.ack`` requests. An ack is queued and must never block the
        #: inbound ``receive`` loop (a serial ``session.call`` there stalls every later
        #: frame for up to its reply timeout), but each task is still owned here so
        #: ``terminate`` can cancel and reap it.
        self._ack_tasks: set[asyncio.Task] = set()

    # -- configuration helpers ---------------------------------------------------------

    def _cfg(self, key: str, default: Any) -> Any:
        """Read one plugin configuration value.

        Args:
            key: Configuration key.
            default: Fallback when the config is absent.

        Returns:
            The configured value or the default.
        """
        if self._config is None:
            return default
        try:
            value = self._config.get(key, default)
        except Exception:
            return default
        return default if value is None else value

    def _connections(self) -> list[dict]:
        """Return the configured connection templates (normalised).

        Returns:
            List of connection dictionaries; empty when unconfigured.
        """
        raw = _list(self._cfg("connections", []), [])
        connections: list[dict] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            conn_id = _str(item.get("conn_id"), "default").strip() or "default"
            if not CONN_ID_PATTERN.match(conn_id):
                logger.error("bridge config_invalid conn_id=%s reason=pattern", conn_id)
                continue
            connections.append(
                {
                    "conn_id": conn_id,
                    "mode": _str(item.get("conn_mode"), "connect"),
                    "transport": _str(item.get("conn_transport"), "ws"),
                    "fallback": [
                        str(entry)
                        for entry in _list(
                            item.get("conn_transport_fallback"), ["longpoll"]
                        )
                    ],
                    "host": _str(item.get("conn_host"), "127.0.0.1"),
                    "port": _int(item.get("conn_port"), 8765, minimum=1, maximum=65535),
                    # The inbound endpoint is configured separately from the peer
                    # address: webhook needs both sides reachable, so a connect side
                    # that only knows the peer address would otherwise advertise an
                    # ephemeral (or loopback) port as its own return path (§7.3).
                    "bind_addr": _str(item.get("conn_bind_addr"), "0.0.0.0"),
                    "bind_port": _int(
                        item.get("conn_bind_port"), 0, minimum=0, maximum=65535
                    ),
                    "path": _str(item.get("conn_path"), "/dsh-bridge") or "/dsh-bridge",
                    "tls": _bool(item.get("conn_tls_enabled"), False),
                    "tls_cert": _str(item.get("conn_tls_cert_path"), ""),
                    "tls_key": _str(item.get("conn_tls_key_path"), ""),
                    "tls_fingerprint": _str(item.get("conn_tls_fingerprint"), ""),
                    "psk_id": _str(item.get("conn_psk_id"), ""),
                    "psk_secret": _str(item.get("conn_psk_secret"), ""),
                    "allow_agent_create": _bool(
                        item.get("conn_allow_agent_create"), True
                    ),
                    "max_agent_sessions": _int(
                        item.get("conn_max_agent_sessions"), 10, minimum=0, maximum=1000
                    ),
                }
            )
        return connections

    def _primary(self) -> dict | None:
        """Return the first configured connection.

        Returns:
            The connection dictionary, or ``None``.
        """
        connections = self._connections()
        return connections[0] if connections else None

    def _conn_id(self) -> str:
        """Return the primary connection id for logs and protocol fields.

        Returns:
            Connection id, or ``default``.
        """
        conn = self._primary()
        return conn["conn_id"] if conn else "default"

    # -- lifecycle ---------------------------------------------------------------------

    async def initialize(self) -> None:
        """Create the data directory, open the store and start background work."""
        try:
            self._data_dir = Path(get_astrbot_plugin_data_path()) / PLUGIN_NAME
            (self._data_dir / "tmp").mkdir(parents=True, exist_ok=True)

            self._store = Store()
            await self._store.init(self._data_dir / "bridge.db")
            await self._store.cleanup_expired(
                _int(self._cfg("task_retention_days", 7), 7, minimum=1)
            )

            conn = self._primary()
            self._blobs = BlobService(
                tmp_dir=self._data_dir / "tmp",
                image_enabled=_bool(self._cfg("image_enabled", True), True),
                max_bytes=_int(
                    self._cfg("image_max_bytes", 10_485_760), 10_485_760, minimum=1024
                ),
                max_count=_int(
                    self._cfg("image_max_count", 4), 4, minimum=1, maximum=64
                ),
                total_max_bytes=_int(
                    self._cfg("image_total_max_bytes", 20_971_520),
                    20_971_520,
                    minimum=1024,
                ),
                allowed_mime=tuple(
                    _list(self._cfg("image_allowed_mime", None), list(IMAGE_MIME_TYPES))
                ),
            )
            await self._blobs.init()

            self._sessions_svc = SessionService(
                self._store,
                conn=self._conn_id(),
                allow_agent_create=conn["allow_agent_create"] if conn else True,
                max_agent_sessions=conn["max_agent_sessions"] if conn else 10,
                on_authz_changed=self._push_authz,
            )
            await self._sessions_svc.init()

            self._notify = NotifyService(
                self._store,
                conn=self._conn_id(),
                wake_max_chain=_int(
                    self._cfg("wake_max_chain", DEFAULT_WAKE_MAX_CHAIN),
                    DEFAULT_WAKE_MAX_CHAIN,
                    minimum=1,
                ),
                wake_rate_per_minute=_int(
                    self._cfg("wake_rate_per_minute", DEFAULT_WAKE_RATE_PER_MINUTE),
                    DEFAULT_WAKE_RATE_PER_MINUTE,
                    minimum=1,
                ),
                on_task_event=self._send_task_event,
                on_event=self._send_event_message,
                on_ack_request=self._send_ack_request,
            )

            self._platform = PlatformHost(self.context)
            self._capabilities = HostCapabilities(
                version="0.1.0",
                transports=["longpoll", "webhook", "ws"],
                tls=bool(conn["tls"]) if conn else False,
                image_enabled=_bool(self._cfg("image_enabled", True), True),
                image_max_count=_int(self._cfg("image_max_count", 4), 4, minimum=1),
                image_max_bytes=_int(
                    self._cfg("image_max_bytes", 10_485_760), 10_485_760, minimum=1024
                ),
                image_total_max_bytes=_int(
                    self._cfg("image_total_max_bytes", 20_971_520),
                    20_971_520,
                    minimum=1024,
                ),
            )

            self._openapi = OpenApiHost(
                base_url=_str(
                    self._cfg("openapi_base_url", "http://127.0.0.1:6185"),
                    "http://127.0.0.1:6185",
                ),
                api_key=_str(self._cfg("openapi_api_key", ""), ""),
                key_id=_str(self._cfg("openapi_key_id", ""), ""),
                allow_private_addr=_bool(self._cfg("addr_allow_private", False), False),
            )

            self._approvals = ApprovalService(
                self._store,
                conn=self._conn_id(),
                side="A",
                approval_timeout_s=_int(
                    self._cfg("approval_timeout_seconds", 1800), 1800, minimum=30
                ),
                notify_channels=_list(
                    self._cfg("approval_notify_channels", None), ["im", "web"]
                ),
                notify=self._notify,
                on_approval_decided=self._on_approval_decided,
                on_decision_answered=self._on_decision_answered,
                on_human_notify=self._on_human_notify,
                blobs=self._blobs,
                # Fail closed until a handshake proves the peer side: ``native_tool``
                # requests are refused while this anchor is not a protocol side.
                peer_side=UNVERIFIED_PEER_SIDE,
                native_tool_origin="B",
            )

            self._tasks = TaskService(
                self._store,
                conn=self._conn_id(),
                notify=self._notify,
                sessions=self._sessions_svc,
                host=self._host_runner(),
                approvals=self._approvals,
                image_enabled=_bool(self._cfg("image_enabled", True), True),
                on_state_change=self._on_task_state_change,
            )
            # Releasing a held outbound submission must use the session that is live
            # at that moment; a stale/absent link parks the task instead of sending.
            self._tasks.set_session_provider(lambda: self._session)

            self._router = Router(self._store, conn=self._conn_id())
            self._tasks.register(self._router)
            self._approvals.register(self._router)
            self._register_session_handlers()
            self._register_blob_handlers()
            self._register_notify_handlers()

            # OpenAPI identity self-check before any task can run (§16.3 rule 2).
            if self._openapi.configured():
                try:
                    await self._openapi.verify_ownership()
                except BridgeError as exc:
                    logger.error(
                        "bridge openapi identity check failed code=%s -> tasks disabled",
                        exc.code,
                    )
                    self._openapi = None
            else:
                logger.warning(
                    "bridge openapi not configured: inbound task execution is disabled"
                )

            await self._tasks.recover_after_restart()
            # Pending native tool approvals are peer-process-local promises: after a
            # restart the DSH run that asked is gone, so the only honest terminal state
            # is ``unavailable`` (never a silent grant, never a re-prompt) — §12.4.
            await self._approvals.invalidate_native_pending("restart")

            self._notify.start()
            self._background.append(asyncio.create_task(self._approvals.timeout_loop()))
            self._background.append(asyncio.create_task(self._blobs.cleanup_loop()))
            self._background.append(asyncio.create_task(self._maintenance_loop()))

            if _bool(self._cfg("dashboard_enabled", True), True):
                self._register_web_apis()
            self._register_llm_tools()

            if conn is not None:
                self._background.append(asyncio.create_task(self._run_connection(conn)))
            else:
                logger.warning(
                    "bridge no connection configured: add one in the plugin settings"
                )
            self._started = True
            logger.info("bridge plugin initialised data_dir=%s", self._data_dir)

        except BaseException:
            # The host clears the plugin registry on a failed load without calling
            # terminate(); release whatever this initialize opened, then re-raise the
            # original exception (including cancellation) unchanged.
            with contextlib.suppress(BaseException):
                await self.terminate()
            raise

    def _host_runner(self) -> Any:
        """Return the object used by the task service to execute inbound tasks.

        Returns:
            A runner exposing ``run_agent(task=...)``, or ``None`` when OpenAPI is off.
        """
        if self._openapi is None:
            return None
        plugin = self

        class _Runner:
            """Adapter that turns one inbound task into one AstrBot Agent run."""

            async def run_agent(self, *, task: dict) -> dict:
                """Execute one task through the OpenAPI chat stream.

                Args:
                    task: Stored task row.

                Returns:
                    Result restricted to the §11.4 whitelist.
                """
                return await plugin._execute_task(task)

        return _Runner()

    async def _execute_task(self, task: dict) -> dict:
        """Run one inbound task via ``POST /api/v1/chat`` (§6.8, §13).

        Args:
            task: Stored task row.

        Returns:
            Result dictionary restricted to the §11.4 whitelist.

        Raises:
            BridgeError: When OpenAPI is unavailable.
        """
        if self._openapi is None:
            raise BridgeError(
                "capability_unavailable", details={"reason": "openapi_off"}
            )
        payload = task.get("payload") or {}
        texts = [
            str(part.get("text", ""))
            for part in payload.get("input_parts", [])
            if isinstance(part, dict) and part.get("type") == "text"
        ]
        attachment_ids: list[str] = []
        degraded: list[str] = []
        validated = []
        # The provider that owns *this* task's OpenAPI session decides vision. Resolve
        # it once, before any upload: a missing session, an absent provider or a failed
        # lookup fails closed to a text placeholder, never to a silent upload.
        provider = None
        provider_ok = False
        if payload.get("attachments") and self._blobs is not None:
            validated = await self._blobs.validate_task_attachments(payload)
            session_id = payload.get("session_id")
            if isinstance(session_id, str) and session_id:
                umo = self._openapi.umo_for_session(session_id)
                try:
                    provider = await self.context.get_using_provider_async(umo=umo)
                    provider_ok = provider is not None
                except Exception:
                    logger.exception("bridge provider lookup failed umo=%s", umo)
            else:
                logger.warning(
                    "bridge image task has no session_id: vision fails closed"
                )
        for item in validated:
            if not (
                provider_ok
                and self._capabilities is not None
                and self._capabilities.supports_vision(provider)
            ):
                # Never silently drop an image: record the degradation and leave a
                # text placeholder for the model (§13.5).
                degraded.append("model_without_vision")
                texts.append(
                    f"[图片已附上，但当前模型不支持图像输入：{item.get('media_type')}]"
                )
                continue
            data = Path(item["path"]).read_bytes()
            attachment_id = await self._openapi.upload_image(
                data, item["media_type"], f"{item['blob_id']}.png"
            )
            attachment_ids.append(attachment_id)
        parts = build_message_parts(texts, attachment_ids)
        outcome = await self._openapi.run_agent(
            parts=parts, session_id=payload.get("session_id")
        )
        text = outcome.get("text") or ""
        return {
            "summary": text.strip()[:1024],
            "text": text[:4096],
            "attachments": [],
            "degraded": degraded,
        }

    async def terminate(self) -> None:
        """Cancel background work and close every resource (no leaks, no races)."""
        self._started = False
        # Reset the registration guard so the same instance can initialize again; the
        # host removes the rows by module path on unload, and add_llm_tools replaces
        # them by name when this instance re-registers.
        self._llm_tools_registered = False
        for task in list(self._background):
            task.cancel()
        for task in list(self._background):
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self._background.clear()

        # Queued acks hold a captured session: cancel and reap them before the
        # session is closed so nothing outlives the plugin.
        for task in list(self._ack_tasks):
            task.cancel()
        if self._ack_tasks:
            await asyncio.gather(*list(self._ack_tasks), return_exceptions=True)
        self._ack_tasks.clear()

        if self._tasks is not None:
            with contextlib.suppress(Exception):
                await self._tasks.stop()
        if self._session is not None:
            with contextlib.suppress(Exception):
                await self._session.close("draining", "plugin_unload")
            self._session = None
        if self._manager is not None:
            with contextlib.suppress(Exception):
                await self._manager.stop()
            self._manager = None
        if self._notify is not None:
            with contextlib.suppress(Exception):
                await self._notify.stop()
        if self._blobs is not None:
            with contextlib.suppress(Exception):
                await self._blobs.purge_tmp()
        if self._openapi is not None:
            with contextlib.suppress(Exception):
                await self._openapi.close()
            self._openapi = None
        if self._store is not None:
            with contextlib.suppress(Exception):
                await self._store.close()
            self._store = None
        logger.info("bridge plugin terminated")

    # -- connection lifecycle ----------------------------------------------------------

    async def _run_connection(self, conn: dict) -> None:
        """Own one connection: build the session, handshake, reconnect on loss.

        The manager calls :meth:`_bind_fresh_session` once per carrier activation and
        :meth:`_release_session` once per carrier release, so a fallback switch or a
        reconnect never reuses the previous session's ``nonce``/``sid``/replay window
        (protocol §4, §7.5; ``开发/v0.1/test/fallback-runtime-fix.md`` §5).

        Args:
            conn: Normalised connection configuration.
        """
        if self._router is None:
            return
        cfg = SessionConfig(
            conn=conn["conn_id"],
            side="A",
            role=Role.RESPONDER if conn["mode"] == "listen" else Role.INITIATOR,
            transport=conn["transport"],
            psk_id=conn["psk_id"],
            psk_secret=conn["psk_secret"],
            heartbeat_s=_int(self._cfg("heartbeat_interval", 30), 30, minimum=5),
            caps=self._capabilities.caps() if self._capabilities else {},
            version="0.1.0",
            host_id="astrbot",
            addr=conn["host"],
            port=conn["port"],
            bind_addr=conn["bind_addr"],
            bind_port=conn["bind_port"],
            path=conn["path"],
            mode=conn["mode"],
            tls_enabled=conn["tls"],
            tls_cert_path=conn["tls_cert"],
            tls_key_path=conn["tls_key"],
            tls_fingerprint=conn["tls_fingerprint"],
            reconnect_max_backoff=_int(
                self._cfg("reconnect_max_backoff", 60), 60, minimum=1
            ),
        )
        if not cfg.psk_id or not cfg.psk_secret:
            logger.error(
                "bridge connection %s refused: psk_not_configured (fill conn_psk_id and "
                "conn_psk_secret on both ends; the bridge never falls back to plaintext)",
                conn["conn_id"],
            )
            self._set_connection_state("config_error", "psk_not_configured")
            return
        problem = self._reachability_problem(conn)
        if problem:
            logger.error(
                "bridge connection %s refused: %s (webhook needs an explicit, reachable "
                "inbound endpoint on both ends; no loopback/ephemeral default is "
                "advertised as if it were reachable)",
                conn["conn_id"],
                problem,
            )
            self._set_connection_state("config_error", problem)
            return

        self._session_cfg = cfg
        # Hooks are stable wrappers that route to whichever session is current, so a
        # carrier that outlives its session can never deliver into a closed one.
        self._hooks = TransportHooks(
            on_plain=self._on_plain,
            on_envelope=self._on_envelope,
            on_probe=self._on_probe,
            on_state=self._set_connection_state,
            on_activity=self._on_activity,
        )
        manager = TransportManager(
            cfg,
            self._hooks,
            preferred=conn["transport"],
            fallbacks=conn["fallback"],
            on_transport=self._bind_fresh_session,
            on_release=self._release_session,
        )
        self._manager = manager

        async def connect() -> None:
            """Handshake the session currently bound to the live carrier."""
            # ``bring_up()`` binds a fresh session to the carrier it adopts and only
            # that carrier is live, so the handshake target must be resolved from the
            # manager instead of the ``_session`` attribute (which is still unset on
            # the very first activation).
            session = self._live_session()
            if session is None:
                raise BridgeError(ERR_NOT_READY, details={"reason": "no_session"})
            await session.start()

        try:
            await manager.bring_up()
            await connect()
            self._background.append(
                asyncio.create_task(manager.run_forever(connect=connect))
            )
        except asyncio.CancelledError:
            raise
        except BridgeError as exc:
            logger.error(
                "bridge connection %s failed code=%s", conn["conn_id"], exc.code
            )
            state = (
                "config_error"
                if exc.code in ("psk_not_configured", "config_invalid")
                else "disconnected"
            )
            self._set_connection_state(state, exc.code)

    def _reachability_problem(self, conn: dict) -> str:
        """Return a config problem that would make a carrier unreachable.

        Webhook is the only carrier that needs *both* endpoints to accept inbound
        connections (§7.3). Its return path must therefore be an explicitly
        configured, non-loopback-relative endpoint: an ephemeral port (``0``) or a
        hard-coded ``127.0.0.1`` only works on one host and must never be reported as
        a normal connection.

        Args:
            conn: Normalised connection configuration.

        Returns:
            A short English reason, or an empty string when the configuration is
            usable.
        """
        carriers = [conn["transport"], *conn["fallback"]]
        if TRANSPORT_WEBHOOK not in carriers:
            return ""
        if conn["mode"] == "connect" and int(conn["bind_port"]) <= 0:
            return "webhook_bind_port_unset"
        loopback = {"", "127.0.0.1", "localhost", "::1", "0.0.0.0", "::"}
        peer_is_local = conn["host"] in {"127.0.0.1", "localhost", "::1"}
        if not peer_is_local and conn["bind_addr"] in loopback:
            return "webhook_bind_addr_unreachable"
        return ""

    async def _bind_fresh_session(self, transport: Any) -> None:
        """Bind a **new** session to a carrier the manager is about to start.

        Called once per activation, before ``start()``. Reusing one session across
        carriers would keep ``_next_seq`` and the 64-frame replay window while the
        peer restarts from ``seq=0``, so the link would fail with
        ``replay_out_of_window`` after a switch (§4, §5.4).

        A carrier that already has a live session which the manager has *adopted* is
        returned unchanged: that is the "still-running fallback" case after a failed
        preferred-carrier attempt, where the live link must survive (§7.5 rule 3).

        Args:
            transport: Carrier that will carry this session.
        """
        existing = self._sessions.get(id(transport))
        if (
            existing is not None
            and existing.state is not SessionState.CLOSED
            and self._manager is not None
            and self._manager.transport() is transport
        ):
            return
        cfg = self._session_cfg
        if cfg is None:
            raise BridgeError(ERR_NOT_READY, details={"reason": "no_session_cfg"})
        # The reply must travel back over the very session that received the request,
        # so the callback is bound to this session instead of reading ``_session``
        # (which always points at the adopted carrier).
        holder: dict[str, Session] = {}
        session = Session(
            cfg,
            transport,
            lambda message: self._on_session_message(message, holder["session"]),
            self._on_security_event,
            on_state=self._on_session_state,
        )
        holder["session"] = session
        self._sessions[id(transport)] = session
        # A brand-new session has no authenticated peer: withdraw trust (which also
        # retires the previous session's pending native approvals) so nothing can be
        # approved against a link that no longer exists.
        self._sync_peer_trust()
        self._set_connection_state("connecting", "session_created")

    async def _release_session(self, transport: Any) -> None:
        """Close the session bound to a carrier the manager is about to stop.

        Runs before the carrier is stopped, so the ``close`` frame can still travel.
        Withdrawing trust also finalises the pending native tool approvals of that
        session (the peer's promise died with it, §12.4).

        Args:
            transport: Outgoing carrier.
        """
        session = self._sessions.pop(id(transport), None)
        if session is None:
            return
        if session is self._session:
            self._session = None
        await self._close_session(session, "carrier_switch")
        self._sync_peer_trust()

    def _live_session(self) -> Session | None:
        """Return the session that may carry traffic right now.

        The manager adopts a carrier only after its ``start()`` succeeded, so the
        session bound to the adopted carrier is the one live link. When no carrier is
        adopted (module-level tests that install a session directly, or a plugin with
        no configured connection) the installed session is used instead.

        Returns:
            The live session, or ``None``.
        """
        manager = self._manager
        transport = manager.transport() if manager is not None else None
        bound = self._sessions.get(id(transport)) if transport is not None else None
        if bound is not None:
            self._session = bound
            return bound
        session = self._session
        if session is None:
            return None
        if getattr(session, "state", None) is SessionState.CLOSED:
            self._session = None
            return None
        return session

    async def _close_session(self, session: Session, reason: str) -> None:
        """Cancel the heartbeat of a session and close it, ignoring double-close.

        Args:
            session: Session to close.
            reason: Short English reason recorded by the session layer.
        """
        if self._heartbeat_session is session:
            await self._stop_heartbeat()
        if session.state is SessionState.CLOSED:
            return
        with contextlib.suppress(Exception):
            await session.close("draining", reason)

    async def _on_plain(self, obj: dict) -> dict | None:
        """Route a plaintext handshake object to the live session.

        Args:
            obj: ``hello`` / ``hello_ack`` object.

        Returns:
            The reply object, if any.

        Raises:
            BridgeError: ``not_ready`` when no session is bound yet.
        """
        session = self._live_session()
        if session is None:
            raise BridgeError(ERR_NOT_READY, details={"reason": "no_session"})
        return await session.handle_plain(obj)

    async def _on_envelope(self, envelope: dict) -> None:
        """Route one sealed envelope to the live session.

        Args:
            envelope: Raw envelope object.
        """
        session = self._live_session()
        if session is None:
            return
        await session.handle_envelope(envelope)

    def _on_activity(self) -> None:
        """Feed the shared liveness clock of the live session."""
        session = self._live_session()
        if session is not None:
            session.touch()

    async def _stop_heartbeat(self) -> None:
        """Cancel the heartbeat task of the current session, if any."""
        task = self._heartbeat_task
        self._heartbeat_task = None
        self._heartbeat_session = None
        if task is None:
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task

    def _start_heartbeat(self) -> None:
        """Start the heartbeat loop for the live session once it is ready."""
        session = self._live_session()
        if session is None:
            return
        if (
            self._heartbeat_task is not None
            and not self._heartbeat_task.done()
            and self._heartbeat_session is session
        ):
            return
        try:
            task = asyncio.create_task(session.run_heartbeat())
        except RuntimeError:
            logger.warning("bridge heartbeat skipped (no running loop)")
            return
        self._heartbeat_task = task
        self._heartbeat_session = session
        self._background.append(task)

    def _schedule_authz_push(self) -> None:
        """Push the full ``session.authz`` table over the freshly ready session.

        The grant table is authoritative on A and may have changed while the link
        was down (agent auto-grants, revocations, a restart), so every ``ready``
        re-publishes the complete snapshot instead of only future diffs (§9.7).
        A first connection is therefore usable for authorized sessions immediately,
        without waiting for some later mutation to trigger a push.
        """
        sessions = self._sessions_svc
        session = self._live_session()
        if sessions is None or session is None:
            return

        async def _run() -> None:
            if session.state is not SessionState.READY:
                return
            try:
                await session.send_message(await sessions.authz_message())
            except Exception:
                logger.warning(
                    "bridge session.authz push on ready failed (retried on next ready)"
                )

        try:
            task = asyncio.create_task(_run())
        except RuntimeError:
            return
        self._background.append(task)

    def _set_connection_state(self, state: str, reason: str) -> None:
        """Record the exposed connection state.

        Args:
            state: Connection state string.
            reason: Short English reason.
        """
        self._connection_state = state
        self._connection_reason = reason

    def _on_session_state(self, state: SessionState, reason: str) -> None:
        """Forward session state transitions and re-evaluate approval trust.

        Args:
            state: Session state.
            reason: Short English reason.
        """
        self._set_connection_state(state.value, reason)
        # Trust and pending-promise bookkeeping are re-derived from the live session
        # on every transition (see ``_sync_peer_trust``), including the very first
        # ``ready`` and every later loss/new-``sid``.
        self._sync_peer_trust()
        if state is SessionState.READY:
            self._start_heartbeat()
            self._schedule_authz_push()

    def _on_security_event(self, code: str, detail: str) -> None:
        """Log a security event (already sanitised by the session layer).

        Args:
            code: §15 error code.
            detail: Non-secret detail.
        """
        logger.warning("bridge security event code=%s detail=%s", code, detail)

    # -- peer trust (T1) and pending native approval lifecycle (T2) --------------------

    def _sync_peer_trust(self) -> None:
        """Bind approval trust to the peer side of *this* handshake, fail closed.

        ``Session.peer_side`` is written only by the handshake after the signed
        ``hello`` / ``hello_ack`` (responder) or ``auth_ack`` (initiator) verifies,
        so it is the single trustworthy statement about who is on the other end.
        While the session is not ``READY``, or has not authenticated a side yet, the
        anchor is reset to the non-side :data:`UNVERIFIED_PEER_SIDE`:
        ``ApprovalService`` then refuses ``native_tool`` requests (``not_ready``
        semantics) instead of falling back to its permissive ``"B"`` default. A
        payload claiming ``origin_side`` / ``_peer_side`` never grants trust because
        this value never comes from the wire.

        A new authenticated ``sid`` (same connection) or a lost connection also
        finalises that session's pending native approvals as ``unavailable``: the
        peer's promise belonged to a run it no longer tracks. The same transition
        binds the handshake ``caps`` (so ``approval.lookup`` is only attempted when
        the authenticated peer advertised it) and clears them on loss.
        """
        if self._approvals is None:
            return
        session = self._session
        ready = session is not None and session.state is SessionState.READY
        peer_side = session.peer_side if ready else None
        if peer_side not in ("A", "B"):
            lost_sid = self._trusted_sid
            if self._trusted_peer is not None or lost_sid is not None:
                logger.warning(
                    "bridge approval trust reset (session=%s) previous_side=%s",
                    session.state.value if session is not None else "none",
                    self._trusted_peer,
                )
            self._trusted_peer = None
            self._trusted_sid = None
            self._approvals.bind_peer_side(UNVERIFIED_PEER_SIDE)
            # No live session: a lookup can neither be answered with fresh
            # evidence nor used to prove a peer reference. Clearing the caps is
            # what makes an unnegotiated lookup fail closed instead of attempting
            # a call to a peer whose features are unknown.
            self._approvals.bind_peer_caps(None)
            self._approvals.bind_session(self._conn_id(), None)
            self._approvals.set_peer_call(None)
            if lost_sid is not None:
                # A late answer on a dead link must not be sendable, and the row
                # must not stay answerable by a human either.
                self._schedule_native_invalidation("disconnected", lost_sid)
            return

        self._approvals.bind_peer_side(peer_side)
        # The capability set used to decide whether an outbound ``approval.lookup``
        # is allowed comes from the same authenticated handshake. It is rebound on
        # every ready (including the first) and cleared above on loss.
        self._approvals.bind_peer_caps(session.peer_caps)
        if peer_side != self._trusted_peer:
            logger.info(
                "bridge approval trust bound peer_side=%s conn=%s",
                peer_side,
                self._conn_id(),
            )
            self._trusted_peer = peer_side
        sid = session.sid
        if not sid:
            return
        # Evidence is bound to the authenticated session (§12.7). Rebinding on
        # every ready (including the first) is what lets this endpoint answer a
        # lookup after the peer's sentinel and stops old sids from answering.
        self._approvals.bind_session(session.cfg.conn, sid)

        async def _peer_call(message: str, params: dict, timeout_s: float) -> dict:
            """Call the peer on exactly the session that installed this hook.

            Args:
                message: Protocol message name.
                params: Request parameters.
                timeout_s: Reply timeout.

            Returns:
                The reply result object.

            Raises:
                BridgeError: ``approval_lookup_failed`` when that session is no
                    longer the live/ready one, so evidence cannot leak across a
                    reconnect.
            """
            live = self._session
            if (
                live is not bound_session
                or live.state is not SessionState.READY
                or live.sid != bound_sid
            ):
                raise BridgeError(ERR_APPROVAL_LOOKUP_FAILED)
            return await live.call(message, params, timeout_s=timeout_s)

        bound_session = session
        bound_sid = sid
        self._approvals.set_peer_call(_peer_call)
        if sid == self._trusted_sid:
            return
        previous, self._trusted_sid = self._trusted_sid, sid
        if previous is not None:
            self._schedule_native_invalidation("new_sid", previous)

    async def _flush_native_sweeps(self) -> None:
        """Wait for pending "session went away" invalidations to hit the store.

        Every entry point a human or the peer can use to act on a native approval
        calls this first (inbound dispatch, the Dashboard listing/decision APIs and
        the ``/dsh approve|reject`` commands). A late answer can therefore never win
        a race against the sweep that turns the orphaned request into
        ``unavailable``, and the decision is emitted for nothing.
        """
        sweeps = [item for item in self._sweeps if not item.done()]
        if sweeps:
            with contextlib.suppress(Exception):
                await asyncio.gather(*sweeps, return_exceptions=True)

    def _schedule_native_invalidation(self, reason: str, lost_sid: str) -> None:
        """Invalidate the pending native approvals of a session that went away.

        The session state callback is synchronous, so the store work is scheduled;
        inbound dispatch waits for it (:meth:`_on_session_message`), which is what
        keeps a *new* sid's requests alive: they are only handled after the old
        pending rows have been finalised, so there is nothing left to mis-kill.

        Args:
            reason: Audit reason (``disconnected`` / ``new_sid``).
            lost_sid: Session id whose promises are being given up.
        """
        approvals = self._approvals
        if approvals is None or not self._started:
            # Shutdown closes the session too; the startup ``restart`` invalidation
            # covers that case without racing the background-task teardown.
            return

        async def _run() -> None:
            try:
                invalidated = await approvals.invalidate_native_pending(reason)
                logger.info(
                    "bridge invalidated %d pending native approval(s) reason=%s sid=%s",
                    len(invalidated),
                    reason,
                    lost_sid,
                )
            except Exception:
                logger.exception(
                    "bridge native approval invalidation failed reason=%s", reason
                )

        try:
            task = asyncio.create_task(_run())
        except RuntimeError:
            logger.warning(
                "bridge native approval invalidation skipped reason=%s (no loop)",
                reason,
            )
            return
        self._sweeps = [item for item in self._sweeps if not item.done()]
        self._sweeps.append(task)
        self._background.append(task)
        self._background = [item for item in self._background if not item.done()]

    async def _on_probe(self, obj: dict) -> dict:
        """Answer a webhook probe with a verified MAC (§7.3).

        Args:
            obj: Probe object.

        Returns:
            ``probe_ack`` object.

        Raises:
            BridgeError: ``psk_not_configured`` when no PSK is available.
        """
        conn = self._primary()
        if conn is None or not conn["psk_id"] or not conn["psk_secret"]:
            raise BridgeError(ERR_PSK_NOT_CONFIGURED)
        master = psk_master(conn["psk_id"], conn["psk_secret"])
        body = {
            "v": 1,
            "type": "probe_ack",
            "conn": obj.get("conn", conn["conn_id"]),
            "nonce": obj.get("nonce"),
            "ts": int(time.time() * 1000),
        }
        body["mac"] = mac_object(handshake_key(master, "probe_ack"), body)
        return body

    async def _on_session_message(
        self, message: dict, session: Session | None = None
    ) -> None:
        """Dispatch one inbound message and send the reply over its own session.

        Args:
            message: Validated ``req``/``evt`` object from the session layer.
            session: Session that received the message; its reply goes back over this
                one, never over whichever session happens to be adopted later.
        """
        if self._router is None:
            return
        target = session if session is not None else self._session
        # A sid change or a lost link may have orphaned native tool approval promises.
        # Finish that bookkeeping first, so a request that arrives on the *new* link
        # can never be swept away by the old session's cleanup.
        await self._flush_native_sweeps()
        reply = await self._router.dispatch(message)
        if reply is not None and target is not None:
            await target.send_message(reply)

    async def _send_task_event(self, params: dict) -> None:
        """Send a ``task.event`` notification over the live session (§11.2).

        Args:
            params: Event parameters.

        Raises:
            RuntimeError: When the session cannot carry the message, so the outbox keeps
                retrying instead of silently dropping the notification.
        """
        if self._session is None or self._session.state is not SessionState.READY:
            raise RuntimeError("session not ready")
        await self._session.send_message(inbound_event_message(params))

    async def _send_event_message(
        self, params: dict, row: dict, task_id: str, root_task_id: str
    ) -> None:
        """Send a non-``task.event`` notification over the live session (§9.2, §12.3).

        Covers every other existing event message the outbox can hold —
        ``approval.decision``, ``decision.request``, ``session.authz`` and the blob
        events. The envelope is the same ``evt`` shape used for ``task.event`` (fresh
        ``id``, protocol UTC-millisecond ``ts``), with ``m`` taken from the outbox row
        so a decision reaches the peer that is waiting for it.

        Args:
            params: Event parameters stored in the outbox row.
            row: Outbox row; its ``message`` is the wire message name.
            task_id: Owning task id (empty for approvals without a task).
            root_task_id: Root task id for wake/audit accounting.

        Raises:
            RuntimeError: When the session cannot carry the message, so the outbox
                keeps retrying instead of silently dropping the notification.
        """
        message = row["message"]
        if self._session is None or self._session.state is not SessionState.READY:
            # The persistent outbox retries with backoff; an unready link is never
            # turned into a silent drop and never into an approval outcome.
            raise RuntimeError(f"session not ready for {message}")
        await self._session.send_message(make_message("evt", message, params=params))

    async def _send_ack_request(self, params: dict) -> dict:
        """Queue ``event.ack`` to the peer as a real ``req`` (§11.1).

        ``event.ack`` is a request in both directions: it must arrive as ``k=req`` so
        the peer can answer ``rep`` and resolve its own pending delivery. It is never
        wrapped as an ``evt``.

        The call itself runs in a managed task: the ack is produced by the serial
        inbound ``receive`` path, and awaiting a request/reply there would block every
        later frame for up to the reply timeout. A queued ack therefore reports
        ``queued`` — never a made-up ``delivered`` — and the task logs its own
        exception when the reply fails (the peer keeps resending until it is acked,
        and the duplicate path acks again). The session is captured now: the task must
        not read a later session, and a closed old session simply fails the call.

        Args:
            params: ``event.ack`` parameters from ``build_ack_params``.

        Returns:
            ``{"notify_id", "queued": True}`` once the request is scheduled.

        Raises:
            RuntimeError: When no ready session can carry the ack; the peer will resend
                the event, and the duplicate path acks again.
        """
        session = self._session
        if session is None or session.state is not SessionState.READY:
            raise RuntimeError("session not ready for event.ack")

        async def _run() -> None:
            try:
                await session.call(MSG_EVENT_ACK, params)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.warning(
                    "bridge event.ack request failed notify=%s task=%s (peer resend "
                    "will retry)",
                    params.get("notify_id"),
                    params.get("task_id"),
                    exc_info=True,
                )

        try:
            task = asyncio.create_task(_run())
        except RuntimeError:
            raise RuntimeError("event.ack cannot be queued without an event loop")
        self._ack_tasks.add(task)
        task.add_done_callback(self._ack_tasks.discard)
        return {"notify_id": params.get("notify_id"), "queued": True}

    async def _push_authz(self, snapshot: dict) -> None:
        """Push ``session.authz`` whenever the authorization table changes (§9.7).

        Args:
            snapshot: New snapshot.
        """
        if self._sessions_svc is None or self._session is None:
            return
        try:
            await self._session.send_message(await self._sessions_svc.authz_message())
        except Exception:
            logger.warning("bridge session.authz push deferred (session not ready)")

    # -- handler registration ----------------------------------------------------------

    def _register_session_handlers(self) -> None:
        """Register ``session.*`` handlers on the router (§9.7)."""
        assert self._router is not None and self._sessions_svc is not None
        router = self._router
        service = self._sessions_svc
        router.register("session.list", lambda p, c: service.list_sessions(p))
        router.register("session.create", lambda p, c: service.create_session(p))
        router.register("session.select", lambda p, c: service.select_session(p))
        router.register("session.manage", lambda p, c: service.manage_session(p))
        router.register("session.authz", lambda p, c: self._on_authz_event(p))
        router.register("decision.request", lambda p, c: self._on_decision_request(p))

    async def _on_authz_event(self, params: dict) -> dict:
        """Handle an inbound ``session.authz`` (A is authoritative, so this is INFO only).

        Args:
            params: Authz parameters.

        Returns:
            Empty dict; A never accepts a peer's authorization table.
        """
        logger.info(
            "bridge ignoring inbound session.authz version=%s (A is authoritative)",
            params.get("version"),
        )
        return {}

    async def _on_decision_request(self, params: dict) -> dict:
        """Surface a peer's decision request to a human (§9.8).

        Args:
            params: Decision request parameters.

        Returns:
            Empty dict; the real answer travels back as ``decision.answer``.
        """
        if self._store is None:
            return {}
        expires_at = ApprovalService._parse_iso(params.get("expires_at")) or (
            time.time() + 1800
        )
        await self._store.put_decision(
            {
                "decision_id": params.get("decision_id"),
                "task_id": params.get("task_id"),
                "root_task_id": params.get("root_task_id", params.get("task_id")),
                "question": params.get("question", ""),
                "options": params.get("options", []),
                "allow_free_text": params.get("allow_free_text", False),
                "default_option": params.get("default_option"),
                "expires_at": expires_at,
                "notify_id": params.get("notify_id"),
            }
        )
        await self._on_human_notify(
            {
                "approval_id": params.get("decision_id"),
                "approval_type": "business_decision",
                "task_id": params.get("task_id"),
                "tool": "decision",
                "reason": params.get("question"),
                "display_reason": {"en": "Decision required", "zh": "需要业务决策"},
                "channels": _list(
                    self._cfg("approval_notify_channels", None), ["im", "web"]
                ),
            }
        )
        return {}

    def _register_blob_handlers(self) -> None:
        """Register ``blob.*`` handlers on the router (§13.3)."""
        assert self._router is not None and self._blobs is not None
        router = self._router
        blobs = self._blobs
        router.register("blob.begin", lambda p, c: blobs.begin(p))
        router.register("blob.chunk", lambda p, c: blobs.chunk(p))
        router.register("blob.commit", lambda p, c: blobs.commit(p))
        router.register("blob.abort", lambda p, c: blobs.abort(p))

    def _register_notify_handlers(self) -> None:
        """Register ``event.ack`` on the router (§11.1)."""
        assert self._router is not None and self._notify is not None
        notify = self._notify
        self._router.register("event.ack", lambda p, c: notify.on_ack(p))

    # -- approval / decision / wake callbacks ------------------------------------------

    async def _on_approval_decided(self, approval: dict, allowed: bool) -> None:
        """Apply an approval outcome to its task (§12.3).

        Args:
            approval: Decided approval row.
            allowed: Whether the human allowed it once.
        """
        if self._tasks is not None:
            await self._tasks.on_approved(approval, allowed=allowed)

    async def _on_decision_answered(self, decision: dict) -> None:
        """Forward a human answer to the executor (§9.8).

        Args:
            decision: Answered (or timed out) decision row.
        """
        if self._session is None:
            return
        if decision.get("timed_out"):
            logger.info(
                "bridge decision timed out id=%s task=%s",
                decision.get("decision_id"),
                decision.get("task_id"),
            )
            return
        params = {
            "decision_id": decision["decision_id"],
            "choice": decision.get("choice"),
            "free_text": decision.get("free_text"),
            "actor": decision.get("actor"),
            "actor_kind": decision.get("actor_kind"),
            "answered_at": utc_iso_ms(),
        }
        with contextlib.suppress(Exception):
            await self._session.send_message(
                make_message("req", "decision.answer", params=params)
            )

    async def _on_task_state_change(self, task: dict, event: str) -> None:
        """Wake the originating conversation for terminal and blocking states (§16.6).

        An archived session is never woken: the archive is a human disposition of the
        session grant, so the task keeps whatever terminal state it reached, no IM is
        sent, and no wake-chain or rate budget is spent. A host without a platform, or
        one whose platform is not registered for this UMO, cannot deliver either, so it
        also returns before any budget is occupied.

        Args:
            task: Updated task row.
            event: Event that caused the change.
        """
        if event not in WAKE_EVENTS or self._notify is None:
            return
        session_id = task.get("session_id")
        if session_id and self._store is not None:
            grant = await self._store.get_grant(session_id)
            if grant is not None and grant["archived"]:
                logger.info(
                    "bridge wake skipped task=%s event=%s reason=session_archived",
                    task["task_id"],
                    event,
                )
                return
        payload = task.get("payload") or {}
        umo = payload.get("umo") or payload.get("session_umo")
        if not umo:
            logger.info(
                "bridge wake skipped task=%s event=%s reason=no_umo",
                task["task_id"],
                event,
            )
            return
        platform = self._platform
        if platform is None:
            logger.info(
                "bridge wake skipped task=%s event=%s reason=no_platform",
                task["task_id"],
                event,
            )
            return
        # Guard + send + record are one serialised decision per wake. Without the lock
        # two concurrent state changes can both pass dedupe/rate and send the same wake.
        async with self._wake_lock:
            # Reachability is a synchronous, budget-free lookup. It must precede the
            # guard so an unreachable platform never consumes chain/rate budget.
            if not platform.can_send(umo):
                logger.info(
                    "bridge wake skipped task=%s event=%s reason=platform_unreachable",
                    task["task_id"],
                    event,
                )
                return
            try:
                if not await self._notify.guard_wake(task, event, umo):
                    # This ``(task_id, event)`` wake was already delivered: stay silent.
                    return
            except BridgeError as exc:
                await self._notify.handle_wake_guard_failure(task, exc.code)
                return
            text = self._wake_text(task, event)
            delivered = await platform.send_text(umo, text)
            if delivered:
                await self._notify.record_wake(task, event)
            else:
                # The rate/chain attempt stays spent (guard already charged it), but a
                # failed send must never be recorded as delivered.
                logger.warning(
                    "bridge wake delivery failed task=%s event=%s",
                    task["task_id"],
                    event,
                )

    def _wake_text(self, task: dict, event: str) -> str:
        """Compose the wake message for a conversation.

        Args:
            task: Task row.
            event: Wake event name.

        Returns:
            Chinese human-facing text clipped to a safe length.
        """
        status = task.get("status")
        error = task.get("error") or {}
        result = task.get("result") or {}
        direction = (
            "本端发起" if task.get("direction") == DIRECTION_OUTBOUND else "对端发起"
        )
        lines = [
            f"【DSH 桥接】任务 {task['task_id']} 状态更新：{status}（{direction}）"
        ]
        if event == "completed" and isinstance(result.get("summary"), str):
            lines.append(f"结果摘要：{result['summary']}")
        if event == "failed" and isinstance(error.get("code"), str):
            lines.append(f"失败原因：{error['code']}")
        if event == "needs_decision":
            lines.append("需要你做出业务决策，请到后台页或使用 /dsh 指令处理。")
        if event == "needs_approval":
            lines.append("需要你批准，请到后台页或使用 /dsh approve 处理。")
        return "\n".join(lines)[:MAX_WAKE_TEXT]

    async def _on_human_notify(self, payload: dict) -> None:
        """Notify a human about a pending approval or decision (§6.6.7).

        Args:
            payload: Notification payload.
        """
        platform = self._platform
        if platform is None:
            return
        # The Web page always keeps the pending row; IM is an optional extra channel.
        # A non-list value or a list without ``im`` therefore degrades to Web only.
        channels = payload.get("channels")
        if not isinstance(channels, list) or "im" not in channels:
            logger.info(
                "bridge approval notification web-only id=%s",
                payload.get("approval_id"),
            )
            return
        umo = _str(self._cfg("approval_notify_umo", ""), "")
        if not umo:
            logger.info(
                "bridge approval notification web-only id=%s",
                payload.get("approval_id"),
            )
            return
        text = (
            f"【DSH 桥接】待处理审批：{payload.get('tool') or payload.get('approval_type')}\n"
            f"任务：{payload.get('task_id') or '-'}\n"
            f"原因：{(payload.get('reason') or '')[:300]}\n"
            f"审批号：{payload.get('approval_id')}\n"
            "请使用 /dsh approve 或 /dsh reject 处理。"
        )
        await platform.send_text(umo, text[:MAX_WAKE_TEXT])

    # -- background maintenance --------------------------------------------------------

    async def _maintenance_loop(self, interval_s: float = 300.0) -> None:
        """Periodically clean expired rows without blocking the main flow (§10.1).

        Args:
            interval_s: Scan interval.
        """
        while True:
            try:
                if self._store is not None:
                    retention = _int(self._cfg("task_retention_days", 7), 7, minimum=1)
                    removed = await self._store.cleanup_expired(retention)
                    if removed:
                        logger.info(
                            "bridge retention cleanup removed=%s tasks", removed
                        )
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("bridge maintenance loop failed")
            await asyncio.sleep(interval_s)

    # -- commands ----------------------------------------------------------------------

    @filter.command_group("dsh")
    def dsh(self):
        """DSH 桥接指令组。"""
        pass

    @dsh.command("help")
    async def dsh_help(self, event: AstrMessageEvent):
        """显示 DSH 桥接帮助。

        Args:
            event: Incoming message event.
        """
        yield event.plain_result(
            "DSH 桥接指令：\n"
            "/dsh status — 连接与传输概况\n"
            "/dsh tasks [n] — 最近任务（双向标注）\n"
            "/dsh sessions — 会话与授权概览\n"
            "/dsh approve <审批号> — 批准一次（仅人可批）\n"
            "/dsh reject <审批号> [理由] — 拒绝\n"
            "任务提交与查询请通过 LLM 工具 dsh_submit_task / dsh_task_status 完成。"
        )

    @dsh.command("status")
    async def dsh_status(self, event: AstrMessageEvent):
        """显示连接状态与传输信息（仅管理员）。

        Args:
            event: Incoming message event.
        """
        if not self._is_admin(event):
            yield event.plain_result("该指令仅管理员可用。")
            return
        diagnostics = self._manager.diagnostics() if self._manager else {}
        session = self._session
        lines = [
            "【DSH 桥接状态】",
            f"连接：{self._connection_state}（{self._connection_reason}）",
            f"传输：{diagnostics.get('current') or '-'}，"
            f"首选 {diagnostics.get('preferred') or '-'}",
            f"已降级：{'是' if diagnostics.get('degraded') else '否'}",
        ]
        if session is not None and session.peer_caps:
            caps = session.peer_caps
            lines.append(
                f"对端：{caps.get('host')} v{caps.get('version')}，pv={caps.get('pv')}"
            )
            lines.append(f"会话：{session.sid or '-'}")
        else:
            lines.append("对端：未连接")
        if diagnostics.get("last_error"):
            lines.append(f"最近错误：{diagnostics['last_error']}")
        yield event.plain_result("\n".join(lines))

    @dsh.command("tasks")
    async def dsh_tasks(self, event: AstrMessageEvent, count: int = 10):
        """列出最近任务（仅管理员）。

        Args:
            event: Incoming message event.
            count: Number of tasks to show.
        """
        if not self._is_admin(event):
            yield event.plain_result("该指令仅管理员可用。")
            return
        if self._store is None:
            yield event.plain_result("桥接尚未初始化。")
            return
        limit = _int(count, 10, minimum=1, maximum=50)
        tasks, _cursor = await self._store.list_tasks(limit=limit)
        if not tasks:
            yield event.plain_result("暂无任务。")
            return
        lines = ["【最近任务】"]
        for task in tasks:
            direction = "→" if task["direction"] == DIRECTION_OUTBOUND else "←"
            lines.append(
                f"{direction} {task['task_id'][:8]} {task['status']} "
                f"{task.get('purpose') or '-'}"
            )
        yield event.plain_result("\n".join(lines))

    @dsh.command("sessions")
    async def dsh_sessions(self, event: AstrMessageEvent):
        """显示会话授权概览（仅管理员）。

        Args:
            event: Incoming message event.
        """
        if not self._is_admin(event):
            yield event.plain_result("该指令仅管理员可用。")
            return
        if self._sessions_svc is None:
            yield event.plain_result("桥接尚未初始化。")
            return
        grants = await self._sessions_svc.admin_grants()
        quota = await self._sessions_svc.admin_quota()
        if not grants:
            yield event.plain_result(
                f"暂无授权会话。Agent 创建配额：{quota['used']}/{quota['max']}，"
                f"允许创建：{'是' if quota['allow_agent_create'] else '否'}"
            )
            return
        lines = [
            f"【会话授权】Agent 配额 {quota['used']}/{quota['max']}"
            f"（允许创建：{'是' if quota['allow_agent_create'] else '否'}）"
        ]
        for grant in grants[:20]:
            state = "已撤销" if grant["revoked"] else "有效"
            lines.append(
                f"{grant['session_id'][:8]} {state} 用途={grant['purpose'] or '-'} "
                f"来源={grant['granted_by']}"
            )
        yield event.plain_result("\n".join(lines))

    @dsh.command("approve")
    async def dsh_approve(self, event: AstrMessageEvent, approval_id: str = ""):
        """批准一条待审批请求（仅管理员，一次有效）。

        Args:
            event: Incoming message event.
            approval_id: Approval identifier (a unique prefix is accepted).
        """
        if not self._is_admin(event):
            yield event.plain_result("该指令仅管理员可用。")
            return
        async for line in self._decide_from_command(
            event, approval_id, allowed=True, reason=None
        ):
            yield event.plain_result(line)

    @dsh.command("reject")
    async def dsh_reject(
        self, event: AstrMessageEvent, approval_id: str = "", reason: str = ""
    ):
        """拒绝一条待审批请求（仅管理员）。

        Args:
            event: Incoming message event.
            approval_id: Approval identifier (a unique prefix is accepted).
            reason: Optional reason.
        """
        if not self._is_admin(event):
            yield event.plain_result("该指令仅管理员可用。")
            return
        async for line in self._decide_from_command(
            event, approval_id, allowed=False, reason=reason or None
        ):
            yield event.plain_result(line)

    async def _decide_from_command(
        self,
        event: AstrMessageEvent,
        approval_id: str,
        *,
        allowed: bool,
        reason: str | None,
    ):
        """Shared implementation for ``/dsh approve`` and ``/dsh reject``.

        Args:
            event: Incoming message event.
            approval_id: Approval identifier or unique prefix.
            allowed: ``True`` to allow once, ``False`` to reject.
            reason: Optional human reason.

        Yields:
            One response line.
        """
        if self._approvals is None or self._store is None:
            yield "桥接尚未初始化。"
            return
        await self._flush_native_sweeps()
        resolved = await self._resolve_approval_id(approval_id)
        if resolved is None:
            yield "未找到对应的待审批项，请检查审批号。"
            return
        actor = f"astrbot_admin:{event.get_sender_id()}"
        applied, failure = await self._approvals.human_decide(
            resolved, allowed=allowed, actor=actor, channel="im", reason=reason
        )
        if not applied:
            yield f"该审批已处理或已过期（{failure or 'unknown'}），本次操作未生效。"
            return
        yield f"已{'批准（仅一次）' if allowed else '拒绝'}：{resolved}"

    async def _resolve_approval_id(self, raw: str) -> str | None:
        """Resolve a full approval id or a unique prefix.

        Args:
            raw: User-supplied id or prefix.

        Returns:
            The matching approval id, or ``None``.
        """
        candidate = (raw or "").strip()
        if not candidate or self._store is None:
            return None
        approvals = await self._store.list_approvals(state="pending", limit=200)
        for approval in approvals:
            if approval["approval_id"] == candidate:
                return candidate
        matches = [
            approval["approval_id"]
            for approval in approvals
            if approval["approval_id"].startswith(candidate)
        ]
        return matches[0] if len(matches) == 1 else None

    def _is_admin(self, event: AstrMessageEvent) -> bool:
        """Whether the sender may use administrative commands.

        Uses AstrBot's own permission model; the bridge never fabricates a role.

        Args:
            event: Incoming message event.

        Returns:
            ``True`` when the sender is an AstrBot administrator.
        """
        if getattr(event, "role", None) == "admin":
            return True
        try:
            admins = self.context.get_config().get("admins_id", [])
            return str(event.get_sender_id()) in [str(item) for item in admins]
        except Exception:
            logger.exception("bridge admin check failed")
            return False

    # -- LLM tools ---------------------------------------------------------------------

    def _register_llm_tools(self) -> None:
        """Register the ``dsh_*`` tools for the LLM (§6.11).

        Registration failures are logged, never raised: a broken tool must not stop the
        plugin from loading.
        """
        if self._llm_tools_registered:
            return
        try:
            self.context.add_llm_tools(
                DshSubmitTaskTool(self),
                DshTaskStatusTool(self),
                DshListSessionsTool(self),
                DshCreateSessionTool(self),
                DshSelectSessionTool(self),
            )
            self._llm_tools_registered = True
            logger.info("bridge registered 5 llm tools")
        except Exception:
            logger.exception("bridge llm tool registration failed")

    async def llm_submit_task(
        self,
        event: AstrMessageEvent,
        prompt: str,
        purpose: str = "",
        origin: str = ORIGIN_LLM,
        session_id: str | None = None,
    ) -> str:
        """Open a human gate for one cross-end submission and return its handle.

        Agent-initiated submissions are sensitive (§16.4): nothing is sent to the
        peer until a human on this endpoint answers, and the eventual submission
        carries an ``approval_ref`` the receiver can verify against this side's
        authority (§12.5/§12.7).

        Args:
            event: Incoming message event (supplies the wake UMO).
            prompt: Task description.
            purpose: Optional purpose label.
            origin: ``llm`` for tool-initiated tasks.
            session_id: Target peer session, when the caller already selected one.

        Returns:
            Human-readable submission or pending-approval result.
        """
        if self._tasks is None or self._session is None:
            return "桥接尚未就绪，无法提交任务。"
        if self._session.state is not SessionState.READY:
            return "桥接当前未连接，任务未提交（请先检查 /dsh status）。"
        if not isinstance(session_id, str) or not session_id:
            # Never guess the first authorized session: an absent target must fail
            # closed here, before any gate can be bypassed by a grant-less submission.
            return (
                "未指定已授权的目标会话，任务未提交（不会自动选择会话；"
                "请先列出授权会话并显式传入 session_id）。"
            )
        try:
            held = await self._tasks.prepare_outbound_approval(
                input_parts=[{"type": "text", "text": prompt[:65536]}],
                purpose=(purpose or "")[:64] or None,
                origin=origin,
                session_id=session_id,
                timeout_s=1800,
                meta_umo=event.unified_msg_origin,
            )
        except BridgeError as exc:
            return f"任务提交失败：{exc.code}（未自动重试，如需继续请人工确认）。"
        return (
            f"任务已暂存，等待真人批准：task_id={held['task_id']}，"
            f"审批号={held['approval_id']}。批准后才会提交到对端；"
            "请在 AstrBot 侧由管理员执行 /dsh approve <审批号>（或拒绝 /dsh reject）。"
        )

    async def llm_task_status(self, event: AstrMessageEvent, task_id: str) -> str:
        """Return the status of a task by id.

        Args:
            event: Incoming message event.
            task_id: Task identifier.

        Returns:
            Human-readable status text.
        """
        if self._tasks is None:
            return "桥接尚未就绪。"
        try:
            payload = await self._tasks.status({"task_id": task_id})
        except BridgeError as exc:
            return f"查询失败：{exc.code}"
        direction = (
            "本端发起" if payload["direction"] == DIRECTION_OUTBOUND else "对端发起"
        )
        return (
            f"任务 {payload['task_id']} 状态={payload['status']} 方向={direction} "
            f"尝试={payload['attempts']} 需人工={payload['needs_human']}"
        )

    async def llm_list_sessions(
        self, event: AstrMessageEvent, purpose: str = ""
    ) -> str:
        """List authorized sessions within scope.

        Args:
            event: Incoming message event.
            purpose: Optional purpose filter.

        Returns:
            Human-readable list.
        """
        if self._sessions_svc is None:
            return "桥接尚未就绪。"
        payload = await self._sessions_svc.list_sessions(
            {"purpose": purpose or None, "state": "any", "limit": 20}
        )
        if not payload["sessions"]:
            return "授权范围内暂无可用会话。"
        lines = ["授权范围内的会话："]
        for item in payload["sessions"]:
            lines.append(
                f"{item['session_id'][:8]} 用途={item['purpose'] or '-'} "
                f"状态={item['state']}"
            )
        return "\n".join(lines)

    async def llm_create_session(
        self, event: AstrMessageEvent, purpose: str, title: str = ""
    ) -> str:
        """Create a session inside the granted quota (auto-authorized).

        Args:
            event: Incoming message event.
            purpose: Purpose label.
            title: Human title.

        Returns:
            Human-readable result.
        """
        if self._sessions_svc is None:
            return "桥接尚未就绪。"
        try:
            result = await self._sessions_svc.create_session(
                {"request_id": str(uuid.uuid4()), "purpose": purpose, "title": title}
            )
        except BridgeError as exc:
            return f"创建会话失败：{exc.code}"
        return f"会话已创建并授权：{result['session_id']}（用途：{purpose}）"

    async def llm_select_session(
        self, event: AstrMessageEvent, task_id: str, session_id: str
    ) -> str:
        """Select an authorized session for a task.

        Args:
            event: Incoming message event.
            task_id: Task identifier.
            session_id: Session identifier.

        Returns:
            Human-readable result.
        """
        if self._sessions_svc is None:
            return "桥接尚未就绪。"
        try:
            await self._sessions_svc.select_session(
                {"task_id": task_id, "session_id": session_id}
            )
        except BridgeError as exc:
            return f"切换会话失败：{exc.code}"
        return f"已将会话 {session_id} 绑定到任务 {task_id}。"

    # -- dashboard APIs ----------------------------------------------------------------

    def _register_web_apis(self) -> None:
        """Register the status-page endpoints (read-only GET + approval POST)."""
        base = f"/{PLUGIN_NAME}"
        routes = (
            (f"{base}/status", self._api_status, ["GET"], "Bridge connection status"),
            (f"{base}/tasks", self._api_tasks, ["GET"], "Bridge task list"),
            (f"{base}/sessions", self._api_sessions, ["GET"], "Bridge session grants"),
            (f"{base}/approvals", self._api_approvals, ["GET"], "Bridge approvals"),
            (
                f"{base}/approvals/<approval_id>/decide",
                self._api_decide,
                ["POST"],
                "Decide an approval",
            ),
            (
                f"{base}/tasks/<task_id>/resolve",
                self._api_resolve_task,
                ["POST"],
                "Resolve a task",
            ),
            (
                f"{base}/sessions/<session_id>/revoke",
                self._api_revoke_session,
                ["POST"],
                "Revoke a session grant",
            ),
        )
        for route, handler, methods, desc in routes:
            with contextlib.suppress(Exception):
                self.context.register_web_api(route, handler, methods, desc)

    def _api_actor(self) -> str:
        """Return the acting Dashboard identity for audits.

        Returns:
            ``dashboard:<username>`` when known, otherwise ``dashboard:unknown``.
        """
        username = getattr(request, "username", None)
        return f"dashboard:{username}" if username else "dashboard:unknown"

    def _api_authorised(self) -> bool:
        """Whether the caller may perform write operations.

        A Dashboard login is the only accepted credential for approval writes. API keys
        with the ``plugin`` scope are rejected because that scope grants no approval
        rights; otherwise any plugin-scoped key could approve on a human's behalf.

        Returns:
            ``True`` when the caller is an authenticated Dashboard user.
        """
        username = getattr(request, "username", None)
        if not username:
            return False
        return not str(username).startswith("api_key:")

    async def _api_status(self):
        """``GET status``: connection, transport history and diagnostics.

        Returns:
            JSON response with no secret material.
        """
        diagnostics = self._manager.diagnostics() if self._manager else {}
        session = self._session
        conn = self._primary() or {}
        peer = session.peer_caps or {} if session else {}
        return json_response(
            {
                # Single source of truth: the same check that gates approval writes.
                "can_write": self._api_authorised(),
                "connection": {
                    "state": self._connection_state,
                    "reason": self._connection_reason,
                    "conn_id": conn.get("conn_id", ""),
                    "mode": conn.get("mode", ""),
                    "transport": diagnostics.get("current", ""),
                    "sid": session.sid if session else None,
                    "peer_host": peer.get("host"),
                    "peer_version": peer.get("version"),
                    "psk_configured": bool(conn.get("psk_secret")),
                    "openapi_configured": bool(
                        self._openapi and self._openapi.configured()
                    ),
                },
                "transport_history": self._manager.history() if self._manager else [],
                "diagnostics": {
                    "preferred": diagnostics.get("preferred", ""),
                    "fallbacks": diagnostics.get("fallbacks", []),
                    "last_error": diagnostics.get("last_error", ""),
                    "degraded": diagnostics.get("degraded", False),
                    "reachable": diagnostics.get("reachable", False),
                },
            }
        )

    async def _api_tasks(self):
        """``GET tasks``: paginated task list with direction and status.

        Returns:
            JSON response.
        """
        if self._store is None:
            return error_response("bridge not initialised", status_code=503)
        limit = request.query.get("limit", 20, type=int) or 20
        cursor = request.query.get("cursor")
        items, next_cursor = await self._store.list_tasks(limit=limit, cursor=cursor)
        return json_response(
            {
                "items": [
                    {
                        "task_id": task["task_id"],
                        "root_task_id": task["root_task_id"],
                        "direction": task["direction"],
                        "status": task["status"],
                        "purpose": task["purpose"],
                        "attempts": task["attempts"],
                        "needs_human": task["needs_human"],
                        "created_at": utc_iso_ms_from(task["created_at"]),
                        "updated_at": utc_iso_ms_from(task["updated_at"]),
                        "result": task["result"],
                        "error": task["error"],
                    }
                    for task in items
                ],
                "next_cursor": next_cursor,
            }
        )

    async def _api_sessions(self):
        """``GET sessions``: grants, quota and authorization version.

        Returns:
            JSON response.
        """
        if self._sessions_svc is None:
            return error_response("bridge not initialised", status_code=503)
        grants = await self._sessions_svc.admin_grants()
        quota = await self._sessions_svc.admin_quota()
        return json_response(
            {"items": grants, "quota": quota, "authz_version": quota["authz_version"]}
        )

    async def _api_approvals(self):
        """``GET approvals``: pending approvals plus pending decisions.

        Returns:
            JSON response.
        """
        if self._store is None:
            return error_response("bridge not initialised", status_code=503)
        await self._flush_native_sweeps()
        approvals = await self._store.list_approvals(state="pending", limit=50)
        decisions = await self._store.list_decisions(state="pending", limit=50)
        return json_response(
            {
                "items": [
                    {
                        "approval_id": item["approval_id"],
                        "approval_type": item["approval_type"],
                        "task_id": item["task_id"],
                        "tool": item["tool"],
                        "reason": item["reason"],
                        "display_reason": item["display_reason"],
                        "origin_side": item["origin_side"],
                        "expires_at": utc_iso_ms_from(item["expires_at"]),
                    }
                    for item in approvals
                ],
                "decisions": [
                    {
                        "decision_id": item["decision_id"],
                        "task_id": item["task_id"],
                        "question": item["question"],
                        "options": item["options"],
                        "expires_at": utc_iso_ms_from(item["expires_at"]),
                    }
                    for item in decisions
                ],
            }
        )

    async def _api_decide(self, approval_id: str):
        """``POST approvals/<id>/decide``: human decision from the Dashboard.

        Args:
            approval_id: Approval identifier.

        Returns:
            JSON response.
        """
        if not self._api_authorised():
            return error_response("dashboard login required", status_code=403)
        if self._approvals is None:
            return error_response("bridge not initialised", status_code=503)
        await self._flush_native_sweeps()
        payload = await request.json(default={})
        outcome = str(payload.get("outcome", ""))
        if outcome not in ("allowed-once", "rejected"):
            return error_response(
                "outcome must be allowed-once or rejected", status_code=400
            )
        applied, failure = await self._approvals.human_decide(
            approval_id,
            allowed=outcome in APPROVAL_ALLOWING_OUTCOMES,
            actor=self._api_actor(),
            channel="web",
            reason=payload.get("reason") or None,
        )
        if not applied:
            return json_response(
                {"applied": False, "reason": failure, "approval_id": approval_id}
            )
        return json_response({"applied": True, "approval_id": approval_id})

    async def _api_resolve_task(self, task_id: str):
        """``POST tasks/<id>/resolve``: human retry/abandon for ``needs_human`` tasks.

        A retry always produces a NEW task id; the old task is never replayed (§16.1).

        Args:
            task_id: Task identifier.

        Returns:
            JSON response.
        """
        if not self._api_authorised():
            return error_response("dashboard login required", status_code=403)
        if self._store is None or self._tasks is None:
            return error_response("bridge not initialised", status_code=503)
        payload = await request.json(default={})
        action = str(payload.get("action", ""))
        task = await self._store.get_task(task_id)
        if task is None:
            return error_response("unknown task", status_code=404)
        if action == "cancel":
            result = await self._tasks.cancel(
                {"task_id": task_id, "reason": "human_abandon"}
            )
            return json_response({"task_id": task_id, "status": result["status"]})
        if action == "retry":
            if (
                task["status"] not in TERMINAL_STATUSES
                and task["status"] != STATUS_NEEDS_HUMAN
            ):
                return error_response(
                    "only terminal or needs_human tasks can be retried", status_code=400
                )
            new_id = str(uuid.uuid4())
            retried = dict(task["payload"] or {})
            retried["task_id"] = new_id
            retried["root_task_id"] = task["root_task_id"]
            retried["meta"] = {"retry_of": task_id}
            stored = await self._store.upsert_task(
                {
                    "task_id": new_id,
                    "root_task_id": task["root_task_id"],
                    "direction": task["direction"],
                    "kind": task["kind"],
                    "origin": ORIGIN_HUMAN,
                    "status": STATUS_ACCEPTED,
                    "payload": retried,
                    "purpose": task["purpose"],
                }
            )
            return json_response(
                {"task_id": new_id, "retry_of": task_id, "status": stored["status"]}
            )
        return error_response("action must be retry or cancel", status_code=400)

    async def _api_revoke_session(self, session_id: str):
        """``POST sessions/<id>/revoke``: revoke one session grant.

        Args:
            session_id: Session identifier.

        Returns:
            JSON response.
        """
        if not self._api_authorised():
            return error_response("dashboard login required", status_code=403)
        if self._sessions_svc is None:
            return error_response("bridge not initialised", status_code=503)
        version = await self._sessions_svc.admin_revoke(session_id)
        return json_response({"session_id": session_id, "authz_version": version})


class _DshLlmTool(FunctionTool):
    """Base adapter for the five ``dsh_*`` LLM tools.

    A plugin tool must be a concrete ``FunctionTool``: the host's permission wrapper
    reads its ``handler`` and the plugin loader rebinds it by module path. The handler
    stays bound to this tool instance, which owns the plugin, so the class stays in
    ``main.py`` and host ownership is resolved from that module.
    """

    def __init__(self, plugin: DshBridgePlugin) -> None:
        """Bind the tool to the plugin.

        Args:
            plugin: Owning plugin instance.
        """
        # Pydantic's dataclass init resets instance state, so bind ``_plugin`` after it.
        super().__init__(
            name=type(self).name,
            description=type(self).description,
            parameters=type(self).parameters,
            handler=self.__call__,
        )
        self._plugin = plugin


class DshSubmitTaskTool(_DshLlmTool):
    """LLM tool ``dsh_submit_task``: submit a cross-end task and return a handle."""

    name = "dsh_submit_task"
    description = (
        "Submit a task to the DSH peer and return immediately with a task_id. "
        "Use this when work should run on the DSH side. The result arrives later as a "
        "notification; never wait for it inside one tool call."
    )
    parameters = {
        "type": "object",
        "properties": {
            "prompt": {"type": "string", "description": "Task description."},
            "purpose": {"type": "string", "description": "Optional purpose label."},
            "session_id": {
                "type": "string",
                "description": (
                    "Explicitly selected authorized session id. Never selected "
                    "automatically; an omitted value is refused."
                ),
            },
        },
        "required": ["prompt"],
    }

    async def __call__(
        self,
        event: AstrMessageEvent,
        prompt: str,
        purpose: str = "",
        session_id: str | None = None,
    ) -> str:
        """Execute the tool.

        Args:
            event: Incoming message event.
            prompt: Task description.
            purpose: Optional purpose label.
            session_id: Explicit authorized session id; forwarded unchanged.

        Returns:
            Human-readable result including the task id.
        """
        return await self._plugin.llm_submit_task(
            event, prompt, purpose, session_id=session_id
        )


class DshTaskStatusTool(_DshLlmTool):
    """LLM tool ``dsh_task_status``: idempotent status query."""

    name = "dsh_task_status"
    description = (
        "Query the status of a cross-end task by task_id. Read-only and idempotent."
    )
    parameters = {
        "type": "object",
        "properties": {
            "task_id": {"type": "string", "description": "Task identifier."}
        },
        "required": ["task_id"],
    }

    async def __call__(self, event: AstrMessageEvent, task_id: str) -> str:
        """Execute the tool.

        Args:
            event: Incoming message event.
            task_id: Task identifier.

        Returns:
            Human-readable status text.
        """
        return await self._plugin.llm_task_status(event, task_id)


class DshListSessionsTool(_DshLlmTool):
    """LLM tool ``dsh_list_sessions``: list authorized sessions."""

    name = "dsh_list_sessions"
    description = (
        "List the sessions authorized for agent use, with their purpose. Only "
        "authorized sessions are visible."
    )
    parameters = {
        "type": "object",
        "properties": {
            "purpose": {"type": "string", "description": "Optional purpose filter."}
        },
        "required": [],
    }

    async def __call__(self, event: AstrMessageEvent, purpose: str = "") -> str:
        """Execute the tool.

        Args:
            event: Incoming message event.
            purpose: Optional purpose filter.

        Returns:
            Human-readable list.
        """
        return await self._plugin.llm_list_sessions(event, purpose)


class DshCreateSessionTool(_DshLlmTool):
    """LLM tool ``dsh_create_session``: create a session inside the granted quota."""

    name = "dsh_create_session"
    description = (
        "Create a new session for a purpose. Inside the administrator-granted quota the "
        "new session is authorized automatically; above the quota creation is refused."
    )
    parameters = {
        "type": "object",
        "properties": {
            "purpose": {
                "type": "string",
                "description": "Purpose label, e.g. code-review.",
            },
            "title": {
                "type": "string",
                "description": "Optional human-readable title.",
            },
        },
        "required": ["purpose"],
    }

    async def __call__(
        self, event: AstrMessageEvent, purpose: str, title: str = ""
    ) -> str:
        """Execute the tool.

        Args:
            event: Incoming message event.
            purpose: Purpose label.
            title: Optional title.

        Returns:
            Human-readable result.
        """
        return await self._plugin.llm_create_session(event, purpose, title)


class DshSelectSessionTool(_DshLlmTool):
    """LLM tool ``dsh_select_session``: bind a task to an authorized session."""

    name = "dsh_select_session"
    description = (
        "Select an authorized session for a task. Unauthorized sessions are refused."
    )
    parameters = {
        "type": "object",
        "properties": {
            "task_id": {"type": "string", "description": "Task identifier."},
            "session_id": {"type": "string", "description": "Session identifier."},
        },
        "required": ["task_id", "session_id"],
    }

    async def __call__(
        self, event: AstrMessageEvent, task_id: str, session_id: str
    ) -> str:
        """Execute the tool.

        Args:
            event: Incoming message event.
            task_id: Task identifier.
            session_id: Session identifier.

        Returns:
            Human-readable result.
        """
        return await self._plugin.llm_select_session(event, task_id, session_id)


__all__ = [
    "DshBridgePlugin",
    "DshCreateSessionTool",
    "DshListSessionsTool",
    "DshSelectSessionTool",
    "DshSubmitTaskTool",
    "DshTaskStatusTool",
    "KIND_DSH_AGENT_RUN",
    "STATUS_ACCEPTED",
]
