"""WebSocket carrier: independent aiohttp server (listen) or client (connect) (§7.2).

The listener is a **dedicated** aiohttp application on its own port. AstrBot's
plugin ``register_web_api`` routes cannot host a WebSocket upgrade, so the bridge
must not try to reuse them (§6.1.4).

Frames are JSON text frames, one envelope each, negotiated under the
``dsh-bridge.v1`` subprotocol. No ``Authorization`` header is ever added.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from astrbot.api import logger

from ..constants import (
    DEFAULT_LISTEN_PORT,
    HEADER_VERSION,
    WS_SUBPROTOCOL,
)
from ..errors import (
    ERR_CONFIG_INVALID,
    ERR_FRAME_TOO_LARGE,
    ERR_SUBPROTOCOL_MISMATCH,
    ERR_TIMEOUT,
    BridgeError,
)
from .base import Transport, TransportHooks, peer_base_url


class WsTransport(Transport):
    """aiohttp-based WebSocket carrier for both roles."""

    name = "ws"

    def __init__(
        self,
        *,
        role: str,
        conn: str,
        max_frame_bytes: int = 2_097_152,
        handshake_timeout_s: float = 10.0,
        tls_cert_path: str = "",
        tls_key_path: str = "",
        tls_fingerprint: str = "",
    ) -> None:
        """Create the carrier.

        Args:
            role: ``"listen"`` or ``"connect"``.
            conn: Connection identifier (for logs).
            max_frame_bytes: Maximum accepted frame size (§5.1).
            handshake_timeout_s: How long ``send_plain`` waits for ``hello_ack``.
            tls_cert_path: Server certificate for ``wss``.
            tls_key_path: Server private key for ``wss``.
            tls_fingerprint: Expected peer certificate fingerprint (explicit pinning).
        """
        self._role = role
        self._conn = conn
        self._max_frame_bytes = max_frame_bytes
        self._handshake_timeout = handshake_timeout_s
        self._cert = tls_cert_path
        self._key = tls_key_path
        self._fingerprint = tls_fingerprint

        self._hooks: TransportHooks | None = None
        self._cfg: Any = None
        self._session: Any = None
        self._runner: Any = None
        self._ws: Any = None
        self._plain_reply: asyncio.Future | None = None
        self._client: Any = None
        self._listen_task: asyncio.Task | None = None
        self._started = asyncio.Event()
        self._alive = False
        self._closed = asyncio.Event()

    async def start(self, cfg: Any, hooks: TransportHooks) -> None:
        """Start the listener or connect as a client.

        Args:
            cfg: Session configuration (``host``/``port``/``path``/``tls_enabled``).
            hooks: Inbound callbacks.
        """
        from aiohttp import web

        self._cfg = cfg
        self._hooks = hooks
        self._started.set()
        if self._role == "listen":
            app = web.Application()
            app.router.add_get(cfg.path or "/dsh-bridge", self._handle_ws)
            app.router.add_get(
                f"{cfg.path or '/dsh-bridge'}/health", self._handle_health
            )
            self._runner = web.AppRunner(app, access_log=None)
            await self._runner.setup()
            ssl_context = self._server_ssl()
            bind_host = (
                getattr(cfg, "listen_host", None)
                or getattr(cfg, "host", "127.0.0.1")
                or "127.0.0.1"
            )
            bind_port = int(
                getattr(cfg, "listen_port", None)
                or getattr(cfg, "port", DEFAULT_LISTEN_PORT)
            )
            site = web.TCPSite(
                self._runner, bind_host, bind_port, ssl_context=ssl_context
            )
            await site.start()
            self._alive = True
            logger.info(
                "bridge ws listening conn=%s on %s:%s%s tls=%s",
                self._conn,
                bind_host,
                bind_port,
                cfg.path,
                ssl_context is not None,
            )
            return
        self._listen_task = asyncio.create_task(self._connect_loop())

    def _server_ssl(self) -> Any:
        """Build an SSL context for the listener when TLS is configured.

        Returns:
            An ``ssl.SSLContext``, or ``None`` for plaintext.
        """
        if not self._cert or not self._key:
            return None
        import ssl

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self._cert, self._key)
        return context

    async def _handle_health(self, request: Any) -> Any:
        """Health endpoint: ``{"v":1,"ok":true}`` with no configuration leak (§7.0).

        Args:
            request: aiohttp request.

        Returns:
            JSON response.
        """
        from aiohttp import web

        return web.json_response(
            {"v": 1, "ok": True},
            headers={HEADER_VERSION: "1", "Cache-Control": "no-store"},
        )

    async def _handle_ws(self, request: Any) -> Any:
        """Accept one WebSocket upgrade and pump frames.

        Args:
            request: aiohttp request.

        Returns:
            WebSocket response or an error response.
        """
        from aiohttp import web

        offered = request.headers.get("Sec-WebSocket-Protocol", "")
        if WS_SUBPROTOCOL not in [item.strip() for item in offered.split(",")]:
            logger.warning(
                "bridge ws rejected upgrade conn=%s reason=subprotocol", self._conn
            )
            raise web.HTTPBadRequest(
                text='{"v":1,"error":{"code":"subprotocol_mismatch","message":"subprotocol unsupported","retryable":false}}'
            )
        ws = web.WebSocketResponse(
            protocols=[WS_SUBPROTOCOL], max_msg_size=self._max_frame_bytes
        )
        await ws.prepare(request)
        self._ws = ws
        self._alive = True
        self._closed.clear()
        self._hooks.on_state("ready", "ws_connected")
        try:
            async for message in ws:
                if message.type.name != "TEXT":
                    continue
                await self._on_text(message.data)
        finally:
            self._alive = False
            self._ws = None
            self._hooks.on_state("disconnected", "ws_closed")
        return ws

    async def _connect_loop(self) -> None:
        """Reconnect to the peer forever with exponential backoff (§6.3)."""
        import aiohttp

        delay = 1.0
        while not self._closed.is_set():
            url = peer_base_url(self._cfg, scheme="wss" if self._cert else "ws")
            try:
                timeout = aiohttp.ClientTimeout(total=None)
                ssl_context = None
                if self._cfg.tls_enabled:
                    ssl_context = self._client_ssl()
                self._client = aiohttp.ClientSession(timeout=timeout)
                async with self._client.ws_connect(
                    url,
                    protocols=[WS_SUBPROTOCOL],
                    ssl=ssl_context,
                    max_msg_size=self._max_frame_bytes,
                    heartbeat=None,
                ) as ws:
                    negotiated = getattr(ws, "protocol", None) or getattr(
                        ws, "ws_protocol", None
                    )
                    if negotiated is None:
                        raise BridgeError(
                            ERR_SUBPROTOCOL_MISMATCH,
                            details={"reason": "no_subprotocol"},
                        )
                    if negotiated != WS_SUBPROTOCOL:
                        raise BridgeError(ERR_SUBPROTOCOL_MISMATCH)
                    self._verify_peer_fingerprint(ws)
                    self._ws = ws
                    self._alive = True
                    delay = 1.0
                    self._hooks.on_state("ready", "ws_connected")
                    async for message in ws:
                        if message.type.name == "TEXT":
                            await self._on_text(message.data)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._alive = False
                logger.warning(
                    "bridge ws connect failed conn=%s error=%s", self._conn, exc
                )
                self._hooks.on_state("disconnected", "ws_connect_failed")
            finally:
                self._alive = False
                self._ws = None
                if self._client is not None:
                    with contextlib.suppress(Exception):
                        await self._client.close()
                    self._client = None
            if self._closed.is_set():
                return
            await asyncio.sleep(delay)
            delay = min(
                delay * 2, float(getattr(self._cfg, "reconnect_max_backoff", 60))
            )

    def _client_ssl(self) -> Any:
        """Build the client SSL context for a ``wss`` connection.

        Verification is never silently skipped: certificate validation stays on, and
        an optional fingerprint pin is checked separately in
        :meth:`_verify_peer_fingerprint` after the upgrade.

        Returns:
            An ``ssl.SSLContext``.
        """
        import ssl

        return ssl.create_default_context()

    def _verify_peer_fingerprint(self, ws: Any) -> None:
        """Compare the peer certificate against the configured fingerprint (§14).

        Args:
            ws: Connected aiohttp WebSocket response.

        Raises:
            BridgeError: ``config_invalid`` when the certificate does not match, so a
                silent trust downgrade cannot happen.
        """
        if not self._fingerprint:
            return
        expected = self._fingerprint.replace(":", "").replace(" ", "").lower()
        ssl_object = None
        with contextlib.suppress(Exception):
            transport = ws._response.connection.transport  # noqa: SLF001
            ssl_object = transport.get_extra_info("ssl_object")
        if ssl_object is None:
            raise BridgeError(
                ERR_CONFIG_INVALID, details={"reason": "tls_fingerprint_without_tls"}
            )
        der = ssl_object.getpeercert(binary_form=True) or b""
        import hashlib

        actual = hashlib.sha256(der).hexdigest()
        if actual != expected:
            logger.error(
                "bridge ws certificate fingerprint mismatch conn=%s", self._conn
            )
            raise BridgeError(ERR_CONFIG_INVALID, details={"reason": "tls_fingerprint"})

    async def _on_text(self, text: str) -> None:
        """Handle one inbound text frame.

        Args:
            text: Frame payload (one JSON object).
        """
        import json

        from ..errors import ERR_BAD_FRAME

        if self._hooks is None:
            return
        self._hooks.activity()
        if len(text.encode("utf-8")) > self._max_frame_bytes:
            logger.warning("bridge ws frame too large conn=%s", self._conn)
            await self._close_with(ERR_FRAME_TOO_LARGE)
            return
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            logger.warning("bridge ws bad json conn=%s", self._conn)
            await self._close_with(ERR_BAD_FRAME)
            return
        if not isinstance(payload, dict):
            await self._close_with(ERR_BAD_FRAME)
            return
        if payload.get("type") in ("hello", "hello_ack"):
            # The session layer is the single handshake authority: it consumes the
            # object and returns the reply that must go back on the wire.
            # An inbound ``hello_ack`` additionally satisfies the pending
            # ``send_plain`` wait so the initiator can continue.
            pending = self._plain_reply
            reply = await self._hooks.on_plain(payload)
            if reply is not None:
                await self._raw_send(reply)
            if (
                payload.get("type") == "hello_ack"
                and pending is not None
                and not pending.done()
            ):
                pending.set_result(payload)
            return
        try:
            await self._hooks.on_envelope(payload)
        except BridgeError as exc:
            logger.warning(
                "bridge ws envelope rejected conn=%s code=%s", self._conn, exc.code
            )
            if exc.fatal:
                await self._close_with(exc.code)
        except Exception:
            logger.exception("bridge ws envelope handler crashed conn=%s", self._conn)

    async def _close_with(self, code: str) -> None:
        """Close the socket after a protocol violation.

        Args:
            code: §15 error code used only for the log line.
        """
        ws = self._ws
        if ws is None:
            return
        with contextlib.suppress(Exception):
            await ws.close(code=1002, message=code.encode("ascii", "ignore")[:120])

    async def _raw_send(self, obj: dict) -> None:
        """Send one JSON object over the socket.

        Args:
            obj: Envelope or plaintext handshake object.

        Raises:
            BridgeError: ``timeout`` when no socket is available.
        """
        import json

        ws = self._ws
        if ws is None or ws.closed:
            raise BridgeError(ERR_TIMEOUT, details={"reason": "ws_not_connected"})
        await ws.send_str(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))

    async def send_envelope(self, env: dict) -> None:
        """Send a sealed envelope as one text frame (§7.2 rule 3).

        Args:
            env: Envelope object.
        """
        await self._raw_send(env)

    async def send_plain(self, obj: dict) -> dict | None:
        """Send ``hello`` and wait for ``hello_ack`` on a client connection.

        Args:
            obj: ``hello`` object.

        Returns:
            The peer's ``hello_ack``.

        Raises:
            BridgeError: ``timeout`` when the peer never answers.
        """
        if self._role == "listen":
            # A responder never sends ``hello``; the frame is delivered by the peer.
            await self._raw_send(obj)
            return None
        deadline = asyncio.get_running_loop().time() + self._handshake_timeout
        while self._ws is None or self._ws.closed:
            if asyncio.get_running_loop().time() > deadline:
                raise BridgeError(ERR_TIMEOUT, details={"reason": "ws_connect"})
            await asyncio.sleep(0.02)
        self._plain_reply = asyncio.get_running_loop().create_future()
        await self._raw_send(obj)
        try:
            return await asyncio.wait_for(
                self._plain_reply, timeout=self._handshake_timeout
            )
        except TimeoutError as exc:
            raise BridgeError(ERR_TIMEOUT, details={"reason": "hello_ack"}) from exc
        finally:
            self._plain_reply = None

    def alive(self) -> bool:
        """Whether the socket is currently open."""
        return bool(self._alive and self._ws is not None and not self._ws.closed)

    async def wait_ready(self, timeout_s: float) -> None:
        """Wait until a socket is established.

        Args:
            timeout_s: Maximum wait.

        Raises:
            TimeoutError: When no socket appears in time.
        """
        deadline = asyncio.get_running_loop().time() + timeout_s
        while not self.alive():
            if asyncio.get_running_loop().time() > deadline:
                raise TimeoutError("ws not ready")
            await asyncio.sleep(0.02)

    async def stop(self) -> None:
        """Close the socket, the client session and the listener."""
        self._closed.set()
        if self._listen_task is not None:
            self._listen_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._listen_task
            self._listen_task = None
        ws = self._ws
        self._ws = None
        if ws is not None:
            with contextlib.suppress(Exception):
                await ws.close()
        if self._client is not None:
            with contextlib.suppress(Exception):
                await self._client.close()
            self._client = None
        if self._runner is not None:
            with contextlib.suppress(Exception):
                await self._runner.cleanup()
            self._runner = None
        self._alive = False

    def diagnostics(self) -> dict:
        """Return carrier state for the status page."""
        return {
            "name": self.name,
            "role": self._role,
            "alive": self.alive(),
            "subprotocol": WS_SUBPROTOCOL,
        }


__all__ = ["WsTransport"]
