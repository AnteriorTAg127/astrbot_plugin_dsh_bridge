"""HTTP Webhook carrier: POST /hello, POST /frames, POST /probe, plus reverse probe.

Webhook requires **bidirectional** reachability (§7.3). The receiving side must be
able to post back to the sender. Liveness is decided by periodic ``probe``
round-trips; after ``WEBHOOK_PROBE_FAIL`` consecutive failures the transport reports
``transport_degraded`` so the manager can fall back to long-poll (§7.3 rule 6).

No ``Authorization``/``Cookie`` header is ever sent, and any such header on an
inbound request is rejected with ``auth_header_forbidden`` (§7.0).
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import time
import uuid
from typing import Any

from astrbot.api import logger

from ..constants import (
    CONTENT_TYPE_JSON,
    FRAME_AUTH,
    FRAMES_PATH,
    HEADER_VERSION,
    HEALTH_PATH,
    HELLO_PATH,
    MAX_BATCH_BYTES,
    MAX_BATCH_FRAMES,
    PROBE_PATH,
    WEBHOOK_PROBE_FAIL,
)
from ..crypto import b64u, handshake_key, mac_object, psk_master, verify_mac
from ..errors import (
    ERR_AUTH_HEADER_FORBIDDEN,
    ERR_FRAME_TOO_LARGE,
    ERR_UNSUPPORTED_CONTENT_TYPE,
    BridgeError,
)
from .base import (
    Transport,
    TransportHooks,
    bind_target,
    parse_frames_batch,
    peer_base_url,
)


def _batch_error_status(code: str) -> int:
    """Map a batch-validation error to its §8.1 status code.

    Args:
        code: §15 error code raised while validating the batch.

    Returns:
        HTTP status for the error body.
    """
    return 413 if code == ERR_FRAME_TOO_LARGE else 400


def _error_response(code: str, status: int = 400) -> Any:
    """Build a plaintext HTTP error response (§8.2).

    Args:
        code: §15 error code.
        status: HTTP status.

    Returns:
        aiohttp JSON response.
    """
    from aiohttp import web

    from ..errors import http_error_body

    body = http_error_body(code)
    headers = {HEADER_VERSION: "1", "Cache-Control": "no-store"}
    if status in (429, 503):
        headers["Retry-After"] = "60"
    return web.json_response(body, status=status, headers=headers)


class WebhookTransport(Transport):
    """Webhook carrier with an inbound aiohttp server and an outbound client."""

    name = "webhook"

    def __init__(
        self,
        *,
        role: str,
        conn: str,
        side: str,
        psk_id: str = "",
        psk_secret: str = "",
        max_batch_bytes: int = MAX_BATCH_BYTES,
        heartbeat_s: int = 30,
    ) -> None:
        """Create the carrier.

        Args:
            role: ``"listen"`` or ``"connect"``.
            conn: Connection identifier.
            side: Local protocol side (also stored in a MAC-bound field).
            psk_id: PSK id used for probe MACs.
            psk_secret: PSK secret used for probe MACs.
            max_batch_bytes: Maximum accepted batch body size.
            heartbeat_s: Probe interval in seconds.
        """
        self._role = role
        self._conn = conn
        self._side = side
        self._psk_id = psk_id
        self._psk_secret = psk_secret
        self._max_batch_bytes = max_batch_bytes
        self._heartbeat_s = heartbeat_s

        self._cfg: Any = None
        self._hooks: TransportHooks | None = None
        self._runner: Any = None
        self._client: Any = None
        self._probe_task: asyncio.Task | None = None
        self._probe_failures = 0
        self._degraded = False
        self._alive = False
        self._outbound_queue: asyncio.Queue = asyncio.Queue()
        self._flusher: asyncio.Task | None = None
        self._sid: str | None = None
        # While an inbound ``POST /frames`` is being served, frames the session
        # produces belong in *that* response (§7.3 rule 2): the initiator is not
        # reachable, so ``auth_ack`` can only travel back inline.
        self._inline: list[dict] | None = None

    # -- lifecycle ---------------------------------------------------------------------

    async def start(self, cfg: Any, hooks: TransportHooks) -> None:
        """Start the inbound server and/or the outbound sender.

        Args:
            cfg: Session configuration.
            hooks: Inbound callbacks.
        """
        self._cfg = cfg
        self._hooks = hooks
        self._alive = True
        # Webhook requires **bidirectional** reachability (§7.3), so both roles run an
        # inbound server: the connect side must be able to receive the peer's push
        # back and the probe.
        await self._start_server(cfg)
        self._flusher = asyncio.create_task(self._flush_loop())
        self._probe_task = asyncio.create_task(self._probe_loop())

    async def _start_server(self, cfg: Any) -> None:
        """Bring up the inbound HTTP server.

        Args:
            cfg: Session configuration providing host/port/path.
        """
        from aiohttp import web

        base = cfg.path or "/dsh-bridge"
        app = web.Application(client_max_size=self._max_batch_bytes)
        app.router.add_post(f"{base}{HELLO_PATH}", self._handle_hello)
        app.router.add_post(f"{base}{FRAMES_PATH}", self._handle_frames)
        app.router.add_post(f"{base}{PROBE_PATH}", self._handle_probe)
        app.router.add_get(f"{base}{HEALTH_PATH}", self._handle_health)
        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        bind_host, bind_port = bind_target(cfg)
        site = web.TCPSite(self._runner, bind_host, bind_port)
        await site.start()
        bound = self._bound_port(site, bind_port)
        logger.info(
            "bridge webhook listening conn=%s on %s:%s%s",
            self._conn,
            bind_host,
            bound,
            base,
        )

    @staticmethod
    def _bound_port(site: Any, requested: int) -> int:
        """Return the port the server actually bound (``0`` means ephemeral).

        Args:
            site: The aiohttp ``TCPSite`` that was started.
            requested: The configured bind port.

        Returns:
            The effective port, or ``requested`` when it cannot be inspected.
        """
        server = getattr(site, "_server", None)
        for sock in getattr(server, "sockets", None) or ():
            try:
                return int(sock.getsockname()[1])
            except Exception:
                continue
        return requested

    async def stop(self) -> None:
        """Stop probes, the flusher, the client session and the server."""
        for task in (self._probe_task, self._flusher):
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
        self._probe_task = None
        self._flusher = None
        if self._client is not None:
            with contextlib.suppress(Exception):
                await self._client.close()
            self._client = None
        if self._runner is not None:
            with contextlib.suppress(Exception):
                await self._runner.cleanup()
            self._runner = None
        self._alive = False

    # -- inbound handlers --------------------------------------------------------------

    def _guard_headers(self, request: Any) -> None:
        """Reject forbidden authentication headers (§7.0).

        Args:
            request: aiohttp request.

        Raises:
            BridgeError: ``auth_header_forbidden`` when a forbidden header is present.
        """
        if request.headers.get("Authorization") or request.headers.get("Cookie"):
            raise BridgeError(ERR_AUTH_HEADER_FORBIDDEN)

    def _guard_content_type(self, request: Any) -> None:
        """Reject exotic content types and any compression (§7.0).

        Args:
            request: aiohttp request.

        Raises:
            BridgeError: ``unsupported_content_type``.
        """
        content_type = request.headers.get("Content-Type", "")
        if "application/json" not in content_type:
            raise BridgeError(ERR_UNSUPPORTED_CONTENT_TYPE)
        if request.headers.get("Content-Encoding"):
            raise BridgeError(ERR_UNSUPPORTED_CONTENT_TYPE)

    async def _handle_hello(self, request: Any) -> Any:
        """Handle ``POST {base}/hello``: return ``hello_ack`` (§7.3 rule 1).

        Args:
            request: aiohttp request.

        Returns:
            JSON response with ``hello_ack`` or an error body.
        """
        from aiohttp import web

        assert self._hooks is not None
        try:
            self._guard_headers(request)
            self._guard_content_type(request)
            body = await request.json()
        except BridgeError as exc:
            return _error_response(
                exc.code, 401 if exc.code == ERR_AUTH_HEADER_FORBIDDEN else 400
            )
        except Exception:
            return _error_response("bad_json", 400)
        if not isinstance(body, dict):
            return _error_response("bad_json", 400)
        self._hooks.activity()
        try:
            reply = await self._hooks.on_plain(body)
        except BridgeError as exc:
            status = 401 if exc.code in ("psk_mismatch", "th_mismatch") else 400
            if exc.code == "hello_replay":
                status = 409
            elif exc.code == "rate_limited":
                status = 429
            elif exc.code == "unknown_conn":
                status = 404
            elif exc.code == "bad_version":
                status = 426
            return _error_response(exc.code, status)
        if not isinstance(reply, dict):
            return _error_response("bad_frame", 400)
        self._sid = reply.get("sid")
        self._alive = True
        return web.json_response(
            reply, headers={HEADER_VERSION: "1", "Cache-Control": "no-store"}
        )

    async def _handle_frames(self, request: Any) -> Any:
        """Handle ``POST {base}/frames``: accept a batch of envelopes (§7.3 rule 2/3/4).

        Frames the session produces while this batch is being handled are captured
        and returned **inline** in the response body: an initiator that POSTs its
        ``auth`` is not listening, so ``auth_ack`` can only travel back on this
        request. Without that, the handshake could never complete in that
        direction.

        Args:
            request: aiohttp request.

        Returns:
            ``200`` with an inline frame batch when the session produced frames
            (the handshake case), otherwise ``202`` with ``accepted``/``rejected``.
            Unchanged §8.1 semantics: all-fatal batches answer 409.
        """
        from aiohttp import web

        assert self._hooks is not None
        try:
            self._guard_headers(request)
            self._guard_content_type(request)
        except BridgeError as exc:
            return _error_response(
                exc.code, 415 if exc.code == ERR_UNSUPPORTED_CONTENT_TYPE else 401
            )
        try:
            raw = await request.read()
        except Exception:
            # aiohttp enforces ``client_max_size`` before the handler sees the body
            # and answers with a plain-text 413; §8.1 requires the JSON error body.
            return _error_response(ERR_FRAME_TOO_LARGE, 413)
        try:
            batch = parse_frames_batch(raw, self._max_batch_bytes)
        except BridgeError as exc:
            return _error_response(exc.code, _batch_error_status(exc.code))
        frames = batch["frames"]

        self._hooks.activity()
        accepted: list[str] = []
        rejected: list[dict] = []
        fatal = False
        inline: list[dict] = []
        # Only the batch that carries ``auth`` gets an inline reply (§7.3 rule 2):
        # that is the one response the initiator is blocked on. Restricting the
        # capture to it keeps every later batch a plain 202/409 acknowledgement.
        carries_auth = any(frame.get("type") == FRAME_AUTH for frame in frames)
        previous = self._inline
        if carries_auth:
            self._inline = inline
        try:
            for frame in frames:
                ref = f"{frame.get('type')}#{frame.get('seq')}"
                try:
                    await self._hooks.on_envelope(frame)
                    accepted.append(ref)
                except BridgeError as exc:
                    rejected.append({"ref": ref, "code": exc.code})
                    fatal = fatal or exc.fatal
                except Exception:
                    logger.exception("bridge webhook frame handler crashed")
                    rejected.append({"ref": ref, "code": "internal_error"})
            if not accepted and rejected and fatal:
                return _error_response(rejected[0]["code"], 409)
        finally:
            self._inline = previous
        if inline:
            return web.json_response(
                {
                    "v": 1,
                    "conn": self._conn,
                    "sid": batch.get("sid") or self._sid,
                    "batch_id": batch.get("batch_id") or str(uuid.uuid4()),
                    "frames": inline,
                },
                status=200,
                headers={HEADER_VERSION: "1", "Cache-Control": "no-store"},
            )
        body = {"v": 1, "accepted": accepted, "rejected": rejected}
        return web.json_response(
            body, status=202, headers={HEADER_VERSION: "1", "Cache-Control": "no-store"}
        )

    async def _handle_probe(self, request: Any) -> Any:
        """Handle ``POST {base}/probe``: verify the MAC and answer ``probe_ack`` (§7.3 rule 5).

        Args:
            request: aiohttp request.

        Returns:
            ``probe_ack`` or an error body.
        """
        from aiohttp import web

        assert self._hooks is not None
        try:
            self._guard_headers(request)
            self._guard_content_type(request)
            body = await request.json()
        except BridgeError as exc:
            return _error_response(exc.code, 401)
        except Exception:
            return _error_response("bad_json", 400)
        self._hooks.activity()
        try:
            reply = await self._hooks.on_probe(body)
        except BridgeError as exc:
            return _error_response(exc.code, 401)
        return web.json_response(
            reply, headers={HEADER_VERSION: "1", "Cache-Control": "no-store"}
        )

    async def _handle_health(self, request: Any) -> Any:
        """Health endpoint (§7.0).

        Args:
            request: aiohttp request.

        Returns:
            ``{"v":1,"ok":true}``.
        """
        from aiohttp import web

        return web.json_response(
            {"v": 1, "ok": True},
            headers={HEADER_VERSION: "1", "Cache-Control": "no-store"},
        )

    # -- outbound ----------------------------------------------------------------------

    def _client_session(self) -> Any:
        """Return (and lazily create) the shared aiohttp client session.

        Returns:
            An ``aiohttp.ClientSession``.

        Raises:
            RuntimeError: When the transport is not started.
        """
        import aiohttp

        if self._cfg is None:
            raise RuntimeError("webhook transport not started")
        if self._client is None or self._client.closed:
            self._client = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=15),
                headers={
                    "Content-Type": CONTENT_TYPE_JSON,
                    HEADER_VERSION: "1",
                    "Cache-Control": "no-store",
                },
            )
        return self._client

    async def send_plain(self, obj: dict) -> dict | None:
        """POST ``/hello`` to the peer and return ``hello_ack`` (§7.3 rule 1).

        Args:
            obj: ``hello`` object.

        Returns:
            The peer's ``hello_ack``, or ``None`` for a listener.

        Raises:
            BridgeError: ``timeout`` or the peer's error code.
        """
        if self._role == "listen":
            return None
        session = self._client_session()
        url = f"{peer_base_url(self._cfg)}{HELLO_PATH}"
        async with session.post(url, json=obj) as response:
            if response.status != 200:
                body = await _safe_json(response)
                code = (body.get("error") or {}).get("code", "bad_frame")
                raise BridgeError(code)
            ack = await response.json()
        if isinstance(ack, dict) and isinstance(ack.get("sid"), str):
            self._sid = ack["sid"]
        return ack if isinstance(ack, dict) else None

    async def send_envelope(self, env: dict) -> None:
        """Queue an envelope for the batch flusher (§7.3 rule 3).

        While this endpoint is *answering* a ``POST /frames`` batch, the envelope
        is captured for that response instead of being queued outbound: that is
        the only path ``auth_ack`` can take when the initiator is unreachable.

        Args:
            env: Envelope object.
        """
        if self._inline is not None:
            self._inline.append(env)
            return
        await self._outbound_queue.put(env)

    async def _flush_loop(self) -> None:
        """Batch-queue drain loop; posts ``/frames`` with up to ``max_batch_frames``."""
        while True:
            try:
                first = await self._outbound_queue.get()
                batch = [first]
                deadline = time.monotonic() + 0.02
                while len(batch) < MAX_BATCH_FRAMES and time.monotonic() < deadline:
                    try:
                        batch.append(self._outbound_queue.get_nowait())
                    except asyncio.QueueEmpty:
                        await asyncio.sleep(0.002)
                await self._post_frames(batch)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("bridge webhook flush failed conn=%s", self._conn)
                self._probe_failures += 1
                if self._probe_failures >= WEBHOOK_PROBE_FAIL and not self._degraded:
                    self._degraded = True
                    if self._hooks is not None:
                        self._hooks.on_state("degraded", "transport_degraded")

    async def _post_frames(self, frames: list[dict]) -> None:
        """POST one batch to the peer, consuming any inline reply batch (§7.3 rule 2).

        A responder answers the batch that carried ``auth`` with **200** and a body
        whose ``frames`` hold ``auth_ack``; that body is the handshake reply and is
        fed straight back into the session. A ``200`` is only treated as a reply
        when the body actually is a batch — a stray ``200`` with no usable
        ``frames`` array is a protocol violation, never a silent handshake success.

        Args:
            frames: Envelopes to send, ordered by ``seq``.

        Raises:
            BridgeError: When the peer rejects the batch, or answers ``200`` with
                a body that is not a valid batch.
        """
        session = self._client_session()
        url = f"{peer_base_url(self._cfg)}{FRAMES_PATH}"
        batch = {
            "v": 1,
            "conn": self._conn,
            "sid": self._sid or "",
            "batch_id": str(uuid.uuid4()),
            "frames": frames,
        }
        async with session.post(url, json=batch) as response:
            status = response.status
            body = await _safe_json(response)
        if status not in (200, 202):
            code = (body.get("error") or {}).get("code", "bad_frame")
            self._probe_failures += 1
            raise BridgeError(code)
        if status == 200:
            inline = body.get("frames")
            # §7.3 rule 3: a batch carries 1..``max_batch_frames`` frames, so an
            # empty or absent array is malformed — never a completed handshake.
            if not isinstance(inline, list) or not inline:
                raise BridgeError("bad_frame", details={"stage": "inline_batch"})
            assert self._hooks is not None
            for frame in inline:
                if not isinstance(frame, dict):
                    raise BridgeError("bad_frame", details={"stage": "inline_frame"})
                await self._hooks.on_envelope(frame)
        elif body.get("rejected"):
            # §7.3 rule 4: a 202 that rejected frames is not a success.
            code = (body["rejected"][0] or {}).get("code", "bad_frame")
            raise BridgeError(code)
        self._probe_failures = 0
        if self._degraded:
            self._degraded = False
            if self._hooks is not None:
                self._hooks.on_state("ready", "transport_recovered")
        self._alive = True

    async def _probe_loop(self) -> None:
        """Probe the peer periodically and report degradation (§7.3 rule 5/6)."""
        while True:
            await asyncio.sleep(self._heartbeat_s)
            try:
                await self.probe()
                self._probe_failures = 0
                if self._degraded:
                    self._degraded = False
                    if self._hooks is not None:
                        self._hooks.on_state("ready", "webhook_probe_recovered")
            except asyncio.CancelledError:
                raise
            except Exception:
                self._probe_failures += 1
                logger.warning(
                    "bridge webhook probe failed conn=%s failures=%s",
                    self._conn,
                    self._probe_failures,
                )
                if self._probe_failures >= WEBHOOK_PROBE_FAIL and not self._degraded:
                    self._degraded = True
                    if self._hooks is not None:
                        self._hooks.on_state("degraded", "transport_degraded")

    async def probe(self) -> dict:
        """Send one ``probe`` and verify the ``probe_ack`` MAC (§7.3 rule 5).

        Returns:
            The verified ``probe_ack`` object.

        Raises:
            BridgeError: On MAC failure or transport error.
        """
        if self._role == "listen":
            # A listener may probe the connect side when a peer base is known.
            if self._cfg is None:
                raise BridgeError("config_invalid")
        session = self._client_session()
        master = psk_master(self._psk_id, self._psk_secret)
        master_key = handshake_key(master, "probe")
        ack_key = handshake_key(master, "probe_ack")
        nonce = b64u(secrets.token_bytes(16))
        obj = {
            "v": 1,
            "type": "probe",
            "conn": self._conn,
            "nonce": nonce,
            "ts": int(time.time() * 1000),
        }
        obj["mac"] = mac_object(master_key, obj)
        assert self._hooks is not None
        url = f"{peer_base_url(self._cfg)}{PROBE_PATH}"
        async with session.post(url, json=obj) as response:
            if response.status != 200:
                raise BridgeError("poll_auth_failed")
            ack = await response.json()
        if not isinstance(ack, dict):
            raise BridgeError("bad_frame")
        if ack.get("nonce") != nonce:
            raise BridgeError("bad_frame")
        if not verify_mac(ack_key, ack, ack.get("mac", "")):
            raise BridgeError("poll_auth_failed")
        return ack

    def alive(self) -> bool:
        """Whether the carrier believes the link works and is not degraded."""
        return bool(self._alive and not self._degraded)

    def degraded(self) -> bool:
        """Whether the probe loop gave up on reverse reachability (§7.3 rule 6)."""
        return self._degraded

    def diagnostics(self) -> dict:
        """Return carrier state for the status page."""
        return {
            "name": self.name,
            "role": self._role,
            "alive": self.alive(),
            "degraded": self._degraded,
            "probe_failures": self._probe_failures,
        }


async def _safe_json(response: Any) -> dict:
    """Decode a JSON response, returning an empty dict on failure.

    Args:
        response: aiohttp response.

    Returns:
        Decoded object or ``{}``.
    """
    try:
        body = await response.json()
    except Exception:
        return {}
    return body if isinstance(body, dict) else {}


__all__ = ["WebhookTransport"]
