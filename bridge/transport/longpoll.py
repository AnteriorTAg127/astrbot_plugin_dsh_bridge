"""HTTP long-poll carrier: ``GET /poll`` downstream, ``POST /poll/ack`` ack (§7.4).

Long-poll is the fallback that makes one-way reachability usable: the connect side
pulls events that the listen side could not push. Uploads reuse the webhook
``/frames`` shape unchanged.

Every poll is authenticated by an HMAC over a canonical MAC object using the
direction-specific HTTP key; the nonce must be fresh (§7.4). Errors map to the
documented status codes (401/409/425/429/503).
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import time
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
    POLL_ACK_PATH,
    POLL_PATH,
    POLL_WAIT_MAX_S,
    REDELIVER_AFTER_S,
    RETENTION_FRAMES,
)
from ..crypto import jcs_ascii, mac_object, verify_mac
from ..errors import (
    ERR_BAD_BATCH,
    ERR_BAD_JSON,
    ERR_FRAME_TOO_LARGE,
    ERR_NOT_READY,
    ERR_POLL_AUTH_FAILED,
    ERR_RATE_LIMITED,
    ERR_REPLAY_DETECTED,
    ERR_SERVER_BUSY,
    ERR_SID_MISMATCH,
    ERR_STALE_SESSION,
    BridgeError,
)
from .base import (
    Transport,
    TransportHooks,
    bind_target,
    parse_frames_batch,
    peer_base_url,
)


def _poll_mac_object(
    *,
    conn: str,
    sid: str,
    side: str,
    wait: int,
    max_frames: int,
    ts: int,
    nonce: str,
    target: str,
) -> dict:
    """Build the canonical MAC object for a poll request (§7.4).

    Args:
        conn: Connection identifier.
        sid: Session id.
        side: Requesting side.
        wait: Long-poll wait in seconds.
        max_frames: Maximum frames requested.
        ts: Unix milliseconds.
        nonce: Fresh base64url nonce.
        target: ``poll`` or ``poll_ack``.

    Returns:
        Object whose ``jcs_ascii`` form is MACed.
    """
    return {
        "conn": conn,
        "mac_target": target,
        "max": int(max_frames),
        "nonce": nonce,
        "side": side,
        "sid": sid,
        "ts": int(ts),
        "wait": int(wait),
    }


def _ack_mac_object(
    *,
    conn: str,
    sid: str,
    side: str,
    ts: int,
    nonce: str,
    acks: list[str],
) -> dict:
    """Build the canonical MAC object for ``poll/ack`` (§7.4).

    Args:
        conn: Connection identifier.
        sid: Session id.
        side: Requesting side.
        ts: Unix milliseconds.
        nonce: Fresh base64url nonce.
        acks: Frame references being acknowledged.

    Returns:
        Object whose ``jcs_ascii`` form is MACed.
    """
    return {
        "conn": conn,
        "mac_target": "poll_ack",
        "nonce": nonce,
        "acks": list(acks),
        "side": side,
        "sid": sid,
        "ts": int(ts),
    }


class _PollQueue:
    """Bounded per-session queue with redelivery (§7.4)."""

    def __init__(self, retention: int = RETENTION_FRAMES) -> None:
        """Create the queue.

        Args:
            retention: Maximum retained frames; the oldest are dropped with a warning.
        """
        self._retention = retention
        self._items: list[dict] = []
        self._event = asyncio.Event()
        self._dropped = 0

    def put(self, envelope: dict) -> None:
        """Append an envelope, dropping the oldest when full.

        Args:
            envelope: Envelope to queue.
        """
        if len(self._items) >= self._retention:
            self._items.pop(0)
            self._dropped += 1
            logger.warning(
                "bridge poll queue_overflow retention=%s dropped_total=%s",
                self._retention,
                self._dropped,
            )
        self._items.append(
            {
                "envelope": envelope,
                "enqueued_at": time.time(),
                "acked": False,
                "sent": False,
                "sent_at": 0.0,
            }
        )
        self._event.set()

    async def take(self, wait_s: float, max_frames: int) -> list[dict]:
        """Wait for at least one unacked frame.

        Args:
            wait_s: Maximum wait in seconds.
            max_frames: Maximum number of frames returned.

        Returns:
            A list of queued items, each already sent at least once, so the caller can
            reseal them under a fresh ``seq`` (§7.4, §11.3).
        """
        if not self._pending():
            self._event.clear()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._event.wait(), timeout=wait_s)
        return self._pending()[:max_frames]

    def _pending(self) -> list[dict]:
        """Return unacked items that have never been handed out.

        An item is handed out once; redelivery re-offers the same *business payload*
        through :meth:`requeue`, which the server turns into a freshly sealed envelope
        rather than replaying the old ciphertext.

        Returns:
            Items still awaiting their first delivery.
        """
        return [item for item in self._items if not item["acked"] and not item["sent"]]

    def mark_sent(self, refs: list[str]) -> None:
        """Record that the given frame references were handed to the client.

        Args:
            refs: References of the form ``type#seq``.
        """
        wanted = set(refs)
        for item in self._items:
            envelope = item["envelope"]
            if f"{envelope.get('type')}#{envelope.get('seq')}" in wanted:
                item["sent"] = True
                item["sent_at"] = time.time()

    def ack(self, refs: list[str]) -> int:
        """Mark frames acknowledged and drop them.

        Args:
            refs: References of the form ``type#seq``.

        Returns:
            Number of frames removed.
        """
        wanted = set(refs)
        removed = 0
        kept: list[dict] = []
        for item in self._items:
            envelope = item["envelope"]
            ref = f"{envelope.get('type')}#{envelope.get('seq')}"
            if ref in wanted:
                removed += 1
                continue
            kept.append(item)
        self._items = kept
        return removed

    def due_for_redelivery(self) -> list[dict]:
        """Return items unacked for longer than ``REDELIVER_AFTER_S``.

        The caller MUST reseal the same business payload under a new ``seq`` before
        sending it (§7.4): replaying the identical envelope would be rejected as
        ``replay_detected`` by the peer.

        Returns:
            Items that are due for a fresh envelope.
        """
        now = time.time()
        return [
            item
            for item in self._items
            if not item["acked"]
            and item["sent"]
            and now - item["sent_at"] >= REDELIVER_AFTER_S
        ]

    def requeue(self, item: dict) -> None:
        """Make a due item eligible for another downstream batch.

        Args:
            item: Item returned by :meth:`due_for_redelivery`.
        """
        item["sent"] = False

    def size(self) -> int:
        """Return the number of retained items."""
        return len(self._items)


class LongPollTransport(Transport):
    """Long-poll carrier for both roles."""

    name = "longpoll"

    def __init__(
        self,
        *,
        role: str,
        conn: str,
        side: str,
        psk_id: str = "",
        psk_secret: str = "",
        wait_s: int = 25,
        heartbeat_s: int = 30,
    ) -> None:
        """Create the carrier.

        Args:
            role: ``"listen"`` or ``"connect"``.
            conn: Connection identifier.
            side: Local protocol side.
            psk_id: PSK id.
            psk_secret: PSK secret.
            wait_s: Downstream long-poll wait (clamped to 25 s).
            heartbeat_s: Unused placeholder kept for interface symmetry.
        """
        self._role = role
        self._conn = conn
        self._side = side
        self._psk_id = psk_id
        self._psk_secret = psk_secret
        self._wait_s = max(0, min(POLL_WAIT_MAX_S, int(wait_s)))
        self._heartbeat_s = heartbeat_s

        self._cfg: Any = None
        self._hooks: TransportHooks | None = None
        self._runner: Any = None
        self._client: Any = None
        self._sid: str | None = None
        self._queue = _PollQueue()
        self._dl_task: asyncio.Task | None = None
        self._ul_task: asyncio.Task | None = None
        self._outbound: asyncio.Queue = asyncio.Queue()
        self._alive = False
        self._nonce_seen: set[tuple[str, str, str]] = set()
        self._last_status = 0
        self._http_a2b: bytes | None = None
        self._http_b2a: bytes | None = None
        # Frames the session produces while serving the ``auth`` batch, captured
        # for the inline response (§7.3 rule 2, §7.4).
        self._inline: list[dict] | None = None

    async def start(self, cfg: Any, hooks: TransportHooks) -> None:
        """Start the inbound server (listen) and/or the client loops.

        Long-poll only needs the *connect* side to make outbound requests
        (``POST /hello``, ``POST /frames``, ``GET /poll``, ``POST /poll/ack``), so a
        connecting endpoint binds nothing at all: reverse traffic arrives on the
        poll response, and requiring a listener here would demand the very reverse
        reachability long-poll exists to avoid. A listening endpoint still serves
        every endpoint (§7.1/§7.4).

        Args:
            cfg: Session configuration.
            hooks: Inbound callbacks.
        """
        self._cfg = cfg
        self._hooks = hooks
        self._alive = True
        if self._role == "listen":
            await self._start_server(cfg)
        self._ul_task = asyncio.create_task(self._upload_loop())
        if self._role == "connect":
            self._dl_task = asyncio.create_task(self._download_loop())

    async def _start_server(self, cfg: Any) -> None:
        """Bring up the long-poll HTTP server.

        Args:
            cfg: Session configuration.
        """
        from aiohttp import web

        base = cfg.path or "/dsh-bridge"
        app = web.Application(client_max_size=MAX_BATCH_BYTES)
        app.router.add_get(f"{base}{POLL_PATH}", self._handle_poll)
        app.router.add_post(f"{base}{POLL_ACK_PATH}", self._handle_poll_ack)
        app.router.add_post(f"{base}{HELLO_PATH}", self._handle_hello)
        app.router.add_post(f"{base}{FRAMES_PATH}", self._handle_frames)
        app.router.add_get(f"{base}{HEALTH_PATH}", self._handle_health)
        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        bind_host, bind_port = bind_target(cfg)
        site = web.TCPSite(self._runner, bind_host, bind_port)
        await site.start()
        logger.info(
            "bridge longpoll listening conn=%s on %s:%s%s",
            self._conn,
            bind_host,
            bind_port,
            base,
        )

    async def stop(self) -> None:
        """Stop both loops, the client session and the server."""
        for task in (self._dl_task, self._ul_task):
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
        self._dl_task = None
        self._ul_task = None
        if self._client is not None:
            with contextlib.suppress(Exception):
                await self._client.close()
            self._client = None
        if self._runner is not None:
            with contextlib.suppress(Exception):
                await self._runner.cleanup()
            self._runner = None
        self._alive = False

    # -- server side -------------------------------------------------------------------

    async def _handle_hello(self, request: Any) -> Any:
        """Accept ``POST /hello`` for the long-poll carrier (§7.4).

        Args:
            request: aiohttp request.

        Returns:
            ``hello_ack`` or an error body.
        """
        from aiohttp import web

        assert self._hooks is not None
        if request.headers.get("Authorization") or request.headers.get("Cookie"):
            return _err("auth_header_forbidden", 401)
        try:
            body = await request.json()
        except Exception:
            return _err(ERR_BAD_JSON, 400)
        self._hooks.activity()
        try:
            reply = await self._hooks.on_plain(body)
        except BridgeError as exc:
            return _err(exc.code, 401 if exc.code == ERR_POLL_AUTH_FAILED else 400)
        if not isinstance(reply, dict):
            return _err("bad_frame", 400)
        self._sid = reply.get("sid")
        return web.json_response(
            reply, headers={HEADER_VERSION: "1", "Cache-Control": "no-store"}
        )

    async def _handle_frames(self, request: Any) -> Any:
        """Accept an upload batch, identical to webhook (§7.3 rule 2, §7.4).

        As on the webhook carrier, frames the session produces while the batch
        that carried ``auth`` is being handled belong in this response: they are
        the only way ``auth_ack`` reaches an initiator that is not listening.

        Args:
            request: aiohttp request.

        Returns:
            ``200`` with the inline frame batch when the session produced frames,
            otherwise ``202`` with accepted/rejected lists (``409`` when the whole
            batch failed for fatal reasons).
        """
        from aiohttp import web

        assert self._hooks is not None
        if request.headers.get("Authorization") or request.headers.get("Cookie"):
            return _err("auth_header_forbidden", 401)
        raw = await request.read()
        try:
            batch = parse_frames_batch(raw, MAX_BATCH_BYTES)
        except BridgeError as exc:
            status = 413 if exc.code == ERR_FRAME_TOO_LARGE else 400
            return _err(exc.code, status)
        frames = batch["frames"]
        self._hooks.activity()
        accepted: list[str] = []
        rejected: list[dict] = []
        fatal = False
        inline: list[dict] = []
        carries_auth = any(
            isinstance(frame, dict) and frame.get("type") == FRAME_AUTH
            for frame in frames
        )
        previous = self._inline
        if carries_auth:
            self._inline = inline
        try:
            for frame in frames:
                ref = (
                    f"{frame.get('type')}#{frame.get('seq')}"
                    if isinstance(frame, dict)
                    else "?"
                )
                try:
                    await self._hooks.on_envelope(frame)
                    accepted.append(ref)
                except BridgeError as exc:
                    rejected.append({"ref": ref, "code": exc.code})
                    fatal = fatal or exc.fatal
                except Exception:
                    logger.exception("bridge longpoll frame handler crashed")
                    rejected.append({"ref": ref, "code": "internal_error"})
            if not accepted and rejected and fatal:
                return _err(rejected[0]["code"], 409)
        finally:
            self._inline = previous
        if inline:
            return web.json_response(
                {
                    "v": 1,
                    "conn": self._conn,
                    "sid": batch.get("sid") or self._sid,
                    "batch_id": batch.get("batch_id"),
                    "frames": inline,
                },
                status=200,
                headers={HEADER_VERSION: "1", "Cache-Control": "no-store"},
            )
        return web.json_response(
            {"v": 1, "accepted": accepted, "rejected": rejected},
            status=202,
            headers={HEADER_VERSION: "1", "Cache-Control": "no-store"},
        )

    async def _handle_poll(self, request: Any) -> Any:
        """Serve ``GET /poll``: authenticate, then long-poll for frames (§7.4).

        Args:
            request: aiohttp request.

        Returns:
            ``200`` with frames, ``204`` on timeout, or a documented error status.
        """
        from aiohttp import web

        assert self._hooks is not None
        if request.headers.get("Authorization") or request.headers.get("Cookie"):
            return _err("auth_header_forbidden", 401)
        query = request.query
        try:
            conn = query["conn"]
            sid = query["sid"]
            side = query["side"]
            wait = int(query.get("wait", 0))
            max_frames = int(query.get("max", 32))
            ts = int(query["ts"])
            nonce = query["nonce"]
            target = query.get("target", "poll")
            mac = query["mac"]
        except (KeyError, TypeError, ValueError):
            return _err(ERR_POLL_AUTH_FAILED, 401)
        if conn != self._conn or target != "poll":
            return _err(ERR_POLL_AUTH_FAILED, 401)
        if abs(int(time.time() * 1000) - ts) > 300_000:
            return _err(ERR_POLL_AUTH_FAILED, 401)
        if not 0 <= wait <= POLL_WAIT_MAX_S or not 1 <= max_frames <= MAX_BATCH_FRAMES:
            return _err(ERR_POLL_AUTH_FAILED, 401)
        if side not in ("A", "B") or side == self._side:
            return _err(ERR_SID_MISMATCH, 409)
        if self._sid is None:
            return _err(ERR_NOT_READY, 425)
        if sid != self._sid:
            return _err(ERR_STALE_SESSION, 409)
        replay_key = (sid, side, nonce)
        if replay_key in self._nonce_seen:
            return _err(ERR_REPLAY_DETECTED, 409)
        key = self._http_key(side)
        mac_obj = _poll_mac_object(
            conn=conn,
            sid=sid,
            side=side,
            wait=wait,
            max_frames=max_frames,
            ts=ts,
            nonce=nonce,
            target=target,
        )
        if not verify_mac(key, mac_obj, mac):
            return _err(ERR_POLL_AUTH_FAILED, 401)
        self._nonce_seen.add(replay_key)
        self._hooks.activity()

        items = await self._queue.take(wait, max_frames)
        if not items:
            return web.Response(status=204)
        frames = [item["envelope"] for item in items]
        self._queue.mark_sent(
            [
                f"{item['envelope'].get('type')}#{item['envelope'].get('seq')}"
                for item in items
            ]
        )
        return web.json_response(
            {
                "v": 1,
                "conn": self._conn,
                "sid": sid,
                "frames": frames,
                "redelivery": any(item.get("redelivered") for item in items),
            },
            headers={HEADER_VERSION: "1", "Cache-Control": "no-store"},
        )

    async def _handle_poll_ack(self, request: Any) -> Any:
        """Handle ``POST /poll/ack`` (§7.4).

        Args:
            request: aiohttp request.

        Returns:
            ``204`` on success or an error body.
        """
        from aiohttp import web

        try:
            body = await request.json()
        except Exception:
            return _err(ERR_BAD_JSON, 400)
        if not isinstance(body, dict):
            return _err(ERR_BAD_JSON, 400)
        mac = body.get("mac")
        side = body.get("side")
        sid = body.get("sid")
        acks = body.get("acks")
        if (
            side not in ("A", "B")
            or not isinstance(acks, list)
            or not isinstance(sid, str)
        ):
            return _err(ERR_POLL_AUTH_FAILED, 401)
        if sid != self._sid:
            return _err(ERR_STALE_SESSION, 409)
        obj = _ack_mac_object(
            conn=body.get("conn", self._conn),
            sid=sid,
            side=side,
            ts=int(body.get("ts", 0)),
            nonce=str(body.get("nonce", "")),
            acks=[str(item) for item in acks],
        )
        if not verify_mac(self._http_key(side), obj, str(mac or "")):
            return _err(ERR_POLL_AUTH_FAILED, 401)
        self._queue.ack([str(item) for item in acks])
        return web.Response(status=204)

    async def _handle_health(self, request: Any) -> Any:
        """Health endpoint (§7.0).

        Args:
            request: aiohttp request.

        Returns:
            ``{"v":1,"ok":true}``.
        """
        from aiohttp import web

        return web.json_response({"v": 1, "ok": True}, headers={HEADER_VERSION: "1"})

    # -- client side -------------------------------------------------------------------

    def _client_session(self) -> Any:
        """Return the shared client session.

        Returns:
            An ``aiohttp.ClientSession``.
        """
        import aiohttp

        if self._client is None or self._client.closed:
            wait_total = self._wait_s + 15
            self._client = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=wait_total),
                headers={"Content-Type": CONTENT_TYPE_JSON, HEADER_VERSION: "1"},
            )
        return self._client

    async def send_plain(self, obj: dict) -> dict | None:
        """POST ``/hello`` and return ``hello_ack`` (§7.4).

        Args:
            obj: ``hello`` object.

        Returns:
            The peer's ``hello_ack`` for the connect role.
        """
        if self._role == "listen":
            return None
        session = self._client_session()
        url = f"{peer_base_url(self._cfg)}{HELLO_PATH}"
        async with session.post(url, json=obj) as response:
            if response.status != 200:
                raise BridgeError(ERR_POLL_AUTH_FAILED)
            ack = await response.json()
        if isinstance(ack, dict) and isinstance(ack.get("sid"), str):
            self._sid = ack["sid"]
        return ack if isinstance(ack, dict) else None

    async def send_envelope(self, env: dict) -> None:
        """Queue an envelope for downstream poll or upstream upload (§7.4).

        While this endpoint is answering the batch that carried ``auth``, the
        envelope is captured for that response instead (§7.3 rule 2, §7.4): the
        initiator's ``auth_ack`` has no other path back.

        Args:
            env: Envelope object.
        """
        if self._inline is not None:
            self._inline.append(env)
            return
        if self._role == "listen":
            self._queue.put(env)
        else:
            await self._outbound.put(env)

    async def _upload_loop(self) -> None:
        """Upload queued envelopes as batches for the connect role."""
        while True:
            try:
                frames = [await self._outbound.get()]
                while len(frames) < MAX_BATCH_FRAMES:
                    try:
                        frames.append(self._outbound.get_nowait())
                    except asyncio.QueueEmpty:
                        break
                if self._sid is None:
                    await asyncio.sleep(0.05)
                    for frame in frames:
                        await self._outbound.put(frame)
                    continue
                await self._post_frames(frames)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("bridge longpoll upload failed conn=%s", self._conn)

    async def _post_frames(self, frames: list[dict]) -> None:
        """POST one batch to the peer and consume any inline reply batch (§7.4).

        The responder answers the batch that carried ``auth`` with **200** and a
        body whose ``frames`` hold ``auth_ack`` (§7.3 rule 2, §7.4); that body is
        fed straight back into the session. A ``200`` without a usable ``frames``
        array is a protocol violation, never a silent handshake success.

        Args:
            frames: Envelopes.

        Raises:
            BridgeError: When the peer rejects the batch or answers a malformed
                ``200``.
        """
        import uuid

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
            body: Any = {}
            with contextlib.suppress(Exception):
                body = await response.json()
        if status == 200:
            inline = body.get("frames") if isinstance(body, dict) else None
            # §7.3 rule 3: a batch carries 1..``max_batch_frames`` frames, so an
            # empty or absent array is malformed — never a completed handshake.
            if not isinstance(inline, list) or not inline:
                raise BridgeError(ERR_BAD_BATCH, details={"stage": "inline_batch"})
            assert self._hooks is not None
            for frame in inline:
                if not isinstance(frame, dict):
                    raise BridgeError(ERR_BAD_BATCH, details={"stage": "inline_frame"})
                await self._hooks.on_envelope(frame)
            return
        if status == 202:
            rejected = body.get("rejected") if isinstance(body, dict) else None
            if rejected:
                # §7.3 rule 4: a 202 that rejected frames is not a success.
                raise BridgeError(str((rejected[0] or {}).get("code", ERR_BAD_BATCH)))
            return
        raise BridgeError(ERR_SERVER_BUSY if status >= 500 else ERR_BAD_BATCH)

    async def _download_loop(self) -> None:
        """Continuously poll the peer for downstream frames (§7.4)."""
        while True:
            try:
                await self._poll_once()
            except asyncio.CancelledError:
                raise
            except BridgeError as exc:
                logger.warning(
                    "bridge longpoll poll failed conn=%s code=%s", self._conn, exc.code
                )
                if exc.code in (
                    ERR_STALE_SESSION,
                    ERR_SID_MISMATCH,
                    ERR_POLL_AUTH_FAILED,
                ):
                    self._alive = False
                await asyncio.sleep(1.0)
            except Exception:
                logger.exception("bridge longpoll poll crashed conn=%s", self._conn)
                await asyncio.sleep(1.0)

    async def _poll_once(self) -> None:
        """Perform one poll round-trip: request, dispatch, then ack (§7.4)."""
        assert self._hooks is not None
        if self._sid is None:
            await asyncio.sleep(0.1)
            return
        nonce = _b64u16()
        ts = int(time.time() * 1000)
        key = self._http_key(self._side)
        mac_obj = _poll_mac_object(
            conn=self._conn,
            sid=self._sid,
            side=self._side,
            wait=self._wait_s,
            max_frames=MAX_BATCH_FRAMES,
            ts=ts,
            nonce=nonce,
            target="poll",
        )
        mac = mac_object(key, mac_obj)
        params = {
            "conn": self._conn,
            "sid": self._sid,
            "side": self._side,
            "wait": str(self._wait_s),
            "max": str(MAX_BATCH_FRAMES),
            "ts": str(ts),
            "nonce": nonce,
            "target": "poll",
            "mac": mac,
        }
        session = self._client_session()
        url = f"{peer_base_url(self._cfg)}{POLL_PATH}"
        async with session.get(url, params=params) as response:
            self._last_status = response.status
            if response.status == 204:
                self._alive = True
                self._hooks.activity()
                return
            if response.status != 200:
                body = {}
                with contextlib.suppress(Exception):
                    body = await response.json()
                code = (body.get("error") or {}).get("code", ERR_POLL_AUTH_FAILED)
                if response.status == 401:
                    raise BridgeError(ERR_POLL_AUTH_FAILED)
                if response.status == 409:
                    raise BridgeError(
                        code
                        if code in (ERR_STALE_SESSION, ERR_SID_MISMATCH)
                        else ERR_STALE_SESSION
                    )
                if response.status == 425:
                    await asyncio.sleep(1.0)
                    return
                if response.status == 429:
                    raise BridgeError(ERR_RATE_LIMITED)
                raise BridgeError(code)
            body = await response.json()
        self._alive = True
        self._hooks.activity()
        frames = body.get("frames") or []
        acks: list[str] = []
        for frame in frames:
            try:
                await self._hooks.on_envelope(frame)
                acks.append(f"{frame.get('type')}#{frame.get('seq')}")
            except BridgeError as exc:
                logger.warning("bridge longpoll frame rejected code=%s", exc.code)
                if exc.fatal:
                    raise
        if acks:
            await self._send_ack(acks)

    async def _send_ack(self, acks: list[str]) -> None:
        """POST ``/poll/ack`` for the frames just processed (§7.4).

        Args:
            acks: Frame references.
        """
        nonce = _b64u16()
        ts = int(time.time() * 1000)
        # §7.4: the wire body carries ``target`` while the MACed object names the same
        # field ``mac_target``. Only the MAC object is canonicalised; ``v`` and
        # ``target`` stay out of it.
        mac_body = _ack_mac_object(
            conn=self._conn,
            sid=self._sid or "",
            side=self._side,
            ts=ts,
            nonce=nonce,
            acks=acks,
        )
        body = {
            "v": 1,
            "conn": self._conn,
            "sid": self._sid or "",
            "side": self._side,
            "ts": ts,
            "target": "poll_ack",
            "nonce": nonce,
            "acks": acks,
        }
        body["mac"] = mac_object(self._http_key(self._side), mac_body)
        session = self._client_session()
        url = f"{peer_base_url(self._cfg)}{POLL_ACK_PATH}"
        async with session.post(url, json=body) as response:
            if response.status != 204:
                raise BridgeError(ERR_POLL_AUTH_FAILED)

    def _http_key(self, direction_side: str) -> bytes:
        """Return the HTTP direction key for poll MACs (§3.4).

        The keys are derived once during the handshake and pushed in by the session
        layer via :meth:`set_http_keys`, so this module never re-derives them.

        Args:
            direction_side: Side that originates the request (the MAC direction).

        Returns:
            32-byte HMAC key for that direction.

        Raises:
            BridgeError: ``not_ready`` when the handshake has not supplied the keys.
        """
        if self._http_a2b is None or self._http_b2a is None:
            raise BridgeError(ERR_NOT_READY, details={"reason": "http_keys"})
        return self._http_a2b if direction_side == "A" else self._http_b2a

    def set_http_keys(self, k_http_a2b: bytes, k_http_b2a: bytes) -> None:
        """Install the per-session HTTP MAC keys derived by the session layer (§3.4).

        Args:
            k_http_a2b: Key for polls originated by side A.
            k_http_b2a: Key for polls originated by side B.
        """
        self._http_a2b = k_http_a2b
        self._http_b2a = k_http_b2a

    def alive(self) -> bool:
        """Whether recent poll activity succeeded."""
        return self._alive

    def diagnostics(self) -> dict:
        """Return carrier state for the status page."""
        return {
            "name": self.name,
            "role": self._role,
            "alive": self._alive,
            "queued": self._queue.size(),
            "last_status": self._last_status,
        }


def _b64u16() -> str:
    """Return a fresh 16-byte base64url nonce (§7.4).

    Returns:
        Base64url nonce.
    """
    from ..crypto import b64u

    return b64u(secrets.token_bytes(16))


def _err(code: str, status: int) -> Any:
    """Build a plaintext HTTP error response (§8.2).

    Args:
        code: §15 error code.
        status: HTTP status.

    Returns:
        aiohttp JSON response.
    """
    from aiohttp import web

    from ..errors import http_error_body

    headers = {HEADER_VERSION: "1", "Cache-Control": "no-store"}
    if status in (429, 503):
        headers["Retry-After"] = "60"
    return web.json_response(http_error_body(code), status=status, headers=headers)


__all__ = ["LongPollTransport", "jcs_ascii", "ERR_FRAME_TOO_LARGE"]
