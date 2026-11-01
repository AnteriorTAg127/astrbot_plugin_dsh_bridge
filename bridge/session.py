"""Session layer: handshake state machine, envelope sealing, request/reply pairing.

Implements protocol §4 (four-step handshake and caps negotiation), §5 (AEAD
envelopes, single-writer sequence lock, replay window), §6 (heartbeat, close,
reconnect) and §9.1 (message object validation).

Layering contract (§1.1): this module MUST NOT import ``bridge.app`` or
``bridge.host``. It only knows envelopes, handshakes, ``seq`` and timeouts.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from astrbot.api import logger

from .constants import (
    ENVELOPE_VERSION,
    FEATURES,
    FRAME_AUTH,
    FRAME_AUTH_ACK,
    FRAME_CLOSE,
    FRAME_DATA,
    FRAME_HELLO,
    FRAME_HELLO_ACK,
    FRAME_PING,
    FRAME_PONG,
    HANDSHAKE_FAIL_WINDOW_S,
    HANDSHAKE_MAX_FAIL,
    HANDSHAKE_RATE_LIMIT_S,
    HANDSHAKE_TIMEOUT_MS,
    HEARTBEAT_MISS,
    HELLO_REPLAY_TTL_S,
    HELLO_SKEW_S,
    IMAGE_MIME_TYPES,
    KIND_EVT,
    KIND_REP,
    KIND_REQ,
    MAX_BATCH_FRAMES,
    MAX_CHUNK_BYTES,
    MAX_FRAME_BYTES,
    PROTOCOL_VERSION,
    RETENTION_FRAMES,
    ROLE_INITIATOR,
    ROLE_RESPONDER,
    SIDE_A,
    SUPPORTED_PROTOCOL_VERSIONS,
)
from .crypto import (
    b64u,
    b64u_dec,
    handshake_key,
    mac_object,
    open_frame,
    psk_master,
    seal_frame,
    session_keys,
    transcript_hash,
    verify_mac,
)
from .errors import (
    ERR_AUTH_REQUIRED,
    ERR_BAD_CAPS,
    ERR_BAD_FRAME,
    ERR_BAD_PARAMS,
    ERR_BAD_SIDE,
    ERR_BAD_VERSION,
    ERR_CAPABILITY_UNAVAILABLE,
    ERR_CONFIG_INVALID,
    ERR_DRAINING,
    ERR_HANDSHAKE_REUSE,
    ERR_HELLO_EXPIRED,
    ERR_HELLO_REPLAY,
    ERR_INTERNAL_ERROR,
    ERR_NOT_READY,
    ERR_PSK_MISMATCH,
    ERR_PSK_NOT_CONFIGURED,
    ERR_STALE_SESSION,
    ERR_TH_MISMATCH,
    ERR_TIMEOUT,
    ERR_UNKNOWN_CONN,
    ERR_UNKNOWN_MESSAGE,
    ERR_UNKNOWN_MESSAGE_KIND,
    BridgeError,
)
from .replay import ReplayWindow


class SessionState(str, Enum):
    """Connection lifecycle states (§16.5)."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    HANDSHAKING = "handshaking"
    READY = "ready"
    DRAINING = "draining"
    CLOSED = "closed"
    DEGRADED = "degraded"
    CONFIG_ERROR = "config_error"


class Role(str, Enum):
    """Transport role for this endpoint (§4.1)."""

    INITIATOR = "initiator"
    RESPONDER = "responder"


@dataclass(frozen=True)
class SessionConfig:
    """Immutable connection configuration for one session.

    Attributes:
        conn: Connection identifier; must match on both ends.
        side: Local protocol side, ``"A"`` or ``"B"``.
        role: Whether this endpoint initiates or answers the handshake.
        transport: Selected carrier, ``ws`` / ``webhook`` / ``longpoll``.
        psk_id: Connection PSK identifier (not secret).
        psk_secret: Connection PSK secret; empty means "refuse to connect".
        heartbeat_s: Application heartbeat interval in seconds.
        req_timeout_s: Default request/reply timeout in seconds.
        caps: Local capability object (§4.5). Must be ASCII-clean.
        version: Local plugin version advertised in ``caps``.
        host_id: Host identifier advertised in ``caps`` (``astrbot`` / ``dsh``).
        addr: Peer address for outbound carriers (§7.1).
        port: Peer port for outbound carriers.
        bind_addr: Local bind address for a listening socket.
        bind_port: Local bind port; ``0`` means "same as ``port``".
        path: Connection path prefix (``conn_path``).
        mode: ``connect`` or ``listen``; MUST be opposite to the peer (§4.1).
        tls_enabled: Whether TLS is enabled for this connection.
        tls_cert_path: TLS certificate path for the listener.
        tls_key_path: TLS private key path for the listener.
        tls_fingerprint: Expected peer certificate SHA-256 fingerprint.
        reconnect_max_backoff: Upper bound for reconnect backoff in seconds.
        poll_wait_s: Long-poll wait in seconds.
        max_frame_bytes: Maximum envelope size.
    """

    conn: str
    side: str
    role: Role
    transport: str
    psk_id: str
    psk_secret: str
    heartbeat_s: int = 30
    req_timeout_s: float = 60.0
    caps: dict = field(default_factory=dict)
    version: str = "0.1.0"
    host_id: str = "astrbot"
    addr: str = "127.0.0.1"
    port: int = 8765
    bind_addr: str = "127.0.0.1"
    bind_port: int = 0
    path: str = "/dsh-bridge"
    mode: str = "connect"
    tls_enabled: bool = False
    tls_cert_path: str = ""
    tls_key_path: str = ""
    tls_fingerprint: str = ""
    reconnect_max_backoff: int = 60
    poll_wait_s: int = 25
    max_frame_bytes: int = 2_097_152

    @property
    def host(self) -> str:
        """Peer host, kept as a ``host`` alias for the transports.

        Returns:
            The configured peer address.
        """
        return self.addr

    @property
    def listen_host(self) -> str:
        """Bind address for a listening socket.

        Returns:
            ``bind_addr`` when set, otherwise the peer address.
        """
        return self.bind_addr or self.addr

    @property
    def listen_port(self) -> int:
        """Bind port for a listening socket.

        Returns:
            ``bind_port`` when non-zero, otherwise the peer port.
        """
        return self.bind_port or self.port

    def __post_init__(self) -> None:
        """Validate the invariants that fail fast at configuration time.

        Raises:
            BridgeError: ``config_invalid`` when the connection cannot work.
        """
        if self.side not in (SIDE_A, "B"):
            raise BridgeError(ERR_CONFIG_INVALID, details={"reason": "side"})
        if not self.conn:
            raise BridgeError(ERR_CONFIG_INVALID, details={"reason": "conn"})
        if not self.psk_id or not self.psk_secret:
            raise BridgeError(ERR_PSK_NOT_CONFIGURED)

    def psk(self) -> bytes:
        """Derive ``psk_master`` for this connection.

        Returns:
            32-byte master key.
        """
        return psk_master(self.psk_id, self.psk_secret)


def build_caps(
    *,
    side: str,
    host: str,
    version: str,
    transports: list[str],
    tls: bool,
    native_tool: bool,
    image_enabled: bool,
    image_max_count: int,
    image_max_bytes: int,
    image_total_max_bytes: int,
) -> dict:
    """Build the local ``caps`` object exactly as §4.5 requires.

    The object participates in the handshake MAC and transcript, so field order is
    irrelevant (JCS sorts keys) but the field set and value types are normative.

    Args:
        side: Local side ``"A"`` or ``"B"``.
        host: ``"astrbot"`` or ``"dsh"``.
        version: Local plugin version string (ASCII).
        transports: Carriers this endpoint can actually use.
        tls: Whether TLS is enabled for this connection.
        native_tool: Whether native tool approvals are forwarded (A is always False).
        image_enabled: Whether image attachments are accepted.
        image_max_count: Maximum images per task.
        image_max_bytes: Maximum bytes per image.
        image_total_max_bytes: Maximum bytes per task.

    Returns:
        Capability dictionary ready to embed in ``hello``/``hello_ack``.
    """
    return {
        "side": side,
        "host": host,
        "version": version,
        "pv": list(SUPPORTED_PROTOCOL_VERSIONS),
        "transports": sorted(set(transports)),
        "tls": bool(tls),
        "roles": {"initiate_task": True, "execute_task": True},
        "approvals": {
            "business_decision": True,
            "cross_end_submit": True,
            "native_tool": bool(native_tool),
        },
        "attachments": {
            "image": bool(image_enabled),
            "blob": True,
            "reference": False,
            "mime": sorted(IMAGE_MIME_TYPES),
            "max_bytes": int(image_max_bytes),
            "max_count": int(image_max_count),
            "max_total_bytes": int(image_total_max_bytes),
            "max_pixels": 64_000_000,
            "max_dimension": 8192,
        },
        "limits": {
            "max_frame_bytes": MAX_FRAME_BYTES,
            "max_chunk_bytes": MAX_CHUNK_BYTES,
            "max_batch_frames": MAX_BATCH_FRAMES,
            "retention_frames": RETENTION_FRAMES,
        },
        "features": sorted(FEATURES),
    }


def _validate_caps(caps: Any) -> None:
    """Validate a peer ``caps`` object (§4.5).

    Args:
        caps: Object received in ``hello``/``hello_ack``.

    Raises:
        BridgeError: ``bad_caps`` when a field is missing or the wrong type.
    """
    if not isinstance(caps, dict):
        raise BridgeError(ERR_BAD_CAPS, details={"reason": "not_object"})
    for key in ("side", "host", "version"):
        if not isinstance(caps.get(key), str) or not caps[key]:
            raise BridgeError(ERR_BAD_CAPS, details={"reason": key})
    pv = caps.get("pv")
    if (
        not isinstance(pv, list)
        or not pv
        or not all(isinstance(i, int) and not isinstance(i, bool) for i in pv)
    ):
        raise BridgeError(ERR_BAD_CAPS, details={"reason": "pv"})
    for key in ("transports", "features"):
        value = caps.get(key)
        if not isinstance(value, list) or not all(isinstance(i, str) for i in value):
            raise BridgeError(ERR_BAD_CAPS, details={"reason": key})
    if not isinstance(caps.get("tls"), bool):
        raise BridgeError(ERR_BAD_CAPS, details={"reason": "tls"})
    roles = caps.get("roles")
    if not isinstance(roles, dict) or not isinstance(roles.get("initiate_task"), bool):
        raise BridgeError(ERR_BAD_CAPS, details={"reason": "roles"})
    if not isinstance(roles.get("execute_task"), bool):
        raise BridgeError(ERR_BAD_CAPS, details={"reason": "roles"})
    approvals = caps.get("approvals")
    if not isinstance(approvals, dict):
        raise BridgeError(ERR_BAD_CAPS, details={"reason": "approvals"})
    for key in ("business_decision", "cross_end_submit", "native_tool"):
        if not isinstance(approvals.get(key), bool):
            raise BridgeError(ERR_BAD_CAPS, details={"reason": "approvals"})
    attachments = caps.get("attachments")
    if not isinstance(attachments, dict):
        raise BridgeError(ERR_BAD_CAPS, details={"reason": "attachments"})
    if attachments.get("reference") is not False:
        # v1 MUST NOT support the reference mode (§13.3).
        raise BridgeError(ERR_BAD_CAPS, details={"reason": "reference"})
    for key in (
        "max_bytes",
        "max_count",
        "max_total_bytes",
        "max_pixels",
        "max_dimension",
    ):
        value = attachments.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise BridgeError(ERR_BAD_CAPS, details={"reason": key})
    limits = caps.get("limits")
    if not isinstance(limits, dict):
        raise BridgeError(ERR_BAD_CAPS, details={"reason": "limits"})
    for key in (
        "max_frame_bytes",
        "max_chunk_bytes",
        "max_batch_frames",
        "retention_frames",
    ):
        value = limits.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise BridgeError(ERR_BAD_CAPS, details={"reason": key})


def now_ms() -> int:
    """Return the current Unix time in milliseconds."""
    return int(time.time() * 1000)


def _uuid4() -> str:
    """Return a lowercase RFC 4122 v4 UUID string."""
    return str(uuid.uuid4())


def utc_iso_ms() -> str:
    """Return the protocol timestamp format ``YYYY-MM-DDTHH:MM:SS.mmmZ``."""
    now = time.time()
    millis = int(now * 1000)
    seconds = millis // 1000
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(seconds)) + (
        f".{millis % 1000:03d}Z"
    )


class HandshakeRateLimiter:
    """Sliding-window failure counter guarding the responder (§4.6)."""

    def __init__(self) -> None:
        """Create an empty limiter."""
        self._failures: list[float] = []
        self._blocked_until: float = 0.0

    def is_blocked(self) -> bool:
        """Whether new ``hello`` attempts must be answered with ``rate_limited``."""
        return time.monotonic() < self._blocked_until

    def record_failure(self) -> None:
        """Record one failed handshake and apply the lockout when saturated."""
        now = time.monotonic()
        self._failures = [
            stamp for stamp in self._failures if now - stamp < HANDSHAKE_FAIL_WINDOW_S
        ]
        self._failures.append(now)
        if len(self._failures) >= HANDSHAKE_MAX_FAIL:
            self._blocked_until = now + HANDSHAKE_RATE_LIMIT_S
            logger.warning(
                "bridge handshake rate limit engaged after %d failures",
                len(self._failures),
            )

    def record_success(self) -> None:
        """Reset the failure counter after a successful handshake."""
        self._failures.clear()
        self._blocked_until = 0.0


class HelloReplayCache:
    """Short-lived cache of seen ``hello_id``/``nonce_c`` values (§4.6)."""

    def __init__(self, ttl_s: int = HELLO_REPLAY_TTL_S) -> None:
        """Create the cache.

        Args:
            ttl_s: Retention time for each observed identifier.
        """
        self._ttl = ttl_s
        self._seen: dict[str, float] = {}

    def _purge(self) -> None:
        """Drop entries older than the TTL."""
        cutoff = time.monotonic() - self._ttl
        for key in [k for k, stamp in self._seen.items() if stamp < cutoff]:
            del self._seen[key]

    def check_and_record(self, hello_id: str, nonce_c: str) -> None:
        """Reject a replayed handshake and record a fresh one.

        Args:
            hello_id: Initiator handshake identifier.
            nonce_c: Initiator nonce (base64url as sent).

        Raises:
            BridgeError: ``hello_replay`` when either value was seen recently.
        """
        self._purge()
        for key in (f"id:{hello_id}", f"nonce:{nonce_c}"):
            if key in self._seen:
                raise BridgeError(ERR_HELLO_REPLAY)
        stamp = time.monotonic()
        self._seen[f"id:{hello_id}"] = stamp
        self._seen[f"nonce:{nonce_c}"] = stamp


@dataclass
class _PendingCall:
    """One in-flight request awaiting its reply."""

    future: asyncio.Future
    message: str


class Session:
    """One A↔B session: handshake, sealed frames, request/reply pairing.

    The session talks to a *transport* through the duck-typed interface
    ``send_plain(obj) -> dict | None`` and ``send_envelope(env)``. Payload
    routing is delegated to the callbacks supplied by the composition root, so
    this layer stays free of business semantics (§1.1).
    """

    def __init__(
        self,
        cfg: SessionConfig,
        transport: Any,
        on_message: Callable[[dict], Awaitable[None]],
        on_security_event: Callable[[str, str], None],
        *,
        on_state: Callable[[SessionState, str], None] | None = None,
    ) -> None:
        """Create a session.

        Args:
            cfg: Connection configuration.
            transport: Carrier implementing ``send_plain``/``send_envelope``.
            on_message: Awaited with each validated ``req``/``rep``/``evt`` object
                (``rep`` objects are consumed internally and never forwarded).
            on_security_event: Called with ``(code, detail)`` for audit logging.
            on_state: Optional observer for state transitions.
        """
        self.cfg = cfg
        self.sid: str | None = None
        self.peer_caps: dict | None = None
        self.state: SessionState = SessionState.DISCONNECTED
        self.write_epoch = 0

        self._transport = transport
        self._on_message = on_message
        self._on_security_event = on_security_event
        self._on_state = on_state

        self._keys = None
        self._th: bytes | None = None
        self._peer_side: str | None = None
        self._next_seq = 0
        self._send_lock = asyncio.Lock()
        self._replay = ReplayWindow(start=0)
        self._pending: dict[str, _PendingCall] = {}
        self._hello_id: str | None = None
        self._nonce_c: bytes | None = None
        self._nonce_s: bytes | None = None
        self._hello_without_mac: dict | None = None
        self._hello_ack_without_mac: dict | None = None
        self._handshake_done = asyncio.Event()
        self._handshake_error: BridgeError | None = None
        self._closed = asyncio.Event()
        self._last_inbound = time.monotonic()
        self._hearbeat_task: asyncio.Task | None = None

    # -- state helpers -----------------------------------------------------------------

    def _set_state(self, state: SessionState, reason: str = "") -> None:
        """Record and publish a state transition.

        Args:
            state: New state.
            reason: Short English reason for logs and the status page.
        """
        if self.state is state:
            return
        self.state = state
        logger.info(
            "bridge session %s state=%s reason=%s",
            self.cfg.conn,
            state.value,
            reason or "-",
        )
        if self._on_state is not None:
            with contextlib.suppress(Exception):
                self._on_state(state, reason)

    def _security(self, code: str, detail: str) -> None:
        """Emit a structured security event (English, secret-free)."""
        logger.warning(
            "bridge security event conn=%s sid=%s code=%s detail=%s",
            self.cfg.conn,
            self.sid or "-",
            code,
            detail,
        )
        with contextlib.suppress(Exception):
            self._on_security_event(code, detail)

    # -- handshake ---------------------------------------------------------------------

    @property
    def peer_side(self) -> str | None:
        """The peer's protocol side once known."""
        return self._peer_side

    def local_caps(self) -> dict:
        """Return the caps object advertised in this handshake."""
        if self.cfg.caps:
            return self.cfg.caps
        return build_caps(
            side=self.cfg.side,
            host=self.cfg.host_id,
            version=self.cfg.version,
            transports=[self.cfg.transport],
            tls=False,
            native_tool=False,
            image_enabled=True,
            image_max_count=4,
            image_max_bytes=10_485_760,
            image_total_max_bytes=20_971_520,
        )

    async def start(self) -> None:
        """Drive the handshake to ``ready`` or raise.

        The initiator runs the whole four-step exchange. The responder only enters
        ``handshaking`` and returns: it becomes ``ready`` when the initiator's
        ``hello``/``auth`` arrive, which the transport delivers asynchronously.
        Callers that need to wait for a responder session should await
        :meth:`wait_ready`.

        Raises:
            BridgeError: Any handshake failure from §15.1 (initiator only).
        """
        self._set_state(SessionState.CONNECTING, "start")
        if self.cfg.role is Role.INITIATOR:
            await self._start_initiator()
            self._mark_ready("handshake_complete")
        else:
            self._set_state(SessionState.HANDSHAKING, "listen")

    def _mark_ready(self, reason: str) -> None:
        """Publish ``ready`` and record the inbound activity timestamp.

        Args:
            reason: Short English reason for logs.
        """
        self._set_state(SessionState.READY, reason)
        self._last_inbound = time.monotonic()
        self._handshake_done.set()

    async def wait_ready(self, timeout_s: float | None = None) -> None:
        """Wait until the handshake completes.

        Args:
            timeout_s: Override for the handshake timeout.

        Raises:
            BridgeError: The recorded handshake failure, or ``timeout``.
        """
        timeout = HANDSHAKE_TIMEOUT_MS / 1000 if timeout_s is None else timeout_s
        try:
            await asyncio.wait_for(self._handshake_done.wait(), timeout=timeout)
        except TimeoutError as exc:
            raise BridgeError(ERR_TIMEOUT, details={"stage": "handshake"}) from exc
        if self._handshake_error is not None:
            raise self._handshake_error

    async def _start_initiator(self) -> None:
        """Run the initiator half of the handshake (§4.1)."""
        self._set_state(SessionState.HANDSHAKING, "send_hello")
        hello = await self._make_hello()
        ack = await self._transport.send_plain(hello)
        if not isinstance(ack, dict):
            raise BridgeError(ERR_TIMEOUT, details={"stage": "hello_ack"})
        self._accept_hello_ack(ack)
        self._derive_from_handshake()
        await self._send_auth()
        await self.wait_ready()

    async def _make_hello(self) -> dict:
        """Build and MAC the plaintext ``hello`` object (§4.2).

        Returns:
            Complete ``hello`` object including ``mac``.
        """
        master = self.cfg.psk()
        self._hello_id = _uuid4()
        self._nonce_c = b64u_dec(b64u(_random_bytes(32)))
        self._hello_without_mac = {
            "v": ENVELOPE_VERSION,
            "type": FRAME_HELLO,
            "conn": self.cfg.conn,
            "hello_id": self._hello_id,
            "pv": PROTOCOL_VERSION,
            "side": self.cfg.side,
            "tp": self.cfg.transport,
            "nonce": b64u(self._nonce_c),
            "ts": now_ms(),
            "caps": self.local_caps(),
        }
        key = handshake_key(master, "hello")
        mac = mac_object(key, self._hello_without_mac)
        return {**self._hello_without_mac, "mac": mac}

    def _accept_hello_ack(self, ack: dict) -> None:
        """Validate and store the responder ``hello_ack`` (§4.3).

        Args:
            ack: The received ``hello_ack`` object.

        Raises:
            BridgeError: On any validation failure.
        """
        master = self.cfg.psk()
        if not isinstance(ack, dict) or ack.get("type") != FRAME_HELLO_ACK:
            raise BridgeError(ERR_BAD_FRAME, details={"stage": "hello_ack"})
        if ack.get("conn") != self.cfg.conn:
            raise BridgeError(ERR_UNKNOWN_CONN)
        if ack.get("hello_id") != self._hello_id:
            raise BridgeError(ERR_HELLO_REPLAY, details={"stage": "hello_id"})
        if ack.get("pv") != PROTOCOL_VERSION:
            raise BridgeError(ERR_BAD_VERSION)
        if ack.get("side") == self.cfg.side:
            raise BridgeError(ERR_BAD_SIDE)
        key = handshake_key(master, "hello_ack")
        if not verify_mac(key, ack, ack.get("mac", "")):
            raise BridgeError(ERR_PSK_MISMATCH, details={"stage": "hello_ack_mac"})
        self._nonce_s = b64u_dec(ack["nonce"])
        if self._nonce_s == self._nonce_c:
            raise BridgeError(ERR_HANDSHAKE_REUSE, details={"stage": "nonce_reuse"})
        _validate_caps(ack.get("caps"))
        self.peer_caps = ack["caps"]
        self._peer_side = ack.get("side")
        if self._peer_side != _opposite_side(self.cfg.side):
            raise BridgeError(ERR_BAD_SIDE)
        self.sid = ack.get("sid")
        if not isinstance(self.sid, str) or not self.sid:
            raise BridgeError(ERR_BAD_FRAME, details={"stage": "sid"})
        self._hello_ack_without_mac = {k: v for k, v in ack.items() if k != "mac"}

    def _derive_from_handshake(self) -> None:
        """Derive session keys and the transcript digest (§3.4, §4.4).

        Also hands the HTTP direction keys to the long-poll transport, which needs
        them to MAC its poll requests and acknowledgements.
        """
        if self._nonce_c is None or self._nonce_s is None:
            raise BridgeError(ERR_BAD_FRAME, details={"stage": "nonces"})
        if self._hello_without_mac is None or self._hello_ack_without_mac is None:
            raise BridgeError(ERR_BAD_FRAME, details={"stage": "transcript"})
        self._keys = session_keys(self.cfg.psk(), self._nonce_c, self._nonce_s)
        self._th = transcript_hash(self._hello_without_mac, self._hello_ack_without_mac)
        install = getattr(self._transport, "set_http_keys", None)
        if callable(install):
            install(self._keys.k_http_a2b, self._keys.k_http_b2a)

    async def _send_auth(self) -> None:
        """Send the first sealed frame (``auth``, ``seq=0``)."""
        payload = {
            "side": self.cfg.side,
            "role": ROLE_INITIATOR,
            "sid": self.sid,
            "hello_id": self._hello_id,
            "th": b64u(self._th or b""),
        }
        await self.send(FRAME_AUTH, payload)

    def _auth_payload(self, role: str) -> dict:
        """Build the ``auth``/``auth_ack`` payload binding the transcript.

        Args:
            role: ``initiator`` or ``responder`` for the local side.

        Returns:
            Payload object as specified by §4.4.
        """
        return {
            "side": self.cfg.side,
            "role": role,
            "sid": self.sid,
            "hello_id": self._hello_id,
            "th": b64u(self._th or b""),
        }

    async def handle_plain(self, obj: dict) -> dict | None:
        """Handle a plaintext handshake frame from the transport.

        Args:
            obj: ``hello`` (responder side) or ``hello_ack`` (initiator side).

        Returns:
            The object to send back, if any.

        Raises:
            BridgeError: On handshake failure; the transport turns this into an
                HTTP error body or closes the socket.
        """
        frame_type = obj.get("type") if isinstance(obj, dict) else None
        if frame_type == FRAME_HELLO:
            return await self._handle_hello(obj)
        if frame_type == FRAME_HELLO_ACK:
            self._accept_hello_ack(obj)
            self._derive_from_handshake()
            return None
        raise BridgeError(ERR_BAD_FRAME, details={"stage": "plain", "type": frame_type})

    async def _handle_hello(self, hello: dict) -> dict:
        """Validate ``hello`` and produce ``hello_ack`` (§4.2/§4.3).

        Args:
            hello: The received ``hello`` object.

        Returns:
            The ``hello_ack`` object including ``mac``.

        Raises:
            BridgeError: On any validation failure. No ``hello_ack`` is produced.
        """
        if self.state is not SessionState.HANDSHAKING:
            raise BridgeError(ERR_AUTH_REQUIRED, details={"stage": "hello"})
        master = self.cfg.psk()
        if hello.get("conn") != self.cfg.conn:
            raise BridgeError(ERR_UNKNOWN_CONN)
        if hello.get("pv") != PROTOCOL_VERSION:
            raise BridgeError(ERR_BAD_VERSION)
        if hello.get("v") != ENVELOPE_VERSION:
            raise BridgeError(ERR_BAD_VERSION, details={"stage": "v"})
        if hello.get("side") != _opposite_side(self.cfg.side):
            raise BridgeError(ERR_BAD_SIDE)
        if hello.get("tp") not in (self.cfg.transport, "ws", "webhook", "longpoll"):
            raise BridgeError(ERR_BAD_FRAME, details={"stage": "tp"})
        try:
            skew_ms = abs(now_ms() - int(hello.get("ts", 0)))
        except (TypeError, ValueError) as exc:
            raise BridgeError(ERR_BAD_FRAME, details={"stage": "ts"}) from exc
        if skew_ms > HELLO_SKEW_S * 1000:
            raise BridgeError(ERR_HELLO_EXPIRED)
        _validate_caps(hello.get("caps"))
        key = handshake_key(master, "hello")
        if not verify_mac(key, hello, hello.get("mac", "")):
            raise BridgeError(ERR_PSK_MISMATCH, details={"stage": "hello_mac"})
        nonce_c = b64u_dec(hello["nonce"])
        if len(nonce_c) != 32:
            raise BridgeError(ERR_BAD_FRAME, details={"stage": "nonce"})

        # Peer caps must intersect ours, otherwise nothing can be negotiated.
        if not set(hello["caps"]["pv"]) & set(SUPPORTED_PROTOCOL_VERSIONS):
            raise BridgeError(ERR_BAD_VERSION)
        if not set(hello["caps"]["transports"]) & {self.cfg.transport}:
            raise BridgeError(
                ERR_CAPABILITY_UNAVAILABLE, details={"stage": "transports"}
            )

        self._hello_id = hello["hello_id"]
        self._nonce_c = nonce_c
        self._hello_without_mac = {k: v for k, v in hello.items() if k != "mac"}
        self.peer_caps = hello["caps"]
        self._peer_side = hello["side"]
        self._nonce_s = _random_bytes(32)
        self.sid = _uuid4()
        self._hello_ack_without_mac = {
            "v": ENVELOPE_VERSION,
            "type": FRAME_HELLO_ACK,
            "conn": self.cfg.conn,
            "hello_id": self._hello_id,
            "sid": self.sid,
            "pv": PROTOCOL_VERSION,
            "side": self.cfg.side,
            "tp": self.cfg.transport,
            "nonce": b64u(self._nonce_s),
            "ts": now_ms(),
            "caps": self.local_caps(),
        }
        ack_key = handshake_key(master, "hello_ack")
        mac = mac_object(ack_key, self._hello_ack_without_mac)
        self._derive_from_handshake()
        return {**self._hello_ack_without_mac, "mac": mac}

    # -- sealed frames -----------------------------------------------------------------

    async def send(self, frame_type: str, payload: dict) -> None:
        """Seal and enqueue one frame under the single-writer lock (§5.6).

        Args:
            frame_type: Envelope type.
            payload: JSON payload to seal.

        Raises:
            BridgeError: ``not_ready`` before the handshake completes.
        """
        if self._keys is None or self.sid is None:
            raise BridgeError(ERR_NOT_READY)
        if self.state is not SessionState.READY and frame_type not in (
            FRAME_AUTH,
            FRAME_AUTH_ACK,
            FRAME_CLOSE,
            FRAME_PONG,
        ):
            raise BridgeError(ERR_NOT_READY)
        async with self._send_lock:
            seq = self._next_seq
            self._next_seq += 1
            envelope = seal_frame(
                self._keys.key_for(self.cfg.side),
                self.cfg.side,
                frame_type,
                self.cfg.conn,
                seq,
                payload,
            )
            await self._transport.send_envelope(envelope)

    async def send_message(self, message: dict) -> None:
        """Wrap an application message in a ``data`` frame and send it.

        Args:
            message: ``k``-discriminated message object (§9.1).
        """
        await self.send(FRAME_DATA, message)

    async def call(
        self, message: str, params: dict, timeout_s: float | None = None
    ) -> dict:
        """Send a ``req`` and await the matching ``rep`` (§5.5).

        Args:
            message: Message name (``m``).
            params: Request parameters.
            timeout_s: Override for the reply timeout.

        Returns:
            The ``rep.result`` object.

        Raises:
            BridgeError: The remote error, or ``timeout``.
        """
        request_id = _uuid4()
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[request_id] = _PendingCall(future=future, message=message)
        envelope = {
            "k": KIND_REQ,
            "m": message,
            "id": request_id,
            "ts": utc_iso_ms(),
            "params": params,
        }
        try:
            await self.send_message(envelope)
        except Exception:
            self._pending.pop(request_id, None)
            raise
        timeout = timeout_s if timeout_s is not None else self.cfg.req_timeout_s
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except TimeoutError as exc:
            raise BridgeError(ERR_TIMEOUT, details={"m": message}) from exc
        finally:
            self._pending.pop(request_id, None)

    async def handle_envelope(self, envelope: dict) -> None:
        """Validate and dispatch one inbound envelope (§5.3/§5.4).

        Args:
            envelope: Raw envelope object from the transport.

        Raises:
            BridgeError: Fatal security errors; the caller must drop the session.
        """
        if self._keys is None:
            raise BridgeError(
                ERR_AUTH_REQUIRED, details={"stage": "sealed_before_hello"}
            )
        if envelope.get("conn") != self.cfg.conn:
            raise BridgeError(ERR_UNKNOWN_CONN)
        seq = envelope.get("seq")
        frame_type = envelope.get("type")
        # The replay window advances only after a successful AEAD open, so a forged
        # frame cannot consume a legitimate slot.
        payload = open_frame(
            self._keys.inbound_key_for(self._peer_side), self._peer_side, envelope
        )
        self._replay.accept(seq)
        self._last_inbound = time.monotonic()

        if frame_type == FRAME_AUTH:
            await self._handle_auth(payload)
            return
        if frame_type == FRAME_AUTH_ACK:
            await self._handle_auth_ack(payload)
            return
        if self.state is not SessionState.READY:
            if frame_type == FRAME_PONG:
                return
            raise BridgeError(ERR_AUTH_REQUIRED, details={"stage": frame_type})
        if frame_type == FRAME_DATA:
            await self._handle_data(payload)
        elif frame_type == FRAME_PING:
            await self.send(FRAME_PONG, {"n": payload.get("n", 0), "echo": now_ms()})
        elif frame_type == FRAME_PONG:
            return
        elif frame_type == FRAME_CLOSE:
            self._set_state(SessionState.CLOSED, str(payload.get("code", "close")))
            self._closed.set()
            self._fail_pending(
                BridgeError(ERR_DRAINING, details={"reason": "peer_close"})
            )
        else:
            raise BridgeError(ERR_BAD_FRAME, details={"reason": "unknown_type"})

    async def _handle_auth(self, payload: dict) -> None:
        """Validate the responder-side ``auth`` frame and answer ``auth_ack``.

        Args:
            payload: Decrypted ``auth`` payload.

        Raises:
            BridgeError: ``th_mismatch`` when transcripts diverge.
        """
        if self._th is None:
            raise BridgeError(ERR_TH_MISMATCH, details={"stage": "auth_early"})
        self._check_transcript(payload)
        if self.sid is None or payload.get("sid") != self.sid:
            raise BridgeError(ERR_STALE_SESSION)
        await self.send(FRAME_AUTH_ACK, self._auth_payload(ROLE_RESPONDER))
        self._mark_ready("auth_ack_sent")

    async def _handle_auth_ack(self, payload: dict) -> None:
        """Validate the initiator-side ``auth_ack`` frame.

        Args:
            payload: Decrypted ``auth_ack`` payload.

        Raises:
            BridgeError: ``th_mismatch`` when transcripts diverge.
        """
        if self._th is None:
            raise BridgeError(ERR_TH_MISMATCH, details={"stage": "auth_ack_early"})
        self._check_transcript(payload)
        if self.sid is None or payload.get("sid") != self.sid:
            raise BridgeError(ERR_STALE_SESSION)
        self._mark_ready("auth_ack_received")

    def _check_transcript(self, payload: dict) -> None:
        """Compare the peer ``th`` with ours in constant time (§4.4).

        Args:
            payload: Decrypted ``auth``/``auth_ack`` payload.

        Raises:
            BridgeError: ``th_mismatch`` on divergence.
        """
        import hmac

        expected = b64u(self._th or b"")
        received = payload.get("th")
        if not isinstance(received, str) or not hmac.compare_digest(expected, received):
            raise BridgeError(ERR_TH_MISMATCH)

    async def _handle_data(self, payload: dict) -> None:
        """Validate a ``data`` payload and route or correlate it (§9.1).

        Args:
            payload: Decrypted message object.

        Raises:
            BridgeError: ``unknown_message_kind`` / ``bad_params`` for invalid shapes.
        """
        kind = payload.get("k")
        if kind == KIND_REP:
            self._resolve_reply(payload)
            return
        if kind not in (KIND_REQ, KIND_EVT):
            raise BridgeError(ERR_UNKNOWN_MESSAGE_KIND)
        message = payload.get("m")
        if not isinstance(message, str) or not message:
            raise BridgeError(ERR_UNKNOWN_MESSAGE)
        if not isinstance(payload.get("id"), str) or not payload["id"]:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "id"})
        await self._on_message(payload)

    def _resolve_reply(self, payload: dict) -> None:
        """Deliver a ``rep`` to the waiting ``call`` (§5.5).

        Args:
            payload: Decrypted ``rep`` object.
        """
        reply_to = payload.get("reply_to")
        pending = self._pending.get(reply_to) if isinstance(reply_to, str) else None
        if pending is None:
            logger.debug("bridge dropped orphan reply reply_to=%s", reply_to)
            return
        if pending.future.done():
            return
        if payload.get("ok"):
            pending.future.set_result(payload.get("result") or {})
        else:
            error = payload.get("error") or {}
            pending.future.set_exception(
                BridgeError(
                    error.get("code", ERR_INTERNAL_ERROR),
                    message=error.get("message"),
                    details=error.get("details"),
                )
            )

    def _fail_pending(self, error: BridgeError) -> None:
        """Fail every in-flight request (used on close).

        Args:
            error: Error to raise in each waiter.
        """
        for pending in list(self._pending.values()):
            if not pending.future.done():
                pending.future.set_exception(error)
        self._pending.clear()

    # -- liveness ----------------------------------------------------------------------

    def touch(self) -> None:
        """Record inbound activity (used by the long-poll transport as liveness)."""
        self._last_inbound = time.monotonic()

    def is_alive(self) -> bool:
        """Whether inbound activity is recent enough to keep the session (§6.1)."""
        limit = self.cfg.heartbeat_s * HEARTBEAT_MISS
        return (time.monotonic() - self._last_inbound) <= limit

    async def ping(self) -> None:
        """Send one application heartbeat ``ping``."""
        await self.send(FRAME_PING, {"n": now_ms()})

    async def close(self, code: str, reason: str) -> None:
        """Send ``close`` (best effort), drain briefly, then stop (§6.2).

        Args:
            code: §15 string code.
            reason: Short ASCII reason, at most 120 characters.
        """
        self._set_state(SessionState.DRAINING, code)
        safe_reason = (reason or "")[:120].encode("ascii", "ignore").decode("ascii")
        with contextlib.suppress(Exception):
            await self.send(FRAME_CLOSE, {"code": code, "reason": safe_reason})
        with contextlib.suppress(Exception):
            await asyncio.sleep(0)
        self._set_state(SessionState.CLOSED, code)
        self._closed.set()
        self._fail_pending(BridgeError(code))
        await self._stop_heartbeat()

    async def _stop_heartbeat(self) -> None:
        """Cancel the background heartbeat task if any.

        Raises:
            None: Cancellation errors are suppressed.
        """
        task = self._hearbeat_task
        self._hearbeat_task = None
        if task is None:
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task

    async def run_heartbeat(self) -> None:
        """Emit periodic ``ping`` frames while the session is ready (§6.1).

        Returns when the session leaves ``READY``.
        """
        interval = max(1, int(self.cfg.heartbeat_s))
        while self.state is SessionState.READY:
            await asyncio.sleep(interval)
            if self.state is not SessionState.READY:
                return
            with contextlib.suppress(Exception):
                await self.ping()

    # -- negotiation -------------------------------------------------------------------

    def peer_supports(self, feature: str) -> bool:
        """Whether the peer advertised ``feature`` in ``caps.features`` (§4.5).

        Args:
            feature: Feature string such as ``event.ack``.

        Returns:
            ``True`` when the peer advertised it.
        """
        if not self.peer_caps:
            return False
        return feature in self.peer_caps.get("features", [])

    def peer_role(self, role: str) -> bool:
        """Whether the peer advertised a task role (§4.5).

        Args:
            role: ``initiate_task`` or ``execute_task``.

        Returns:
            ``True`` when the peer advertised the role as available.
        """
        if not self.peer_caps:
            return False
        return bool(self.peer_caps.get("roles", {}).get(role, False))

    def negotiated(self) -> dict:
        """Compute the negotiated capability intersection (§4.5).

        Returns:
            ``{"mime", "max_count", "max_bytes", "max_total_bytes",
            "max_frame_bytes", "max_chunk_bytes", "max_batch_frames",
            "roles", "approvals", "features"}`` using intersections and minima.
        """
        if not self.peer_caps:
            return {}
        mine = self.local_caps()
        peer = self.peer_caps
        mine_att = mine.get("attachments", {})
        peer_att = peer.get("attachments", {})
        mine_limits = mine.get("limits", {})
        peer_limits = peer.get("limits", {})

        def _min_int(a: int, b: int) -> int:
            return min(int(a), int(b))

        return {
            "mime": sorted(
                set(mine_att.get("mime", [])) & set(peer_att.get("mime", []))
            ),
            "max_count": _min_int(
                mine_att.get("max_count", 0), peer_att.get("max_count", 0)
            ),
            "max_bytes": _min_int(
                mine_att.get("max_bytes", 0), peer_att.get("max_bytes", 0)
            ),
            "max_total_bytes": _min_int(
                mine_att.get("max_total_bytes", 0), peer_att.get("max_total_bytes", 0)
            ),
            "max_frame_bytes": _min_int(
                mine_limits.get("max_frame_bytes", 0),
                peer_limits.get("max_frame_bytes", 0),
            ),
            "max_chunk_bytes": _min_int(
                mine_limits.get("max_chunk_bytes", 0),
                peer_limits.get("max_chunk_bytes", 0),
            ),
            "max_batch_frames": _min_int(
                mine_limits.get("max_batch_frames", 0),
                peer_limits.get("max_batch_frames", 0),
            ),
            "roles": {
                key: bool(mine.get("roles", {}).get(key))
                and bool(peer.get("roles", {}).get(key))
                for key in ("initiate_task", "execute_task")
            },
            "approvals": {
                key: bool(mine.get("approvals", {}).get(key))
                and bool(peer.get("approvals", {}).get(key))
                for key in ("business_decision", "cross_end_submit", "native_tool")
            },
            "features": sorted(
                set(mine.get("features", [])) & set(peer.get("features", []))
            ),
        }


def _opposite_side(side: str) -> str:
    """Return the counterpart side.

    Args:
        side: ``"A"`` or ``"B"``.

    Returns:
        The other side.
    """
    return "B" if side == SIDE_A else "A"


def _random_bytes(length: int) -> bytes:
    """Return ``length`` CSPRNG bytes.

    Args:
        length: Number of bytes.

    Returns:
        Random bytes.
    """
    import secrets

    return secrets.token_bytes(length)


def make_message(
    kind: str,
    message: str,
    *,
    params: dict | None = None,
    result: dict | None = None,
    reply_to: str | None = None,
) -> dict:
    """Build a validated message object (§9.1) for sending.

    Args:
        kind: ``req`` / ``rep`` / ``evt``.
        message: Message name from the closed vocabulary.
        params: Parameters for ``req``/``evt``.
        result: Result for a successful ``rep``.
        reply_to: Request id for a ``rep``.

    Returns:
        Message object with a fresh ``id`` and ``ts``.

    Raises:
        BridgeError: ``unknown_message_kind`` for an invalid ``kind``.
    """
    if kind not in (KIND_REQ, KIND_REP, KIND_EVT):
        raise BridgeError(ERR_UNKNOWN_MESSAGE_KIND)
    body: dict[str, Any] = {"k": kind, "m": message, "id": _uuid4(), "ts": utc_iso_ms()}
    if kind == KIND_REP:
        body["reply_to"] = reply_to
        body["ok"] = True
        body["result"] = result or {}
    else:
        body["params"] = params or {}
    return body


__all__ = [
    "HandshakeRateLimiter",
    "HelloReplayCache",
    "Role",
    "Session",
    "SessionConfig",
    "SessionState",
    "build_caps",
    "make_message",
    "utc_iso_ms",
]
