"""Protocol constants for dsh-bridge/v1.

All values here are normative: they come from ``开发/v0.1/protocol.md`` and the
golden fixture ``tests/fixtures/protocol_vectors_v1.json``. Never invent new
labels, frame types, message names or error codes at call sites.

Label note:
    ``LABEL`` is the single authoritative value ``"dsh-bridge/v1"`` used for PSK
    derivation, every HKDF ``info`` prefix and the frame AAD prefix
    (``开发/v0.1/protocol-freeze.json``). Both ends MUST use the same value or the
    handshake can never succeed (``psk_mismatch``). Never copy ``aad`` strings out
    of the fixture — always derive them from this constant.
"""

from __future__ import annotations

# Domain separation label. MUST match ``protocol-freeze.json`` and the fixture.
LABEL: str = "dsh-bridge/v1"

# Envelope / protocol versions.
ENVELOPE_VERSION: int = 1
PROTOCOL_VERSION: int = 1
SUPPORTED_PROTOCOL_VERSIONS: tuple[int, ...] = (1,)

# Local side identity.
SIDE_A: str = "A"
SIDE_B: str = "B"

# WebSocket subprotocol negotiated during the HTTP upgrade.
WS_SUBPROTOCOL: str = "dsh-bridge.v1"

# Roles.
ROLE_INITIATOR: str = "initiator"
ROLE_RESPONDER: str = "responder"

# Envelope / handshake frame types (§5.1, §4.2, §4.3).
FRAME_AUTH: str = "auth"
FRAME_AUTH_ACK: str = "auth_ack"
FRAME_DATA: str = "data"
FRAME_PING: str = "ping"
FRAME_PONG: str = "pong"
FRAME_CLOSE: str = "close"
FRAME_HELLO: str = "hello"
FRAME_HELLO_ACK: str = "hello_ack"
FRAME_PROBE: str = "probe"
FRAME_PROBE_ACK: str = "probe_ack"

SEALED_FRAME_TYPES: frozenset[str] = frozenset(
    {FRAME_AUTH, FRAME_AUTH_ACK, FRAME_DATA, FRAME_PING, FRAME_PONG, FRAME_CLOSE}
)
HANDSHAKE_FRAME_TYPES: frozenset[str] = frozenset({FRAME_HELLO, FRAME_HELLO_ACK})

# Direction nonce tags (§3.5).
DIRECTION_TAG_A2B: int = 0x0A
DIRECTION_TAG_B2A: int = 0x0B

# Handshake MAC key names, used as ``LABEL || " " || name`` HKDF info (§3.3).
HANDSHAKE_KEY_NAMES: tuple[str, ...] = ("hello", "hello_ack", "probe", "probe_ack")

# Session key info suffixes (§3.4).
INFO_A2B: str = " a2b"
INFO_B2A: str = " b2a"
INFO_HTTP_A2B: str = " http-a2b"
INFO_HTTP_B2A: str = " http-b2a"
INFO_HANDSHAKE: str = " handshake"

# Frame types that the app layer may see (``data`` payload kinds, §9.1).
KIND_REQ: str = "req"
KIND_REP: str = "rep"
KIND_EVT: str = "evt"

# Message names (closed vocabulary, §9.2).
MSG_TASK_SUBMIT: str = "task.submit"
MSG_TASK_STATUS: str = "task.status"
MSG_TASK_LIST_OPEN: str = "task.list_open"
MSG_TASK_CANCEL: str = "task.cancel"
MSG_TASK_EVENT: str = "task.event"
MSG_DECISION_REQUEST: str = "decision.request"
MSG_DECISION_ANSWER: str = "decision.answer"
MSG_APPROVAL_REQUEST: str = "approval.request"
MSG_APPROVAL_DECISION: str = "approval.decision"
MSG_APPROVAL_LOOKUP: str = "approval.lookup"
MSG_SESSION_LIST: str = "session.list"
MSG_SESSION_CREATE: str = "session.create"
MSG_SESSION_SELECT: str = "session.select"
MSG_SESSION_MANAGE: str = "session.manage"
MSG_SESSION_AUTHZ: str = "session.authz"
MSG_BLOB_BEGIN: str = "blob.begin"
MSG_BLOB_CHUNK: str = "blob.chunk"
MSG_BLOB_COMMIT: str = "blob.commit"
MSG_BLOB_ABORT: str = "blob.abort"
MSG_EVENT_ACK: str = "event.ack"

#: Messages that MUST be answered with ``k="rep"``.
REQUEST_MESSAGES: frozenset[str] = frozenset(
    {
        MSG_TASK_SUBMIT,
        MSG_TASK_STATUS,
        MSG_TASK_LIST_OPEN,
        MSG_TASK_CANCEL,
        MSG_DECISION_ANSWER,
        MSG_APPROVAL_REQUEST,
        MSG_APPROVAL_LOOKUP,
        MSG_SESSION_LIST,
        MSG_SESSION_CREATE,
        MSG_SESSION_SELECT,
        MSG_SESSION_MANAGE,
        MSG_EVENT_ACK,
    }
)

#: Messages that MUST NOT be answered (``evt`` only).
EVENT_MESSAGES: frozenset[str] = frozenset(
    {
        MSG_TASK_EVENT,
        MSG_DECISION_REQUEST,
        MSG_APPROVAL_DECISION,
        MSG_SESSION_AUTHZ,
        MSG_BLOB_BEGIN,
        MSG_BLOB_CHUNK,
        MSG_BLOB_COMMIT,
        MSG_BLOB_ABORT,
    }
)

# Task statuses (§16.1).
STATUS_PENDING_APPROVAL: str = "pending_approval"
STATUS_ACCEPTED: str = "accepted"
STATUS_QUEUED: str = "queued"
STATUS_RUNNING: str = "running"
STATUS_SUCCEEDED: str = "succeeded"
STATUS_FAILED: str = "failed"
STATUS_CANCELED: str = "canceled"
STATUS_REJECTED: str = "rejected"
STATUS_NEEDS_DECISION: str = "needs_decision"
STATUS_NEEDS_APPROVAL: str = "needs_approval"
STATUS_NEEDS_HUMAN: str = "needs_human"

#: Terminal statuses; no further transition is legal.
TERMINAL_STATUSES: frozenset[str] = frozenset(
    {STATUS_SUCCEEDED, STATUS_FAILED, STATUS_CANCELED, STATUS_REJECTED}
)

#: Statuses considered "open" for ``task.list_open`` (§9.5).
OPEN_STATUSES: frozenset[str] = frozenset(
    {
        STATUS_PENDING_APPROVAL,
        STATUS_ACCEPTED,
        STATUS_QUEUED,
        STATUS_RUNNING,
        STATUS_NEEDS_DECISION,
        STATUS_NEEDS_APPROVAL,
        STATUS_NEEDS_HUMAN,
    }
)

#: Legal transitions from §16.1. Illegal transitions MUST be dropped with a warning.
ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    STATUS_PENDING_APPROVAL: frozenset(
        {
            STATUS_ACCEPTED,
            STATUS_QUEUED,
            STATUS_REJECTED,
            STATUS_CANCELED,
            STATUS_NEEDS_HUMAN,
        }
    ),
    STATUS_ACCEPTED: frozenset(
        {
            STATUS_QUEUED,
            STATUS_PENDING_APPROVAL,
            STATUS_REJECTED,
            STATUS_CANCELED,
            STATUS_NEEDS_HUMAN,
        }
    ),
    STATUS_QUEUED: frozenset({STATUS_RUNNING, STATUS_CANCELED, STATUS_NEEDS_HUMAN}),
    STATUS_RUNNING: frozenset(
        {
            STATUS_SUCCEEDED,
            STATUS_FAILED,
            STATUS_CANCELED,
            STATUS_NEEDS_DECISION,
            STATUS_NEEDS_APPROVAL,
            STATUS_NEEDS_HUMAN,
        }
    ),
    STATUS_NEEDS_DECISION: frozenset(
        {STATUS_RUNNING, STATUS_FAILED, STATUS_CANCELED, STATUS_NEEDS_HUMAN}
    ),
    STATUS_NEEDS_APPROVAL: frozenset(
        {
            STATUS_RUNNING,
            STATUS_REJECTED,
            STATUS_FAILED,
            STATUS_CANCELED,
            STATUS_NEEDS_HUMAN,
        }
    ),
    STATUS_NEEDS_HUMAN: frozenset({STATUS_RUNNING, STATUS_CANCELED}),
}

# Task event names (§11.2).
EVENT_ACCEPTED: str = "accepted"
EVENT_QUEUED: str = "queued"
EVENT_RUNNING: str = "running"
EVENT_PROGRESS: str = "progress"
EVENT_COMPLETED: str = "completed"
EVENT_FAILED: str = "failed"
EVENT_CANCELED: str = "canceled"
EVENT_NEEDS_DECISION: str = "needs_decision"
EVENT_NEEDS_APPROVAL: str = "needs_approval"
EVENT_NEEDS_HUMAN: str = "needs_human"

#: Event name -> resulting task status (§11.2).
EVENT_TO_STATUS: dict[str, str] = {
    EVENT_ACCEPTED: STATUS_ACCEPTED,
    EVENT_QUEUED: STATUS_QUEUED,
    EVENT_RUNNING: STATUS_RUNNING,
    EVENT_PROGRESS: STATUS_RUNNING,
    EVENT_COMPLETED: STATUS_SUCCEEDED,
    EVENT_FAILED: STATUS_FAILED,
    EVENT_CANCELED: STATUS_CANCELED,
    EVENT_NEEDS_DECISION: STATUS_NEEDS_DECISION,
    EVENT_NEEDS_APPROVAL: STATUS_NEEDS_APPROVAL,
    EVENT_NEEDS_HUMAN: STATUS_NEEDS_HUMAN,
}

#: Events that must wake the originating session (§16.6).
WAKE_EVENTS: frozenset[str] = frozenset(
    {EVENT_COMPLETED, EVENT_FAILED, EVENT_NEEDS_DECISION, EVENT_NEEDS_APPROVAL}
)

# Task kinds (§9.3).
KIND_DSH_AGENT_RUN: str = "dsh_agent_run"
KIND_ASTR_AGENT_RUN: str = "astr_agent_run"
TASK_KINDS: frozenset[str] = frozenset({KIND_DSH_AGENT_RUN, KIND_ASTR_AGENT_RUN})

# Task origins (§9.3).
ORIGIN_LLM: str = "llm"
ORIGIN_HUMAN: str = "human"
TASK_ORIGINS: frozenset[str] = frozenset({ORIGIN_LLM, ORIGIN_HUMAN})

# Approval types and outcomes (§12).
APPROVAL_NATIVE_TOOL: str = "native_tool"
APPROVAL_BUSINESS_DECISION: str = "business_decision"
APPROVAL_CROSS_END_SUBMIT: str = "cross_end_submit"
APPROVAL_TYPES: frozenset[str] = frozenset(
    {APPROVAL_NATIVE_TOOL, APPROVAL_BUSINESS_DECISION, APPROVAL_CROSS_END_SUBMIT}
)

OUTCOME_ALLOWED_ONCE: str = "allowed-once"
OUTCOME_REJECTED: str = "rejected"
OUTCOME_CANCELLED: str = "cancelled"
OUTCOME_UNAVAILABLE: str = "unavailable"
APPROVAL_OUTCOMES: frozenset[str] = frozenset(
    {OUTCOME_ALLOWED_ONCE, OUTCOME_REJECTED, OUTCOME_CANCELLED, OUTCOME_UNAVAILABLE}
)
#: Outcomes that actually allow the action. Everything else fails closed.
APPROVAL_ALLOWING_OUTCOMES: frozenset[str] = frozenset({OUTCOME_ALLOWED_ONCE})

# Actor kinds (§12.3). Only humans may approve or decide.
ACTOR_HUMAN: str = "human"
ACTOR_AGENT: str = "agent"

# Approval channels.
CHANNEL_IM: str = "im"
CHANNEL_WEB: str = "web"
CHANNEL_TIMEOUT: str = "timeout"

# Decision outcomes / reasons.
DECISION_REASON_ALREADY_ANSWERED: str = "already_answered"
DECISION_REASON_EXPIRED: str = "expired"

# Image MIME whitelist (§13.1), ascending ASCII order.
IMAGE_MIME_TYPES: tuple[str, ...] = (
    "image/gif",
    "image/jpeg",
    "image/png",
    "image/webp",
)

# Magic numbers used to verify declared MIME against real bytes (§13.2).
IMAGE_MAGIC: dict[str, bytes] = {
    "image/png": b"\x89PNG\r\n\x1a\n",
    "image/jpeg": b"\xff\xd8\xff",
    "image/gif": b"GIF8",
}
WEBP_RIFF_MAGIC: bytes = b"RIFF"
WEBP_FORM_MAGIC: bytes = b"WEBP"

# Hard limits (§13.2). Some are fixed by protocol, some configurable.
MAX_IMAGE_PIXELS: int = 64_000_000
MAX_IMAGE_DIMENSION: int = 8192
MAX_CHUNK_BYTES: int = 786_432
MAX_FRAME_BYTES: int = 2_097_152
MAX_BATCH_FRAMES: int = 32
RETENTION_FRAMES: int = 4096
MAX_BATCH_BYTES: int = 8_388_608

# Timing constants (§2.2, §4.1, §6, §7.4, §11).
HELLO_SKEW_S: int = 300
HANDSHAKE_TIMEOUT_MS: int = 10_000
HELLO_REPLAY_TTL_S: int = 120
HANDSHAKE_MAX_FAIL: int = 10
HANDSHAKE_FAIL_WINDOW_S: int = 60
HANDSHAKE_RATE_LIMIT_S: int = 60
DEFAULT_HEARTBEAT_S: int = 30
HEARTBEAT_MISS: int = 2
DRAIN_GRACE_S: float = 5.0
POLL_WAIT_MAX_S: int = 25
REDELIVER_AFTER_S: int = 30
NOTIFY_BACKOFF_S: tuple[int, ...] = (1, 5, 30, 120, 600)
NOTIFY_MAX_ATTEMPTS: int = 5
WEBHOOK_PROBE_FAIL: int = 3
BLOB_TTL_S: int = 300
DEFAULT_REQ_TIMEOUT_S: float = 60.0
TASK_SUBMIT_TIMEOUT_S: float = 15.0
IDEMPOTENT_REPLY_TTL_S: int = 24 * 3600

# Default transport list and fallbacks (§7.5, §14).
TRANSPORT_WS: str = "ws"
TRANSPORT_WEBHOOK: str = "webhook"
TRANSPORT_LONGPOLl: str = "longpoll"
TRANSPORTS: tuple[str, ...] = (TRANSPORT_WS, TRANSPORT_WEBHOOK, TRANSPORT_LONGPOLl)

MODES: tuple[str, ...] = ("connect", "listen")

# Capability feature strings (§4.5).
FEATURES: tuple[str, ...] = (
    "approval.lookup",
    "blob.chunked",
    "decision.options",
    "event.ack",
    "session.authz",
    "task.cancel",
    "task.list_open",
)

# HTTP binding (§7.0).
HEADER_VERSION: str = "X-Dsh-Bridge-Version"
CONTENT_TYPE_JSON: str = "application/json; charset=utf-8"
HEALTH_PATH: str = "/health"
HELLO_PATH: str = "/hello"
FRAMES_PATH: str = "/frames"
POLL_PATH: str = "/poll"
POLL_ACK_PATH: str = "/poll/ack"
PROBE_PATH: str = "/probe"

# Default listener binding (§7.1).
DEFAULT_CONN_PATH: str = "/dsh-bridge"
DEFAULT_LISTEN_PORT: int = 8765

# AstrBot OpenAPI identity (§16.3). The API key channel always authenticates as
# ``api_key:<key_id>``; the bridge MUST use that username for session recovery.
OPENAPI_USERNAME_PREFIX: str = "api_key:"

# Wake guard rails (§16.6).
DEFAULT_WAKE_MAX_CHAIN: int = 8
DEFAULT_WAKE_RATE_PER_MINUTE: int = 10
WAKE_DELIVERY_MAX_ATTEMPTS: int = 3
WAKE_DELIVERY_BACKOFF_S: tuple[int, ...] = (1, 5, 30)

# Session listing (§9.7).
SESSION_STATES: tuple[str, ...] = ("idle", "busy", "cold")
SESSION_ACTIONS: tuple[str, ...] = ("rename", "archive")

# Grant provenance (§9.7).
GRANTED_BY_HUMAN: str = "human"
GRANTED_BY_AGENT_AUTO: str = "agent_auto"

# Output-task direction markers used by the UI and store.
DIRECTION_OUTBOUND: str = "outbound"
DIRECTION_INBOUND: str = "inbound"
