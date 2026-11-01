"""Error codes and the ``BridgeError`` exception used across the bridge.

The code vocabulary is closed (protocol §15). New codes MUST be added to the
shared protocol document on both ends first; never invent a synonym locally.
"""

from __future__ import annotations

from typing import Any

# --- Handshake / security (§15.1) -------------------------------------------------

ERR_PSK_NOT_CONFIGURED = "psk_not_configured"
ERR_PSK_MISMATCH = "psk_mismatch"
ERR_TH_MISMATCH = "th_mismatch"
ERR_AEAD_FAILED = "aead_failed"
ERR_REPLAY_DETECTED = "replay_detected"
ERR_REPLAY_OUT_OF_WINDOW = "replay_out_of_window"
ERR_HELLO_REPLAY = "hello_replay"
ERR_HANDSHAKE_REUSE = "handshake_reuse"
ERR_STALE_SESSION = "stale_session"
ERR_DUAL_WRITER = "dual_writer"
ERR_SID_MISMATCH = "sid_mismatch"
ERR_AUTH_REQUIRED = "auth_required"
ERR_POLL_AUTH_FAILED = "poll_auth_failed"
ERR_AUTH_HEADER_FORBIDDEN = "auth_header_forbidden"
ERR_BAD_VERSION = "bad_version"
ERR_SUBPROTOCOL_MISMATCH = "subprotocol_mismatch"
ERR_BAD_HANDSHAKE_ENCODING = "bad_handshake_encoding"
ERR_BAD_CAPS = "bad_caps"
ERR_BAD_SIDE = "bad_side"
ERR_UNKNOWN_CONN = "unknown_conn"
ERR_RATE_LIMITED = "rate_limited"
ERR_HELLO_EXPIRED = "hello_expired"

# --- Protocol / transport (§15.2) -------------------------------------------------

ERR_BAD_JSON = "bad_json"
ERR_BAD_FRAME = "bad_frame"
ERR_BAD_BATCH = "bad_batch"
ERR_FRAME_TOO_LARGE = "frame_too_large"
ERR_UNSUPPORTED_CONTENT_TYPE = "unsupported_content_type"
ERR_UNKNOWN_MESSAGE = "unknown_message"
ERR_BAD_PARAMS = "bad_params"
ERR_UNKNOWN_MESSAGE_KIND = "unknown_message_kind"
ERR_ORPHAN_REPLY = "orphan_reply"
ERR_TIMEOUT = "timeout"
ERR_NOT_READY = "not_ready"
ERR_DRAINING = "draining"
ERR_SERVER_BUSY = "server_busy"
ERR_INTERNAL_ERROR = "internal_error"
ERR_CONFIG_INVALID = "config_invalid"
ERR_CAPABILITY_UNAVAILABLE = "capability_unavailable"

# --- Business (§15.3) -------------------------------------------------------------

ERR_TASK_NOT_FOUND = "task_not_found"
ERR_TASK_EXISTS = "task_exists"
ERR_TASK_TIMEOUT = "task_timeout"
ERR_TASK_CANCEL_UNSUPPORTED = "task_cancel_unsupported"
ERR_SESSION_NOT_AUTHORIZED = "session_not_authorized"
ERR_SESSION_QUOTA_EXCEEDED = "session_quota_exceeded"
ERR_SESSION_CREATE_DENIED = "session_create_denied"
ERR_SESSION_NOT_FOUND = "session_not_found"
ERR_SESSION_ARCHIVED = "session_archived"
ERR_AGENT_CANNOT_APPROVE = "agent_cannot_approve"
ERR_AGENT_CANNOT_DECIDE = "agent_cannot_decide"
ERR_APPROVAL_EXPIRED = "approval_expired"
ERR_APPROVAL_MISMATCH = "approval_mismatch"
ERR_APPROVAL_DIGEST_MISMATCH = "approval_digest_mismatch"
ERR_APPROVAL_ALREADY_DECIDED = "approval_already_decided"
ERR_APPROVAL_EVIDENCE_MISSING = "approval_evidence_missing"
ERR_APPROVAL_LOOKUP_FAILED = "approval_lookup_failed"
ERR_DECISION_TIMEOUT = "decision_timeout"
ERR_ATTACHMENT_TYPE_DENIED = "attachment_type_denied"
ERR_ATTACHMENT_TOO_LARGE = "attachment_too_large"
ERR_ATTACHMENT_COUNT_EXCEEDED = "attachment_count_exceeded"
ERR_ATTACHMENT_PIXELS_EXCEEDED = "attachment_pixels_exceeded"
ERR_ATTACHMENT_BYTES_MISMATCH = "attachment_bytes_mismatch"
ERR_ATTACHMENT_INVALID = "attachment_invalid"
ERR_ATTACHMENT_NOT_FOUND = "attachment_not_found"
ERR_ATTACHMENT_META_MISMATCH = "attachment_meta_mismatch"
ERR_ATTACHMENT_SOURCE_DENIED = "attachment_source_denied"
ERR_MODEL_WITHOUT_VISION = "model_without_vision"
ERR_BLOB_INCOMPLETE = "blob_incomplete"
ERR_BLOB_NOT_FOUND = "blob_not_found"
ERR_EVENT_NOT_FOUND = "event_not_found"
ERR_WAKE_CHAIN_EXCEEDED = "wake_chain_exceeded"
ERR_WAKE_RATE_LIMITED = "wake_rate_limited"
ERR_NEEDS_HUMAN = "needs_human"

#: Errors that MUST tear the session down (§15.1). Anything else is reported as a
#: normal ``rep{ok:false}`` without dropping the connection.
FATAL_CODES: frozenset[str] = frozenset(
    {
        ERR_PSK_MISMATCH,
        ERR_TH_MISMATCH,
        ERR_AEAD_FAILED,
        ERR_REPLAY_DETECTED,
        ERR_REPLAY_OUT_OF_WINDOW,
        ERR_HELLO_REPLAY,
        ERR_HANDSHAKE_REUSE,
        ERR_STALE_SESSION,
        ERR_DUAL_WRITER,
        ERR_AUTH_REQUIRED,
        ERR_SUBPROTOCOL_MISMATCH,
        ERR_BAD_HANDSHAKE_ENCODING,
    }
)

#: Fixed English sentences for the HTTP error body (§8.2). Never interpolate
#: peer input into these; never echo ciphertext, MACs, digests or paths.
ERROR_MESSAGES: dict[str, str] = {
    ERR_PSK_NOT_CONFIGURED: "pre-shared key not configured",
    ERR_PSK_MISMATCH: "authentication failed",
    ERR_TH_MISMATCH: "authentication failed",
    ERR_AEAD_FAILED: "frame authentication failed",
    ERR_REPLAY_DETECTED: "replay detected",
    ERR_REPLAY_OUT_OF_WINDOW: "replay detected",
    ERR_HELLO_REPLAY: "replay detected",
    ERR_HANDSHAKE_REUSE: "handshake rejected",
    ERR_STALE_SESSION: "session expired",
    ERR_DUAL_WRITER: "session expired",
    ERR_SID_MISMATCH: "session mismatch",
    ERR_AUTH_REQUIRED: "authentication required",
    ERR_POLL_AUTH_FAILED: "authentication failed",
    ERR_AUTH_HEADER_FORBIDDEN: "forced header present",
    ERR_BAD_VERSION: "protocol version unsupported",
    ERR_SUBPROTOCOL_MISMATCH: "subprotocol unsupported",
    ERR_BAD_HANDSHAKE_ENCODING: "malformed handshake",
    ERR_BAD_CAPS: "malformed capabilities",
    ERR_BAD_SIDE: "unexpected peer side",
    ERR_UNKNOWN_CONN: "unknown connection",
    ERR_RATE_LIMITED: "too many attempts",
    ERR_HELLO_EXPIRED: "handshake expired",
    ERR_BAD_JSON: "malformed request body",
    ERR_BAD_FRAME: "malformed frame",
    ERR_BAD_BATCH: "malformed frame batch",
    ERR_FRAME_TOO_LARGE: "frame too large",
    ERR_UNSUPPORTED_CONTENT_TYPE: "unsupported content type",
    ERR_UNKNOWN_MESSAGE: "unknown message",
    ERR_BAD_PARAMS: "invalid parameters",
    ERR_UNKNOWN_MESSAGE_KIND: "invalid message kind",
    ERR_ORPHAN_REPLY: "unmatched reply",
    ERR_TIMEOUT: "request timed out",
    ERR_NOT_READY: "session not ready",
    ERR_DRAINING: "shutting down",
    ERR_SERVER_BUSY: "server busy",
    ERR_INTERNAL_ERROR: "internal error",
    ERR_CONFIG_INVALID: "configuration invalid",
    ERR_CAPABILITY_UNAVAILABLE: "capability unavailable",
    ERR_TASK_NOT_FOUND: "unknown task",
    ERR_TASK_EXISTS: "conflicting task parameters",
    ERR_TASK_TIMEOUT: "task timed out",
    ERR_TASK_CANCEL_UNSUPPORTED: "cancel not supported",
    ERR_SESSION_NOT_AUTHORIZED: "session not authorized",
    ERR_SESSION_QUOTA_EXCEEDED: "session quota exceeded",
    ERR_SESSION_CREATE_DENIED: "session creation denied",
    ERR_SESSION_NOT_FOUND: "unknown session",
    ERR_SESSION_ARCHIVED: "session archived",
    ERR_AGENT_CANNOT_APPROVE: "approval requires a human",
    ERR_AGENT_CANNOT_DECIDE: "decision requires a human",
    ERR_APPROVAL_EXPIRED: "approval expired",
    ERR_APPROVAL_MISMATCH: "approval does not match",
    ERR_APPROVAL_DIGEST_MISMATCH: "approval does not match submission",
    ERR_APPROVAL_ALREADY_DECIDED: "approval already decided",
    ERR_APPROVAL_EVIDENCE_MISSING: "approval evidence missing",
    ERR_APPROVAL_LOOKUP_FAILED: "approval lookup failed",
    ERR_DECISION_TIMEOUT: "decision timed out",
    ERR_ATTACHMENT_TYPE_DENIED: "attachment type not allowed",
    ERR_ATTACHMENT_TOO_LARGE: "attachment too large",
    ERR_ATTACHMENT_COUNT_EXCEEDED: "too many attachments",
    ERR_ATTACHMENT_PIXELS_EXCEEDED: "attachment dimensions too large",
    ERR_ATTACHMENT_BYTES_MISMATCH: "attachment content does not match",
    ERR_ATTACHMENT_INVALID: "attachment invalid",
    ERR_ATTACHMENT_NOT_FOUND: "attachment not found",
    ERR_ATTACHMENT_META_MISMATCH: "attachment metadata mismatch",
    ERR_ATTACHMENT_SOURCE_DENIED: "attachment source not allowed",
    ERR_MODEL_WITHOUT_VISION: "model has no image capability",
    ERR_BLOB_INCOMPLETE: "attachment incomplete",
    ERR_BLOB_NOT_FOUND: "attachment not found",
    ERR_EVENT_NOT_FOUND: "unknown notification",
    ERR_WAKE_CHAIN_EXCEEDED: "wake chain limit reached",
    ERR_WAKE_RATE_LIMITED: "wake rate limited",
    ERR_NEEDS_HUMAN: "manual intervention required",
}


def error_message(code: str) -> str:
    """Return the fixed English sentence for ``code``.

    Args:
        code: Protocol error code.

    Returns:
        Fixed, non-interpolated English message; ``internal_error`` when the code
        is not part of the closed vocabulary.
    """
    return ERROR_MESSAGES.get(code, ERROR_MESSAGES[ERR_INTERNAL_ERROR])


class BridgeError(Exception):
    """Structured protocol error carrying a §15 code.

    Attributes:
        code: One of the ``ERR_*`` constants.
        details: Optional structured details. Must stay free of secrets.
        fatal: Whether the session must be torn down.
    """

    def __init__(
        self,
        code: str,
        message: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Initialise the error.

        Args:
            code: Protocol error code from §15.
            message: Optional override; defaults to the fixed English sentence.
            details: Optional non-secret structured details.
        """
        self.code = code
        self.message = message or error_message(code)
        self.details = details
        super().__init__(f"{code}: {self.message}")

    @property
    def fatal(self) -> bool:
        """Whether the session must be dropped for this error."""
        return self.code in FATAL_CODES

    def to_payload(self) -> dict[str, Any]:
        """Render the protocol ``error`` object used inside a ``rep``.

        Returns:
            ``{"code", "message", "details"}`` with ``details`` possibly ``None``.
        """
        return {"code": self.code, "message": self.message, "details": self.details}


def http_error_body(code: str) -> dict[str, Any]:
    """Build the plaintext HTTP error envelope (§8.2).

    Args:
        code: Protocol error code.

    Returns:
        ``{"v": 1, "error": {"code", "message", "retryable"}}``.
    """
    retryable = code in {
        ERR_TIMEOUT,
        ERR_RATE_LIMITED,
        ERR_DRAINING,
        ERR_SERVER_BUSY,
        ERR_NOT_READY,
        ERR_INTERNAL_ERROR,
    }
    return {
        "v": 1,
        "error": {"code": code, "message": error_message(code), "retryable": retryable},
    }
