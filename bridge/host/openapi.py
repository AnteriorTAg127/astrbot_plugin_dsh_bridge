"""AstrBot OpenAPI adapter: chat SSE, file upload, IM delivery (§16.3).

Identity facts this module depends on (verified in the AstrBot source):

* With an API key, the server identity is always ``api_key:<key_id>``
  (``astrbot/dashboard/api/auth.py`` + ``astrbot/core/workspace.py``). The ``username``
  in the request body only decides the *creator* of a new session, it is not the
  authenticated identity.
* ``GET /api/v1/chat/sessions`` on the API-key channel requires an explicit
  ``username`` and filters by ``creator``; there is no "list only mine" behaviour.

Therefore the bridge MUST use ``api_key:<openapi_key_id>`` as the username, MUST
verify that the key really belongs to that identity, and MUST NOT use the ``data``
scope or ``chat:admin`` to work around a mismatch (§16.3 rules 2-5).

The API key never leaves this process: it is only put into the ``Authorization``
header of loopback requests and is never logged, stored in task rows, returned to
the peer or rendered in the UI.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import httpx

from astrbot.api import logger

from ..constants import OPENAPI_USERNAME_PREFIX
from ..errors import ERR_CONFIG_INVALID, BridgeError

#: SSE event types emitted by ``POST /api/v1/chat`` (verified in chat_service).
SSE_PLAIN = "plain"
SSE_COMPLETE = "complete"
SSE_END = "end"
SSE_ERROR = "error"
SSE_SESSION_ID = "session_id"
SSE_MESSAGE_SAVED = "message_saved"
SSE_ATTACHMENT_SAVED = "attachment_saved"
SSE_AGENT_STATS = "agent_stats"


def is_loopback(host: str) -> bool:
    """Whether a host name/address is loopback.

    Args:
        host: Host or IP string.

    Returns:
        ``True`` for ``127.0.0.0/8``, ``::1`` and ``localhost``.
    """
    lowered = (host or "").strip().lower()
    if lowered in ("localhost", "::1", "[::1]"):
        return True
    if lowered.startswith("127."):
        return True
    return False


def is_private(host: str) -> bool:
    """Whether a host is a non-loopback private/RFC1918 address.

    Args:
        host: Host or IP string.

    Returns:
        ``True`` for private ranges that require explicit opt-in.
    """
    import ipaddress

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if address.is_loopback:
        return False
    return address.is_private


class OpenApiHost:
    """Thin async client for the local AstrBot OpenAPI."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        key_id: str,
        allow_private_addr: bool = False,
        timeout_s: float = 60.0,
        on_agent_event: Callable[[dict], Awaitable[None]] | None = None,
    ) -> None:
        """Create the adapter.

        Args:
            base_url: ``openapi_base_url`` (loopback by default).
            api_key: ``openapi_api_key``; never logged or serialised.
            key_id: ``openapi_key_id``; the non-secret identity used as ``username``.
            allow_private_addr: Whether a non-loopback private address is allowed.
            timeout_s: Default request timeout.
            on_agent_event: Optional observer for each SSE event (used by the task
                runner to report progress and to surface decision requests).
        """
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._key_id = key_id
        self._allow_private = allow_private_addr
        self._timeout = timeout_s
        self._on_agent_event = on_agent_event
        self._client: httpx.AsyncClient | None = None

    # -- configuration checks ----------------------------------------------------------

    @property
    def username(self) -> str:
        """The only identity the bridge may use (§16.3).

        Returns:
            ``api_key:<key_id>``.
        """
        return f"{OPENAPI_USERNAME_PREFIX}{self._key_id}"

    def umo_for_session(self, session_id: str) -> str:
        """Build the WebChat UMO that owns one OpenAPI task session.

        ``POST /api/v1/chat`` derives the conversation from the body's ``username`` and
        ``session_id``; the webchat adapter then stores
        ``session_id = f"webchat!{username}!{cid}"`` (``webchat_adapter.py``). The UMO
        below is therefore the exact conversation the host used for the run, which lets
        callers ask the host about that session (for example a per-session provider or
        vision capability lookup).

        This is an instance method, not a pure function, because the identity segment
        must be this adapter's ``api_key:<key_id>`` username.

        Args:
            session_id: AstrBot chat session id (from a task row or an SSE
                ``session_id`` event).

        Returns:
            ``webchat:FriendMessage:webchat!<username>!<session_id>``.
        """
        return f"webchat:FriendMessage:webchat!{self.username}!{session_id}"

    def configured(self) -> bool:
        """Whether the adapter has enough configuration to run tasks.

        Returns:
            ``True`` when both the key and its id are present.
        """
        return bool(self._api_key and self._key_id and self._base_url)

    def check_endpoint(self) -> None:
        """Validate that the OpenAPI address is local/private-allowed (§16.3 rule 7).

        Raises:
            BridgeError: ``config_invalid`` when the address is not permitted.
        """
        from urllib.parse import urlparse

        parsed = urlparse(self._base_url)
        host = parsed.hostname or ""
        if is_loopback(host):
            return
        if is_private(host) and self._allow_private:
            return
        logger.error(
            "bridge openapi address rejected host=%s allow_private=%s",
            host,
            self._allow_private,
        )
        raise BridgeError(
            ERR_CONFIG_INVALID, details={"reason": "openapi_addr_not_allowed"}
        )

    async def verify_ownership(self) -> None:
        """Prove that the configured key really maps to ``api_key:<key_id>`` (§16.3 rule 2).

        Calls ``GET /api/v1/chat/sessions?username=api_key:<key_id>`` and checks that
        every returned ``creator`` matches the requested username. A mismatch means the
        configured ``openapi_key_id`` is wrong, so the bridge refuses to run rather than
        fall back to a broader scope.

        Raises:
            BridgeError: ``config_invalid`` when the identity claim cannot be proven, or
                when the key lacks the ``chat`` scope.
        """
        self.check_endpoint()
        if not self.configured():
            raise BridgeError(
                ERR_CONFIG_INVALID, details={"reason": "openapi_not_configured"}
            )
        client = self._http()
        response = await client.get(
            f"{self._base_url}/api/v1/chat/sessions",
            params={"username": self.username, "page": 1, "page_size": 5},
        )
        if response.status_code == 403:
            raise BridgeError(
                ERR_CONFIG_INVALID, details={"reason": "missing_chat_scope"}
            )
        if response.status_code != 200:
            raise BridgeError(
                ERR_CONFIG_INVALID,
                details={
                    "reason": "ownership_probe_failed",
                    "status": response.status_code,
                },
            )
        body = _unwrap(response.json())
        sessions = body.get("sessions") if isinstance(body, dict) else None
        if not isinstance(sessions, list):
            raise BridgeError(
                ERR_CONFIG_INVALID, details={"reason": "ownership_probe_shape"}
            )
        for session in sessions:
            creator = str((session or {}).get("creator", ""))
            if creator and creator != self.username:
                logger.error(
                    "bridge openapi ownership mismatch expected=%s got=%s",
                    self.username,
                    creator,
                )
                raise BridgeError(
                    ERR_CONFIG_INVALID, details={"reason": "openapi_identity_mismatch"}
                )
        logger.info("bridge openapi identity verified username=%s", self.username)

    def _http(self) -> httpx.AsyncClient:
        """Return the shared HTTP client.

        Returns:
            An ``httpx.AsyncClient`` carrying only the loopback API key.
        """
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=self._timeout,
                headers={"Authorization": f"Bearer {self._api_key}"},
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        client = self._client
        self._client = None
        if client is not None:
            await client.aclose()

    # -- chat --------------------------------------------------------------------------

    async def run_agent(
        self,
        *,
        parts: list[dict],
        session_id: str | None = None,
        on_text: Callable[[str], None] | None = None,
    ) -> dict:
        """Drive one AstrBot Agent run over ``POST /api/v1/chat`` SSE (§6.8).

        Args:
            parts: Message parts (``plain``/``image``) built from the task input.
            session_id: Session to continue, or ``None`` to create one.
            on_text: Optional callback invoked with each plain text delta.

        Returns:
            ``{"text", "session_id", "events", "attachments"}``.

        Raises:
            BridgeError: ``config_invalid`` when unconfigured, or the upstream error
                converted from the SSE ``error`` event.
        """
        if not self.configured():
            raise BridgeError(
                ERR_CONFIG_INVALID, details={"reason": "openapi_not_configured"}
            )
        payload: dict[str, Any] = {
            "username": self.username,
            "message": parts,
            "enable_streaming": True,
        }
        if session_id:
            payload["session_id"] = session_id
        collected: list[str] = []
        events: list[dict] = []
        attachments: list[dict] = []
        resolved_session = session_id
        error_text: str | None = None

        client = self._http()
        async with client.stream(
            "POST", f"{self._base_url}/api/v1/chat", json=payload
        ) as response:
            if response.status_code != 200:
                detail = await _read_small(response)
                logger.error(
                    "bridge openapi chat failed status=%s detail=%s",
                    response.status_code,
                    detail[:200],
                )
                raise BridgeError(
                    ERR_CONFIG_INVALID,
                    details={
                        "reason": "chat_request_failed",
                        "status": response.status_code,
                    },
                )
            async for event in _iter_sse(response):
                if self._on_agent_event is not None:
                    try:
                        await self._on_agent_event(event)
                    except Exception:
                        logger.exception("bridge agent event observer failed")
                events.append(event)
                kind = event.get("type")
                data = event.get("data")
                if kind == SSE_SESSION_ID and isinstance(event.get("session_id"), str):
                    resolved_session = event["session_id"]
                elif kind == SSE_PLAIN and isinstance(data, str):
                    collected.append(data)
                    if on_text is not None:
                        on_text(data)
                elif kind == SSE_ATTACHMENT_SAVED and isinstance(data, dict):
                    attachments.append(data)
                elif kind == SSE_ERROR:
                    error_text = str(data)
                elif kind == SSE_END:
                    break
        if error_text is not None:
            raise BridgeError("internal_error", message="agent run failed")
        return {
            "text": "".join(collected),
            "session_id": resolved_session,
            "events": events,
            "attachments": attachments,
        }

    async def list_sessions(self, *, page: int = 1, page_size: int = 20) -> dict:
        """List sessions created by this key's identity (§16.3 rule 1).

        Args:
            page: Page number.
            page_size: Page size.

        Returns:
            The unwrapped response body.
        """
        client = self._http()
        response = await client.get(
            f"{self._base_url}/api/v1/chat/sessions",
            params={"username": self.username, "page": page, "page_size": page_size},
        )
        response.raise_for_status()
        return _unwrap(response.json())

    # -- files -------------------------------------------------------------------------

    async def upload_image(self, data: bytes, mime: str, name: str) -> str:
        """Upload an image and return its ``attachment_id`` (§13.1 source 2).

        Args:
            data: Raw image bytes.
            mime: MIME type.
            name: File name hinted to the host.

        Returns:
            The ``attachment_id`` to reference from a chat ``image`` part.

        Raises:
            BridgeError: When the upload fails or no id is returned.
        """
        if not self.configured():
            raise BridgeError(
                ERR_CONFIG_INVALID, details={"reason": "openapi_not_configured"}
            )
        client = self._http()
        files = {"file": (name or "image", data, mime)}
        response = await client.post(f"{self._base_url}/api/v1/file", files=files)
        if response.status_code != 200:
            logger.error("bridge openapi upload failed status=%s", response.status_code)
            raise BridgeError(ERR_CONFIG_INVALID, details={"reason": "upload_failed"})
        body = _unwrap(response.json())
        attachment_id = (body or {}).get("attachment_id")
        if not isinstance(attachment_id, str) or not attachment_id:
            raise BridgeError(
                ERR_CONFIG_INVALID, details={"reason": "upload_no_attachment_id"}
            )
        return attachment_id

    # -- IM ----------------------------------------------------------------------------

    async def send_im(self, umo: str, parts: list[dict]) -> None:
        """Send an active IM message by UMO (§6.9 approval notifications).

        Args:
            umo: ``unified_msg_origin`` of the target conversation.
            parts: Message parts.

        Raises:
            BridgeError: When the host refuses the message.
        """
        if not self.configured():
            raise BridgeError(
                ERR_CONFIG_INVALID, details={"reason": "openapi_not_configured"}
            )
        client = self._http()
        response = await client.post(
            f"{self._base_url}/api/v1/im/messages",
            json={"umo": umo, "message": parts},
        )
        if response.status_code != 200:
            raise BridgeError(ERR_CONFIG_INVALID, details={"reason": "im_send_failed"})


def _unwrap(body: Any) -> Any:
    """Unwrap the ``{"status":"ok","data":…}`` envelope used by the dashboard API.

    Args:
        body: Decoded JSON body.

    Returns:
        The ``data`` payload when the envelope is present, otherwise the body.
    """
    if isinstance(body, dict) and body.get("status") == "ok" and "data" in body:
        return body["data"]
    return body


async def _read_small(response: Any) -> str:
    """Read a short error body without leaking it into logs.

    Args:
        response: httpx streaming response.

    Returns:
        Up to 512 characters of the body text.
    """
    try:
        text = await response.aread()
    except Exception:
        return ""
    return text.decode("utf-8", "ignore")[:512]


async def _iter_sse(response: Any) -> AsyncIterator[dict]:
    """Parse an SSE stream into JSON event objects (§6.3.1).

    Lines starting with ``:`` are heartbeats and are ignored; a line starting with
    ``data:`` carries one JSON object.

    Args:
        response: httpx streaming response.

    Yields:
        Decoded event dictionaries; non-JSON payloads are wrapped as ``raw`` events.
    """
    async for line in response.aiter_lines():
        if not line or line.startswith(":"):
            continue
        if not line.startswith("data:"):
            continue
        raw = line[5:].strip()
        if not raw:
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            yield {"type": "raw", "data": raw[:512]}
            continue
        if isinstance(event, dict):
            yield event


def build_message_parts(
    text_parts: list[str], attachment_ids: list[str] | None = None
) -> list[dict]:
    """Build the OpenAPI ``message`` array from task inputs (§6.8, §13).

    Args:
        text_parts: Plain text segments.
        attachment_ids: Already-uploaded image attachment ids.

    Returns:
        Array of ``plain`` and ``image`` parts.
    """
    parts: list[dict] = [{"type": "plain", "text": text} for text in text_parts if text]
    for attachment_id in attachment_ids or []:
        parts.append({"type": "image", "attachment_id": attachment_id})
    if not parts:
        parts.append({"type": "plain", "text": ""})
    return parts


__all__ = [
    "OpenApiHost",
    "SSE_AGENT_STATS",
    "SSE_ATTACHMENT_SAVED",
    "SSE_COMPLETE",
    "SSE_END",
    "SSE_ERROR",
    "SSE_MESSAGE_SAVED",
    "SSE_PLAIN",
    "SSE_SESSION_ID",
    "build_message_parts",
    "is_loopback",
    "is_private",
]
