"""AstrBot platform adapter: UMO resolution, active messages and image extraction.

Two responsibilities:

1. **Wake delivery.** Completion/failure/decision/approval notifications must reach the
   conversation that started the task (§16.6). This module turns a stored UMO plus a
   text summary into an actual message. Delivery returns the host's own verdict, and
   ``can_send`` answers reachability (platform instance registered) without sending.
2. **Image sourcing.** Only two sources are legal (§13.1): local bytes from a message
   component, or an already-authorized attachment id. This module never fetches a URL.

Everything here is best-effort with structured English logging: a missing platform must
degrade the notification, not crash the bridge.
"""

from __future__ import annotations

import base64
import contextlib
from typing import Any

import astrbot.api.message_components as Comp
from astrbot.api import logger
from astrbot.api.event import MessageChain
from astrbot.core.platform.message_session import MessageSesion

from ..errors import ERR_ATTACHMENT_SOURCE_DENIED, BridgeError


class PlatformHost:
    """Bridge between the protocol's UMO-based wake model and AstrBot platforms."""

    def __init__(self, context: Any, *, default_platform_id: str = "") -> None:
        """Create the adapter.

        Args:
            context: AstrBot ``Context`` used to resolve platform instances and to send
                active messages.
            default_platform_id: Platform id used when a UMO does not identify one.
        """
        self._context = context
        self._default_platform_id = default_platform_id

    def platform_inst(self, platform_id: str | None) -> Any:
        """Resolve a platform instance by id.

        Args:
            platform_id: Platform instance id, or ``None`` for the default.

        Returns:
            The platform instance, or ``None`` when unavailable.
        """
        target = platform_id or self._default_platform_id
        if not target:
            return None
        try:
            return self._context.get_platform_inst(target)
        except Exception:
            logger.exception("bridge platform lookup failed id=%s", target)
            return None

    async def send_text(self, umo: str, text: str) -> bool:
        """Send one plain text active message to a conversation (§16.6).

        Args:
            umo: ``unified_msg_origin`` of the target conversation.
            text: Message body (already clipped by the caller).

        Returns:
            The host verdict: ``True`` only when ``Context.send_message`` found the
            matching platform and reported success. A malformed UMO makes the host
            raise ``ValueError``; like any other delivery error it is logged and
            reported as ``False`` so the caller never records an undelivered wake.
        """
        if not umo:
            logger.warning("bridge wake skipped: empty umo")
            return False
        try:
            chain = MessageChain().message(text)
            # The host contract is a boolean platform verdict: bare ``bool`` keeps a
            # lenient double honest too, but an unconfirmed send is never delivery.
            return bool(await self._context.send_message(umo, chain))
        except Exception:
            logger.warning("bridge wake delivery failed umo=%s", umo)
            return False

    def can_send(self, umo: str) -> bool:
        """Whether the host can deliver an active message to a conversation.

        A UMO addresses a platform by its ``platform_id`` (the first segment, verified
        against ``Platform.meta().id`` by ``Context.send_message``), so an active
        message can only be delivered when that instance is currently registered. This
        is a pure lookup with no I/O, hence synchronous like ``platform_inst``: it never
        sends anything and never falls back to the default platform, because that would
        make delivery diverge from ``Context.send_message``.

        Args:
            umo: ``unified_msg_origin`` of the target conversation.

        Returns:
            ``True`` only for a well-formed UMO whose platform id is registered.
        """
        if not umo:
            return False
        try:
            session = MessageSesion.from_str(umo)
        except Exception:
            logger.warning("bridge can_send rejected malformed umo=%s", umo)
            return False
        if not session.platform_id:
            logger.warning("bridge can_send rejected umo without platform id")
            return False
        return self.platform_inst(session.platform_id) is not None

    async def send_chain(self, umo: str, parts: list[dict]) -> bool:
        """Send a mixed message built from protocol-style parts.

        Args:
            umo: Target conversation.
            parts: ``[{"type": "plain", "text": ...}]`` or image references.

        Returns:
            ``True`` only when ``Context.send_message`` accepted the message.
        """
        if not umo:
            return False
        chain = MessageChain()
        for part in parts:
            kind = part.get("type")
            if kind == "plain":
                chain.message(str(part.get("text", "")))
            elif kind == "image_path":
                with contextlib.suppress(Exception):
                    chain.file_image(str(part.get("path", "")))
            elif kind == "image_url":
                # Only local file paths are ever forwarded (§13.1); a URL part is a bug.
                logger.warning("bridge refused to forward an image URL part")
        try:
            return bool(await self._context.send_message(umo, chain))
        except Exception:
            logger.warning("bridge chain delivery failed umo=%s", umo)
            return False

    def extract_image_bytes(self, component: Any) -> tuple[bytes, str]:
        """Extract bytes from a message ``Image`` component (§13.1 source 1).

        Args:
            component: ``astrbot.api.message_components.Image`` instance.

        Returns:
            ``(bytes, mime)``.

        Raises:
            BridgeError: ``attachment_source_denied`` when the component only carries a
                remote URL, because fetching arbitrary URLs is forbidden.
        """
        if not isinstance(component, Comp.Image):
            raise BridgeError(
                ERR_ATTACHMENT_SOURCE_DENIED, details={"reason": "not_image"}
            )
        path = ""
        with contextlib.suppress(Exception):
            path = component.convert_to_file_path()
        if path:
            from pathlib import Path

            data = Path(path).read_bytes()
            return data, _guess_mime(data)
        encoded = ""
        with contextlib.suppress(Exception):
            encoded = component.convert_to_base64()
        if encoded:
            payload = encoded.split(",", 1)[-1]
            data = base64.b64decode(payload)
            return data, _guess_mime(data)
        # Only a URL remains: refuse rather than fetch it (SSRF / latency / policy).
        logger.warning("bridge refused image with remote URL only")
        raise BridgeError(ERR_ATTACHMENT_SOURCE_DENIED, details={"reason": "url_only"})

    def umo_for_platform_session(
        self, platform_id: str, session_id: str, *, is_group: bool, sender_id: str
    ) -> str:
        """Build a UMO for a platform session discovered through the OpenAPI.

        Args:
            platform_id: Platform adapter name/id.
            session_id: Platform session id.
            is_group: Whether the session is a group chat.
            sender_id: Sender/creator id used for the friend segment.

        Returns:
            The ``unified_msg_origin`` string.
        """
        message_type = "GroupMessage" if is_group else "FriendMessage"
        return f"{platform_id}:{message_type}:{session_id}"


def _guess_mime(data: bytes) -> str:
    """Detect the MIME type of image bytes.

    Args:
        data: Raw bytes.

    Returns:
        One of the whitelisted image MIME types.
    """
    from ..app.blobs import sniff_image_mime

    return sniff_image_mime(data) or "application/octet-stream"


__all__ = ["PlatformHost"]
