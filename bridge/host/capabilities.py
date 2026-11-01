"""Host capability reporting: local ``caps`` and vision checks (§4.5, §13.5).

Vision support is read from the real provider configuration
(``provider_config["modalities"]``), the same *source* AstrBot reads. The *verdict*
deliberately differs from the host's on unconfigured providers: AstrBot treats a missing
or empty ``modalities`` list as "unconfigured" and keeps accepting images for backward
compatibility (``astr_main_agent._provider_supports_modality`` returns ``True`` for
``[]``; ``tool_loop_agent_runner`` documents the same), whereas this module stays
fail-closed: only an explicit ``"image"`` entry counts. The extra strictness is
intentional and must not be relaxed to match the host's compatibility behaviour, so an
unknown provider never receives an image it may not understand.
"""

from __future__ import annotations

from typing import Any

from astrbot.api import logger

from ..constants import IMAGE_MIME_TYPES
from ..errors import ERR_MODEL_WITHOUT_VISION, BridgeError
from ..session import build_caps


def provider_modalities(provider: Any) -> list[str] | None:
    """Read the modality list from a provider instance.

    Args:
        provider: AstrBot ``Provider`` instance.

    Returns:
        The configured modalities, or ``None`` when unset.
    """
    config = getattr(provider, "provider_config", None)
    if not isinstance(config, dict):
        return None
    modalities = config.get("modalities")
    if modalities is None:
        return None
    if not isinstance(modalities, list):
        return None
    return [str(item) for item in modalities]


def supports_image(provider: Any) -> bool:
    """Whether a provider can accept image input (§13.5).

    Args:
        provider: AstrBot ``Provider`` instance, or ``None`` when unknown.

    Returns:
        ``True`` only when the configuration explicitly lists ``"image"``. Missing,
        empty, or malformed ``modalities`` fails closed to ``False`` (§13.5). This is
        intentionally stricter than the host's backward-compatible "unconfigured means
        accept all" rule.
    """
    if provider is None:
        return False
    modalities = provider_modalities(provider)
    if not modalities:
        return False
    return "image" in modalities


class HostCapabilities:
    """Build the local ``caps`` object and answer capability questions."""

    def __init__(
        self,
        *,
        version: str,
        transports: list[str],
        tls: bool,
        image_enabled: bool = True,
        image_max_count: int = 4,
        image_max_bytes: int = 10_485_760,
        image_total_max_bytes: int = 20_971_520,
        provider_getter: Any = None,
    ) -> None:
        """Create the capability reporter.

        Args:
            version: Local plugin version advertised in ``caps``.
            transports: Carriers this endpoint can actually use.
            tls: Whether TLS is enabled for the connection.
            image_enabled: Whether image attachments are accepted.
            image_max_count: Maximum images per task.
            image_max_bytes: Maximum bytes per image.
            image_total_max_bytes: Maximum bytes per task.
            provider_getter: Callable returning the current chat provider, used for
                vision checks.
        """
        self._version = version
        self._transports = transports
        self._tls = tls
        self._image_enabled = image_enabled
        self._image_max_count = image_max_count
        self._image_max_bytes = image_max_bytes
        self._image_total_max_bytes = image_total_max_bytes
        self._provider_getter = provider_getter

    def caps(self) -> dict:
        """Build the A-side ``caps`` object exactly as §4.5 defines it.

        Returns:
            Capability dictionary. ``approvals.native_tool`` is always ``False`` for A.
        """
        return build_caps(
            side="A",
            host="astrbot",
            version=self._version,
            transports=self._transports,
            tls=self._tls,
            native_tool=False,
            image_enabled=self._image_enabled,
            image_max_count=self._image_max_count,
            image_max_bytes=self._image_max_bytes,
            image_total_max_bytes=self._image_total_max_bytes,
        )

    def allowed_mime(self) -> tuple[str, ...]:
        """Return the MIME whitelist advertised in ``caps``.

        Returns:
            The four image MIME types, ascending.
        """
        return IMAGE_MIME_TYPES

    def current_provider(self) -> Any:
        """Resolve the current chat provider, if any.

        Returns:
            The provider instance or ``None``.
        """
        if self._provider_getter is None:
            return None
        try:
            return self._provider_getter()
        except Exception:
            logger.exception("bridge provider lookup failed")
            return None

    def supports_vision(self, provider: Any = None) -> bool:
        """Whether the effective model accepts images (§13.5).

        Args:
            provider: Optional explicit provider; defaults to the current one.

        Returns:
            ``True`` when images can be sent.
        """
        target = provider if provider is not None else self.current_provider()
        return supports_image(target)

    def require_vision(self, provider: Any = None) -> None:
        """Refuse to send images to a text-only model (§13.5).

        Args:
            provider: Optional explicit provider.

        Raises:
            BridgeError: ``model_without_vision`` so the caller can attach a text
                placeholder instead of silently dropping the image.
        """
        if not self.supports_vision(provider):
            logger.warning("bridge image refused: model has no image modality")
            raise BridgeError(ERR_MODEL_WITHOUT_VISION)


__all__ = [
    "HostCapabilities",
    "provider_modalities",
    "supports_image",
]
