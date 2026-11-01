"""Transport abstraction shared by WS, webhook and long-poll (§1.1, §7).

The transport layer only moves bytes: it never imports ``bridge.app``/``bridge.host``
and never interprets message names. It sees exactly two things — plaintext
handshake objects and sealed envelopes.
"""

from __future__ import annotations

import abc
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from ..constants import DEFAULT_LISTEN_PORT, MAX_BATCH_FRAMES
from ..errors import ERR_BAD_BATCH, ERR_BAD_JSON, ERR_FRAME_TOO_LARGE, BridgeError


@dataclass
class TransportHooks:
    """Callbacks the transport invokes when bytes arrive.

    Attributes:
        on_plain: Receives a plaintext handshake object and returns the response
            object (``hello`` → ``hello_ack``), or ``None`` when no reply is due.
        on_envelope: Receives one raw envelope. The session decrypts and validates it.
        on_probe: Receives a webhook probe object and returns ``probe_ack`` (§7.3).
        on_state: Receives ``(state, reason)`` for status reporting.
        on_activity: Called whenever bytes arrive, feeding the shared liveness clock.
    """

    on_plain: Callable[[dict], Awaitable[dict | None]]
    on_envelope: Callable[[dict], Awaitable[None]]
    on_probe: Callable[[dict], Awaitable[dict]]
    on_state: Callable[[str, str], None]
    on_activity: Callable[[], None] | None = None

    def activity(self) -> None:
        """Record inbound activity if a listener is configured."""
        if self.on_activity is not None:
            self.on_activity()


class Transport(abc.ABC):
    """Common interface for the three carriers (§7.1)."""

    name: str = "base"

    @abc.abstractmethod
    async def start(self, cfg: Any, hooks: TransportHooks) -> None:
        """Bring the carrier up.

        Args:
            cfg: :class:`bridge.session.SessionConfig`-shaped configuration.
            hooks: Inbound callbacks.
        """

    @abc.abstractmethod
    async def stop(self) -> None:
        """Tear the carrier down and release sockets/sessions."""

    @abc.abstractmethod
    async def send_envelope(self, env: dict) -> None:
        """Deliver one sealed envelope.

        Args:
            env: Envelope object (``{"v","type","conn","seq","ct"}``).
        """

    @abc.abstractmethod
    async def send_plain(self, obj: dict) -> dict | None:
        """Send a plaintext handshake object and return the peer's reply.

        Args:
            obj: ``hello`` object.

        Returns:
            The peer's ``hello_ack`` when the carrier is synchronous (webhook /
            long-poll / WS client), or ``None``.
        """

    @abc.abstractmethod
    def alive(self) -> bool:
        """Whether the carrier currently believes the link is usable."""

    async def wait_ready(self, timeout_s: float) -> None:
        """Wait until the carrier is ready to carry envelopes.

        Args:
            timeout_s: Maximum wait.

        Raises:
            TimeoutError: When the carrier never becomes ready.
        """
        return None

    def diagnostics(self) -> dict:
        """Return a small dictionary for the status page.

        Returns:
            Carrier-specific diagnostics with no secret material.
        """
        return {"name": self.name, "alive": self.alive()}


def bind_target(cfg: Any) -> tuple[str, int]:
    """Resolve the address an inbound HTTP endpoint binds to (§7.1).

    The bind address is *always* local: only ``bind_addr``/``bind_port`` name it.
    A ``connect`` endpoint that does not configure an explicit bind port gets an
    ephemeral one (``0``) instead of falling back to the peer port — binding the
    peer's port would collide with the peer's own listener, or silently make the
    endpoint talk to itself.

    Args:
        cfg: Session configuration.

    Returns:
        ``(host, port)``; ``port`` is ``0`` when the kernel should choose one.
    """
    host = (
        getattr(cfg, "listen_host", None)
        or getattr(cfg, "host", "127.0.0.1")
        or "127.0.0.1"
    )
    explicit = int(getattr(cfg, "bind_port", 0) or 0)
    if explicit > 0:
        return host, explicit
    if getattr(cfg, "mode", "connect") == "listen":
        return host, int(getattr(cfg, "listen_port", None) or DEFAULT_LISTEN_PORT)
    return host, 0


def parse_frames_batch(raw: bytes, max_batch_bytes: int) -> dict:
    """Validate an inbound batch object (§7.3 rule 3) without interpreting frames.

    Both HTTP carriers share this: a malformed batch must be refused identically
    (400 with a §15 code), and the size/frame caps must never drift apart.

    Args:
        raw: Raw request body.
        max_batch_bytes: Maximum accepted body size.

    Returns:
        The parsed batch object with a validated ``frames`` array.

    Raises:
        BridgeError: ``frame_too_large``, ``bad_json`` or ``bad_batch``.
    """
    if len(raw) > max_batch_bytes:
        raise BridgeError(ERR_FRAME_TOO_LARGE)
    try:
        batch = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BridgeError(ERR_BAD_JSON) from exc
    if not isinstance(batch, dict):
        raise BridgeError(ERR_BAD_BATCH)
    frames = batch.get("frames")
    if not isinstance(frames, list) or not frames:
        raise BridgeError(ERR_BAD_BATCH)
    if len(frames) > MAX_BATCH_FRAMES:
        raise BridgeError(ERR_BAD_BATCH)
    seqs: list[int] = []
    for frame in frames:
        seq = frame.get("seq") if isinstance(frame, dict) else None
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise BridgeError(ERR_BAD_BATCH)
        seqs.append(seq)
    if seqs != sorted(seqs):
        raise BridgeError(ERR_BAD_BATCH)
    return batch


def peer_base_url(cfg: Any, *, scheme: str | None = None) -> str:
    """Build the peer base URL for outbound HTTP carriers.

    Args:
        cfg: Session configuration (``host``/``port``/``path``/``tls``).
        scheme: Override for the URL scheme.

    Returns:
        ``scheme://host:port/path`` without a trailing slash.
    """
    host = getattr(cfg, "host", "127.0.0.1")
    port = getattr(cfg, "port", 8765)
    path = getattr(cfg, "path", "/dsh-bridge") or ""
    tls = bool(getattr(cfg, "tls_enabled", False))
    if scheme is None:
        scheme = "https" if tls else "http"
    if path and not path.startswith("/"):
        path = f"/{path}"
    path = path.rstrip("/")
    return f"{scheme}://{host}:{port}{path}"


__all__ = [
    "Transport",
    "TransportHooks",
    "bind_target",
    "parse_frames_batch",
    "peer_base_url",
]
