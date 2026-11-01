"""Shared fixtures for the app-layer tests (store, notify, tasks, approvals, blobs)."""

from __future__ import annotations

import struct
import zlib

import pytest

from bridge.app.notify import NotifyService
from bridge.app.sessions import SessionService
from bridge.store import Store


@pytest.fixture
async def store(tmp_path):
    """Open a throwaway SQLite store.

    Args:
        tmp_path: pytest temporary directory.

    Yields:
        An initialised :class:`bridge.store.Store`.
    """
    instance = Store()
    await instance.init(tmp_path / "plugin_data" / "bridge.db")
    try:
        yield instance
    finally:
        await instance.close()


class RecordingSender:
    """Capture ``task.event`` parameters instead of touching a socket."""

    def __init__(self) -> None:
        """Create an empty recorder."""
        self.events: list[dict] = []
        self.fail_next: bool = False

    async def __call__(self, params: dict) -> None:
        """Record one event, optionally simulating a send failure.

        Args:
            params: ``task.event`` parameters.

        Raises:
            RuntimeError: When ``fail_next`` is set (one shot).
        """
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("simulated transport failure")
        self.events.append(params)


@pytest.fixture
def sender():
    """Provide a :class:`RecordingSender`."""
    return RecordingSender()


@pytest.fixture
async def notify(store, sender):
    """Provide a :class:`bridge.app.notify.NotifyService` wired to the recorder.

    Args:
        store: Store fixture.
        sender: Recording sender fixture.

    Returns:
        The service.
    """
    return NotifyService(
        store,
        conn="default",
        wake_max_chain=8,
        wake_rate_per_minute=10,
        on_task_event=sender,
    )


@pytest.fixture
async def sessions(store):
    """Provide a :class:`bridge.app.sessions.SessionService`.

    Args:
        store: Store fixture.

    Returns:
        The service.
    """
    service = SessionService(
        store, conn="default", allow_agent_create=True, max_agent_sessions=10
    )
    await service.init()
    return service


def make_png(width: int = 1, height: int = 1) -> bytes:
    """Build a minimal valid PNG of the requested size.

    Args:
        width: Image width in pixels.
        height: Image height in pixels.

    Returns:
        PNG bytes.
    """

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + tag
            + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    raw = b"".join(b"\x00" + b"\x00\x00\x00\x00" * width for _ in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def make_gif(width: int = 1, height: int = 1) -> bytes:
    """Build a minimal GIF89a header plus screen descriptor.

    Args:
        width: Image width.
        height: Image height.

    Returns:
        GIF bytes (enough for magic and dimension checks).
    """
    return b"GIF89a" + struct.pack("<HH", width, height) + b"\x00\x00\x00;"


def make_jpeg(width: int = 1, height: int = 1) -> bytes:
    """Build a minimal JPEG with a SOF0 segment.

    Args:
        width: Image width.
        height: Image height.

    Returns:
        JPEG bytes (header-only fixture).
    """
    sof = struct.pack(">HH", height, width) + b"\x01\x01\x11\x00"
    return (
        b"\xff\xd8"
        + b"\xff\xe0"
        + struct.pack(">H", 16)
        + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        + b"\xff\xc0"
        + struct.pack(">H", len(sof) + 2)
        + b"\x08"
        + sof
        + b"\xff\xd9"
    )


def make_webp(width: int = 1, height: int = 1) -> bytes:
    """Build a minimal WebP with a VP8X chunk.

    Args:
        width: Image width minus one, per the VP8X encoding.
        height: Image height minus one.

    Returns:
        WebP bytes.
    """
    payload = b"\x00\x00\x00\x00" + (width - 1).to_bytes(3, "little") + (height - 1).to_bytes(3, "little")
    return (
        b"RIFF"
        + struct.pack("<I", 4 + 8 + len(payload))
        + b"WEBP"
        + b"VP8X"
        + struct.pack("<I", len(payload))
        + payload
    )
