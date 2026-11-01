"""Image attachment validation and inline chunk transfer (protocol §13).

Scope rules enforced here:

* Only images, only the four whitelisted MIME types.
* Sizes are checked **before** any byte is written, so an oversized ``blob.begin``
  cannot amplify into disk writes (§13.3 rule 3).
* Declared MIME is verified against real magic bytes, and the whole-image digest is
  verified at ``commit``.
* Temporary bytes live under ``tmp/`` and are deleted on commit/abort or after
  ``BLOB_TTL_S`` (§13.3 rule 5).
* No external URL is ever fetched: callers must pass local bytes or an already
  authorized attachment id (§13.1).
"""

from __future__ import annotations

import contextlib
import hashlib
import struct
import time
import uuid
from pathlib import Path

from astrbot.api import logger

from ..constants import (
    BLOB_TTL_S,
    IMAGE_MAGIC,
    IMAGE_MIME_TYPES,
    MAX_CHUNK_BYTES,
    MAX_IMAGE_DIMENSION,
    MAX_IMAGE_PIXELS,
    WEBP_FORM_MAGIC,
    WEBP_RIFF_MAGIC,
)
from ..crypto import b64u, b64u_dec
from ..errors import (
    ERR_ATTACHMENT_BYTES_MISMATCH,
    ERR_ATTACHMENT_COUNT_EXCEEDED,
    ERR_ATTACHMENT_INVALID,
    ERR_ATTACHMENT_META_MISMATCH,
    ERR_ATTACHMENT_NOT_FOUND,
    ERR_ATTACHMENT_PIXELS_EXCEEDED,
    ERR_ATTACHMENT_SOURCE_DENIED,
    ERR_ATTACHMENT_TOO_LARGE,
    ERR_ATTACHMENT_TYPE_DENIED,
    ERR_BAD_PARAMS,
    ERR_BLOB_INCOMPLETE,
    ERR_BLOB_NOT_FOUND,
    BridgeError,
)


def sniff_image_mime(data: bytes) -> str | None:
    """Detect an image MIME type from its magic bytes (§13.2).

    Args:
        data: Raw image bytes.

    Returns:
        One of the whitelisted MIME strings, or ``None`` when unrecognised.
    """
    if data.startswith(IMAGE_MAGIC["image/png"]):
        return "image/png"
    if data.startswith(IMAGE_MAGIC["image/jpeg"]):
        return "image/jpeg"
    if data.startswith(IMAGE_MAGIC["image/gif"]):
        return "image/gif"
    if (
        len(data) >= 12
        and data[:4] == WEBP_RIFF_MAGIC
        and data[8:12] == WEBP_FORM_MAGIC
    ):
        return "image/webp"
    return None


def image_dimensions(data: bytes) -> tuple[int, int] | None:
    """Read image dimensions from the header without decoding the pixels.

    Args:
        data: Raw image bytes.

    Returns:
        ``(width, height)``, or ``None`` when the header is not understood.
    """
    mime = sniff_image_mime(data)
    try:
        if mime == "image/png" and len(data) >= 24:
            width, height = struct.unpack(">II", data[16:24])
            return int(width), int(height)
        if mime == "image/gif" and len(data) >= 10:
            width, height = struct.unpack("<HH", data[6:10])
            return int(width), int(height)
        if mime == "image/webp" and len(data) >= 30:
            chunk = data[12:16]
            if chunk == b"VP8X" and len(data) >= 30:
                width = int.from_bytes(data[24:27], "little") + 1
                height = int.from_bytes(data[27:30], "little") + 1
                return width, height
            if chunk == b"VP8 " and len(data) >= 30:
                width = int.from_bytes(data[26:28], "little") & 0x3FFF
                height = int.from_bytes(data[28:30], "little") & 0x3FFF
                return width, height
            if chunk == b"VP8L" and len(data) >= 25:
                bits = int.from_bytes(data[21:25], "little")
                width = (bits & 0x3FFF) + 1
                height = ((bits >> 14) & 0x3FFF) + 1
                return width, height
            return None
        if mime == "image/jpeg":
            index = 2
            while index + 9 < len(data):
                if data[index] != 0xFF:
                    index += 1
                    continue
                marker = data[index + 1]
                if marker in (
                    0xC0,
                    0xC1,
                    0xC2,
                    0xC3,
                    0xC5,
                    0xC6,
                    0xC7,
                    0xC9,
                    0xCA,
                    0xCB,
                ):
                    height, width = struct.unpack(">HH", data[index + 5 : index + 9])
                    return int(width), int(height)
                if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
                    index += 2
                    continue
                segment = struct.unpack(">H", data[index + 2 : index + 4])[0]
                index += 2 + segment
            return None
    except (struct.error, IndexError):
        return None
    return None


def validate_image_bytes(
    data: bytes,
    *,
    declared_mime: str,
    max_bytes: int,
    allowed_mime: tuple[str, ...] = IMAGE_MIME_TYPES,
) -> dict:
    """Validate one image against §13.2 and return its metadata.

    Args:
        data: Raw image bytes.
        declared_mime: MIME type declared by the sender.
        max_bytes: Configured per-image byte limit.
        allowed_mime: Allowed MIME whitelist.

    Returns:
        ``{"media_type", "bytes", "sha256", "width", "height"}``.

    Raises:
        BridgeError: The specific §13.2 rejection code.
    """
    if declared_mime not in allowed_mime:
        raise BridgeError(ERR_ATTACHMENT_TYPE_DENIED, details={"mime": declared_mime})
    if not data:
        raise BridgeError(ERR_ATTACHMENT_INVALID, details={"reason": "empty"})
    if len(data) > max_bytes:
        raise BridgeError(
            ERR_ATTACHMENT_TOO_LARGE,
            details={"bytes": len(data), "limit": int(max_bytes)},
        )
    actual = sniff_image_mime(data)
    if actual is None:
        raise BridgeError(ERR_ATTACHMENT_INVALID, details={"reason": "magic"})
    if actual != declared_mime:
        raise BridgeError(
            ERR_ATTACHMENT_BYTES_MISMATCH,
            details={"declared": declared_mime, "actual": actual},
        )
    dimensions = image_dimensions(data)
    if dimensions is None:
        raise BridgeError(ERR_ATTACHMENT_INVALID, details={"reason": "dimensions"})
    width, height = dimensions
    if width <= 0 or height <= 0:
        raise BridgeError(ERR_ATTACHMENT_INVALID, details={"reason": "zero_size"})
    if width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION:
        raise BridgeError(
            ERR_ATTACHMENT_PIXELS_EXCEEDED,
            details={"width": width, "height": height},
        )
    if width * height > MAX_IMAGE_PIXELS:
        raise BridgeError(
            ERR_ATTACHMENT_PIXELS_EXCEEDED,
            details={"pixels": width * height},
        )
    return {
        "media_type": declared_mime,
        "bytes": len(data),
        "sha256": b64u(hashlib.sha256(data).digest()),
        "width": width,
        "height": height,
    }


class BlobService:
    """Inline chunked blob transfer with strict pre-checks (§13.3)."""

    def __init__(
        self,
        *,
        tmp_dir: Path,
        image_enabled: bool = True,
        max_bytes: int = 10_485_760,
        max_count: int = 4,
        total_max_bytes: int = 20_971_520,
        allowed_mime: tuple[str, ...] = IMAGE_MIME_TYPES,
    ) -> None:
        """Create the service.

        Args:
            tmp_dir: Directory for temporary blob bytes (``.../tmp``).
            image_enabled: Whether image attachments are accepted at all.
            max_bytes: Per-image byte limit.
            max_count: Per-task image count limit.
            total_max_bytes: Per-task total byte limit.
            allowed_mime: MIME whitelist.
        """
        self._tmp = tmp_dir
        self._image_enabled = image_enabled
        self._max_bytes = min(int(max_bytes), MAX_CHUNK_BYTES * 4_096)
        self._max_count = int(max_count)
        self._total_max_bytes = int(total_max_bytes)
        self._allowed_mime = allowed_mime
        self._pending: dict[str, dict] = {}

    async def init(self) -> None:
        """Create the temporary directory and purge stale files."""
        self._tmp.mkdir(parents=True, exist_ok=True)
        cutoff = time.time() - BLOB_TTL_S
        for path in self._tmp.glob("blob-*"):
            with contextlib.suppress(OSError):
                if path.stat().st_mtime < cutoff:
                    path.unlink()

    # -- wire handlers -----------------------------------------------------------------

    async def begin(self, params: dict) -> None:
        """``blob.begin``: declare a transfer after pre-checking limits (§13.3).

        Args:
            params: ``{"blob_id", "media_type", "bytes", "sha256", "width", "height",
                "chunks", "task_id", "name"}``.

        Raises:
            BridgeError: Any §13.2 limit violation. Nothing is written to disk.
        """
        if not self._image_enabled:
            raise BridgeError(
                ERR_ATTACHMENT_TYPE_DENIED, details={"reason": "disabled"}
            )
        blob_id = params.get("blob_id")
        media_type = params.get("media_type")
        size = params.get("bytes")
        digest = params.get("sha256")
        chunks = params.get("chunks")
        if not isinstance(blob_id, str) or not blob_id:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "blob_id"})
        if media_type not in self._allowed_mime:
            raise BridgeError(ERR_ATTACHMENT_TYPE_DENIED, details={"mime": media_type})
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise BridgeError(ERR_ATTACHMENT_INVALID, details={"reason": "bytes"})
        if size > self._max_bytes:
            raise BridgeError(
                ERR_ATTACHMENT_TOO_LARGE,
                details={"bytes": size, "limit": self._max_bytes},
            )
        if not isinstance(digest, str) or not digest:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "sha256"})
        if not isinstance(chunks, int) or chunks < 1:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "chunks"})
        expected_chunks = -(-size // MAX_CHUNK_BYTES)
        if chunks != expected_chunks:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "chunks"})

        width = params.get("width", 0)
        height = params.get("height", 0)
        for value in (width, height):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise BridgeError(ERR_BAD_PARAMS, details={"field": "dimensions"})
        if width and height:
            if width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION:
                raise BridgeError(ERR_ATTACHMENT_PIXELS_EXCEEDED)
            if width * height > MAX_IMAGE_PIXELS:
                raise BridgeError(ERR_ATTACHMENT_PIXELS_EXCEEDED)

        self._pending[blob_id] = {
            "media_type": media_type,
            "bytes": size,
            "sha256": digest,
            "chunks": chunks,
            "task_id": params.get("task_id"),
            "name": params.get("name"),
            "width": width,
            "height": height,
            "received": {},
            "created_at": time.time(),
        }
        logger.info(
            "bridge blob.begin id=%s mime=%s bytes=%s chunks=%s",
            blob_id,
            media_type,
            size,
            chunks,
        )

    async def chunk(self, params: dict) -> None:
        """``blob.chunk``: accept one verified chunk, idempotently (§13.3).

        Args:
            params: ``{"blob_id", "index", "data", "sha256"}``.

        Raises:
            BridgeError: ``blob_not_found`` / ``attachment_bytes_mismatch``.
        """
        blob_id = params.get("blob_id")
        if not isinstance(blob_id, str) or blob_id not in self._pending:
            raise BridgeError(ERR_BLOB_NOT_FOUND)
        entry = self._pending[blob_id]
        index = params.get("index")
        if not isinstance(index, int) or isinstance(index, bool) or index < 0:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "index"})
        if index >= entry["chunks"]:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "index"})
        try:
            data = b64u_dec(params.get("data", ""))
        except BridgeError as exc:
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "data"}) from exc
        if len(data) > MAX_CHUNK_BYTES:
            raise BridgeError(ERR_ATTACHMENT_TOO_LARGE, details={"chunk": len(data)})
        expected = params.get("sha256")
        actual = b64u(hashlib.sha256(data).digest())
        if not isinstance(expected, str) or expected != actual:
            raise BridgeError(ERR_ATTACHMENT_BYTES_MISMATCH, details={"chunk": index})
        existing = entry["received"].get(index)
        if existing is not None:
            if existing != data:
                raise BridgeError(
                    ERR_ATTACHMENT_BYTES_MISMATCH, details={"chunk": index}
                )
            return
        entry["received"][index] = data
        total = sum(len(value) for value in entry["received"].values())
        if total > self._max_bytes:
            self._pending.pop(blob_id, None)
            raise BridgeError(ERR_ATTACHMENT_TOO_LARGE, details={"bytes": total})

    async def commit(self, params: dict) -> dict:
        """``blob.commit``: verify the whole image and persist it temporarily.

        Args:
            params: ``{"blob_id", "bytes", "sha256"}``.

        Returns:
            ``{"blob_id", "path", "media_type", "bytes", "sha256", "width", "height"}``.

        Raises:
            BridgeError: ``blob_incomplete`` / ``attachment_bytes_mismatch``.
        """
        blob_id = params.get("blob_id")
        if not isinstance(blob_id, str) or blob_id not in self._pending:
            raise BridgeError(ERR_BLOB_NOT_FOUND)
        entry = self._pending[blob_id]
        missing = [
            index for index in range(entry["chunks"]) if index not in entry["received"]
        ]
        if missing:
            raise BridgeError(ERR_BLOB_INCOMPLETE, details={"missing": missing[:8]})
        data = b"".join(entry["received"][index] for index in range(entry["chunks"]))
        if len(data) != entry["bytes"]:
            raise BridgeError(
                ERR_ATTACHMENT_BYTES_MISMATCH,
                details={"expected": entry["bytes"], "actual": len(data)},
            )
        digest = b64u(hashlib.sha256(data).digest())
        if digest != entry["sha256"]:
            raise BridgeError(
                ERR_ATTACHMENT_BYTES_MISMATCH, details={"reason": "digest"}
            )
        validate_image_bytes(
            data,
            declared_mime=entry["media_type"],
            max_bytes=self._max_bytes,
            allowed_mime=self._allowed_mime,
        )
        path = self._tmp / f"blob-{uuid.uuid4().hex}"
        path.write_bytes(data)
        self._pending.pop(blob_id, None)
        self._committed = getattr(self, "_committed", {})
        self._committed[blob_id] = {
            "path": str(path),
            "media_type": entry["media_type"],
            "bytes": len(data),
            "sha256": digest,
            "width": entry["width"],
            "height": entry["height"],
            "task_id": entry["task_id"],
            "created_at": time.time(),
        }
        logger.info("bridge blob committed id=%s bytes=%s", blob_id, len(data))
        return {
            "blob_id": blob_id,
            "media_type": entry["media_type"],
            "bytes": len(data),
            "sha256": digest,
            "width": entry["width"],
            "height": entry["height"],
        }

    async def abort(self, params: dict) -> None:
        """``blob.abort``: drop a half-received blob (§13.3).

        Args:
            params: ``{"blob_id", "reason"}``.
        """
        blob_id = params.get("blob_id")
        if not isinstance(blob_id, str):
            return
        self._pending.pop(blob_id, None)
        committed = getattr(self, "_committed", {})
        entry = committed.pop(blob_id, None)
        if entry is not None:
            with contextlib.suppress(OSError):
                Path(entry["path"]).unlink()
        logger.info(
            "bridge blob aborted id=%s reason=%s", blob_id, params.get("reason")
        )

    # -- task attachment validation ----------------------------------------------------

    async def validate_task_attachments(self, params: dict) -> list[dict]:
        """Validate every attachment of a ``task.submit`` atomically (§13.2, §13.4).

        The whole submission is rejected when any attachment is invalid; nothing is
        partially accepted.

        Args:
            params: ``task.submit`` parameters.

        Returns:
            The validated attachment descriptors (metadata only).

        Raises:
            BridgeError: The first violation found, so the caller rejects the task.
        """
        attachments = params.get("attachments") or []
        if not isinstance(attachments, list):
            raise BridgeError(ERR_BAD_PARAMS, details={"field": "attachments"})
        if not attachments:
            return []
        if not self._image_enabled:
            raise BridgeError(
                ERR_ATTACHMENT_TYPE_DENIED, details={"reason": "disabled"}
            )
        if len(attachments) > self._max_count:
            raise BridgeError(
                ERR_ATTACHMENT_COUNT_EXCEEDED,
                details={"count": len(attachments), "limit": self._max_count},
            )
        total = 0
        validated: list[dict] = []
        committed = getattr(self, "_committed", {})
        for item in attachments:
            if not isinstance(item, dict):
                raise BridgeError(ERR_BAD_PARAMS, details={"field": "attachments"})
            if item.get("kind") != "blob":
                # Only inline blobs are legal in v1; references and URLs are refused.
                raise BridgeError(
                    ERR_ATTACHMENT_SOURCE_DENIED, details={"kind": item.get("kind")}
                )
            blob_id = item.get("blob_id")
            if not isinstance(blob_id, str) or blob_id not in committed:
                raise BridgeError(
                    ERR_ATTACHMENT_NOT_FOUND, details={"blob_id": blob_id}
                )
            entry = committed[blob_id]
            if item.get("media_type") != entry["media_type"]:
                raise BridgeError(
                    ERR_ATTACHMENT_META_MISMATCH, details={"field": "media_type"}
                )
            if item.get("bytes") != entry["bytes"]:
                raise BridgeError(
                    ERR_ATTACHMENT_META_MISMATCH, details={"field": "bytes"}
                )
            if item.get("sha256") != entry["sha256"]:
                raise BridgeError(
                    ERR_ATTACHMENT_META_MISMATCH, details={"field": "sha256"}
                )
            if not (time.time() - entry["created_at"]) <= BLOB_TTL_S:
                raise BridgeError(
                    ERR_ATTACHMENT_NOT_FOUND, details={"reason": "expired"}
                )
            total += entry["bytes"]
            if total > self._total_max_bytes:
                raise BridgeError(
                    ERR_ATTACHMENT_TOO_LARGE,
                    details={"total": total, "limit": self._total_max_bytes},
                )
            validated.append(
                {
                    "kind": "blob",
                    "blob_id": blob_id,
                    "media_type": entry["media_type"],
                    "bytes": entry["bytes"],
                    "sha256": entry["sha256"],
                    "width": entry["width"],
                    "height": entry["height"],
                    "path": entry["path"],
                }
            )
        return validated

    def committed(self, blob_id: str) -> dict | None:
        """Return committed blob metadata.

        Args:
            blob_id: Blob identifier.

        Returns:
            Metadata dictionary, or ``None``.
        """
        return getattr(self, "_committed", {}).get(blob_id)

    # -- outbound helpers --------------------------------------------------------------

    def plan_outbound(self, images: list[dict]) -> list[dict]:
        """Split outbound images into ``blob.*`` frames (§13.3).

        Args:
            images: ``[{"data": bytes, "media_type": str, "name": str|None}]``.

        Returns:
            A list of frame parameter dictionaries in send order.

        Raises:
            BridgeError: Any §13.2 violation, before anything is sent.
        """
        if not self._image_enabled:
            raise BridgeError(
                ERR_ATTACHMENT_TYPE_DENIED, details={"reason": "disabled"}
            )
        if len(images) > self._max_count:
            raise BridgeError(
                ERR_ATTACHMENT_COUNT_EXCEEDED,
                details={"count": len(images), "limit": self._max_count},
            )
        total = 0
        frames: list[dict] = []
        for image in images:
            data = image.get("data") or b""
            meta = validate_image_bytes(
                data,
                declared_mime=image.get("media_type", ""),
                max_bytes=self._max_bytes,
                allowed_mime=self._allowed_mime,
            )
            total += meta["bytes"]
            if total > self._total_max_bytes:
                raise BridgeError(
                    ERR_ATTACHMENT_TOO_LARGE,
                    details={"total": total, "limit": self._total_max_bytes},
                )
            blob_id = str(uuid.uuid4())
            chunks = -(-len(data) // MAX_CHUNK_BYTES)
            frames.append(
                {
                    "blob_id": blob_id,
                    "media_type": meta["media_type"],
                    "bytes": meta["bytes"],
                    "sha256": meta["sha256"],
                    "width": meta["width"],
                    "height": meta["height"],
                    "chunks": chunks,
                    "name": image.get("name"),
                    "data": data,
                    "attachment": {
                        "kind": "blob",
                        "blob_id": blob_id,
                        "media_type": meta["media_type"],
                        "bytes": meta["bytes"],
                        "sha256": meta["sha256"],
                        "width": meta["width"],
                        "height": meta["height"],
                    },
                }
            )
        return frames

    # -- maintenance --------------------------------------------------------------------

    async def cleanup_loop(self, interval_s: float = 60.0) -> None:
        """Delete expired temporary blobs periodically (§13.3 rule 4).

        Args:
            interval_s: Scan interval.
        """
        import asyncio

        while True:
            try:
                now = time.time()
                for blob_id, entry in list(getattr(self, "_committed", {}).items()):
                    if now - entry["created_at"] > BLOB_TTL_S:
                        with contextlib.suppress(OSError):
                            Path(entry["path"]).unlink()
                        getattr(self, "_committed", {}).pop(blob_id, None)
                for blob_id, entry in list(self._pending.items()):
                    if now - entry["created_at"] > BLOB_TTL_S:
                        self._pending.pop(blob_id, None)
                for path in self._tmp.glob("blob-*"):
                    with contextlib.suppress(OSError):
                        if now - path.stat().st_mtime > BLOB_TTL_S:
                            path.unlink()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("bridge blob cleanup failed")
            await asyncio.sleep(interval_s)

    async def purge_tmp(self) -> None:
        """Delete every temporary blob file (used on plugin shutdown)."""
        for path in self._tmp.glob("blob-*"):
            with contextlib.suppress(OSError):
                path.unlink()
        self._pending.clear()
        getattr(self, "_committed", {}).clear()


def build_blob_frames(plan: dict, task_id: str) -> list[tuple[str, dict]]:
    """Build the ordered ``blob.*`` frame payloads for one image (§13.3).

    Args:
        plan: One entry from :meth:`BlobService.plan_outbound`.
        task_id: Task the image belongs to.

    Returns:
        ``[(message_name, params), ...]`` in send order: ``begin``, ``chunk``…,
        ``commit``.
    """
    data: bytes = plan["data"]
    frames: list[tuple[str, dict]] = [
        (
            "blob.begin",
            {
                "blob_id": plan["blob_id"],
                "media_type": plan["media_type"],
                "bytes": plan["bytes"],
                "sha256": plan["sha256"],
                "width": plan["width"],
                "height": plan["height"],
                "chunks": plan["chunks"],
                "task_id": task_id,
                "name": plan["name"],
            },
        )
    ]
    for index in range(plan["chunks"]):
        chunk = data[index * MAX_CHUNK_BYTES : (index + 1) * MAX_CHUNK_BYTES]
        frames.append(
            (
                "blob.chunk",
                {
                    "blob_id": plan["blob_id"],
                    "index": index,
                    "data": b64u(chunk),
                    "sha256": b64u(hashlib.sha256(chunk).digest()),
                },
            )
        )
    frames.append(
        (
            "blob.commit",
            {
                "blob_id": plan["blob_id"],
                "bytes": plan["bytes"],
                "sha256": plan["sha256"],
            },
        )
    )
    return frames


def frames_for_images(plans: list[dict], task_id: str) -> list[tuple[str, dict]]:
    """Concatenate the frame lists of several images, preserving order.

    Args:
        plans: Output of :meth:`BlobService.plan_outbound`.
        task_id: Task the images belong to.

    Returns:
        Flat list of ``(message_name, params)``.
    """
    frames: list[tuple[str, dict]] = []
    for plan in plans:
        frames.extend(build_blob_frames(plan, task_id))
    return frames


__all__ = [
    "BlobService",
    "build_blob_frames",
    "frames_for_images",
    "image_dimensions",
    "sniff_image_mime",
    "validate_image_bytes",
]
