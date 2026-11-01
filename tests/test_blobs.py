"""Image/blob tests: magic bytes, limits, chunking, tampering, expiry (§13)."""

from __future__ import annotations

import hashlib
import time

import pytest

from bridge.app.blobs import (
    BlobService,
    build_blob_frames,
    frames_for_images,
    image_dimensions,
    sniff_image_mime,
    validate_image_bytes,
)
from bridge.crypto import b64u, b64u_dec
from bridge.errors import BridgeError
from conftest import make_gif, make_jpeg, make_png, make_webp


@pytest.fixture
def blobs(tmp_path):
    """Provide an initialised :class:`BlobService`.

    Args:
        tmp_path: Temporary directory.

    Returns:
        The service.
    """
    service = BlobService(
        tmp_dir=tmp_path / "tmp",
        image_enabled=True,
        max_bytes=10_485_760,
        max_count=4,
        total_max_bytes=20_971_520,
    )
    (tmp_path / "tmp").mkdir(parents=True, exist_ok=True)
    return service


@pytest.mark.parametrize(
    ("builder", "mime"),
    [
        (make_png, "image/png"),
        (make_gif, "image/gif"),
        (make_jpeg, "image/jpeg"),
        (make_webp, "image/webp"),
    ],
)
def test_magic_detection_for_all_four_types(builder, mime) -> None:
    """All four whitelisted MIME types are detected from real bytes (§13.2)."""
    data = builder(3, 4)
    assert sniff_image_mime(data) == mime
    assert image_dimensions(data) == (3, 4)
    meta = validate_image_bytes(data, declared_mime=mime, max_bytes=1_000_000)
    assert meta["media_type"] == mime
    assert meta["width"] == 3 and meta["height"] == 4
    assert meta["bytes"] == len(data)
    assert meta["sha256"] == b64u(hashlib.sha256(data).digest())


def test_mime_mismatch_is_rejected() -> None:
    """Declared MIME must match the real magic bytes (§13.2)."""
    with pytest.raises(BridgeError) as excinfo:
        validate_image_bytes(make_png(), declared_mime="image/jpeg", max_bytes=1_000_000)
    assert excinfo.value.code == "attachment_bytes_mismatch"


def test_disaallowed_mime_is_rejected() -> None:
    """Anything outside the whitelist is ``attachment_type_denied``."""
    with pytest.raises(BridgeError) as excinfo:
        validate_image_bytes(b"GIF89a....", declared_mime="image/bmp", max_bytes=1_000)
    assert excinfo.value.code == "attachment_type_denied"


def test_empty_and_corrupt_bytes_are_invalid() -> None:
    """Empty or undecodable payloads are ``attachment_invalid``."""
    for payload in (b"", b"not an image at all"):
        with pytest.raises(BridgeError) as excinfo:
            validate_image_bytes(payload, declared_mime="image/png", max_bytes=1_000)
        assert excinfo.value.code in ("attachment_invalid", "attachment_bytes_mismatch")


def test_oversized_image_is_rejected() -> None:
    """Exceeding the per-image byte limit is ``attachment_too_large``."""
    data = make_png(4, 4)
    with pytest.raises(BridgeError) as excinfo:
        validate_image_bytes(data, declared_mime="image/png", max_bytes=len(data) - 1)
    assert excinfo.value.code == "attachment_too_large"


def test_oversized_dimensions_are_rejected() -> None:
    """Dimensions above 8192 px or 64 Mpx are ``attachment_pixels_exceeded``."""
    data = make_png(9000, 1)
    with pytest.raises(BridgeError) as excinfo:
        validate_image_bytes(data, declared_mime="image/png", max_bytes=10_000_000)
    assert excinfo.value.code == "attachment_pixels_exceeded"


@pytest.mark.asyncio
async def test_full_chunk_roundtrip(blobs) -> None:
    """``begin``/``chunk``/``commit`` accepts a valid image (§13.3)."""
    data = make_png(8, 8)
    digest = b64u(hashlib.sha256(data).digest())
    await blobs.begin(
        {
            "blob_id": "b-1",
            "media_type": "image/png",
            "bytes": len(data),
            "sha256": digest,
            "width": 8,
            "height": 8,
            "chunks": 1,
            "task_id": "t-1",
            "name": None,
        }
    )
    await blobs.chunk(
        {
            "blob_id": "b-1",
            "index": 0,
            "data": b64u(data),
            "sha256": b64u(hashlib.sha256(data).digest()),
        }
    )
    result = await blobs.commit({"blob_id": "b-1", "bytes": len(data), "sha256": digest})
    assert result["sha256"] == digest
    assert result["media_type"] == "image/png"
    assert blobs.committed("b-1") is not None


@pytest.mark.asyncio
async def test_begin_rejects_before_writing_anything(blobs, tmp_path) -> None:
    """An oversized ``blob.begin`` writes no bytes at all (§13.3 rule 3)."""
    with pytest.raises(BridgeError) as excinfo:
        await blobs.begin(
            {
                "blob_id": "b-big",
                "media_type": "image/png",
                "bytes": 20_000_000,
                "sha256": b64u(b"\x00" * 32),
                "width": 1,
                "height": 1,
                "chunks": 26,
            }
        )
    assert excinfo.value.code == "attachment_too_large"
    assert not list((tmp_path / "tmp").glob("blob-*"))


@pytest.mark.asyncio
async def test_chunk_tampering_is_rejected(blobs) -> None:
    """A chunk whose digest does not match its bytes is refused (§13.3 rule 2)."""
    data = make_png()
    await blobs.begin(
        {
            "blob_id": "b-2",
            "media_type": "image/png",
            "bytes": len(data),
            "sha256": b64u(hashlib.sha256(data).digest()),
            "width": 1,
            "height": 1,
            "chunks": 1,
        }
    )
    with pytest.raises(BridgeError) as excinfo:
        await blobs.chunk(
            {
                "blob_id": "b-2",
                "index": 0,
                "data": b64u(data),
                "sha256": b64u(b"\xff" * 32),
            }
        )
    assert excinfo.value.code == "attachment_bytes_mismatch"


@pytest.mark.asyncio
async def test_commit_without_chunks_is_incomplete(blobs) -> None:
    """Committing a partially received blob is ``blob_incomplete`` (§13.3 rule 1)."""
    data = make_png()
    await blobs.begin(
        {
            "blob_id": "b-3",
            "media_type": "image/png",
            "bytes": len(data),
            "sha256": b64u(hashlib.sha256(data).digest()),
            "width": 1,
            "height": 1,
            "chunks": 1,
        }
    )
    with pytest.raises(BridgeError) as excinfo:
        await blobs.commit(
            {"blob_id": "b-3", "bytes": len(data), "sha256": b64u(hashlib.sha256(data).digest())}
        )
    assert excinfo.value.code == "blob_incomplete"


@pytest.mark.asyncio
async def test_duplicate_chunk_is_idempotent(blobs) -> None:
    """Re-sending an identical chunk is accepted without double counting (§10.1)."""
    data = make_png()
    chunk_digest = b64u(hashlib.sha256(data).digest())
    await blobs.begin(
        {
            "blob_id": "b-4",
            "media_type": "image/png",
            "bytes": len(data),
            "sha256": chunk_digest,
            "width": 1,
            "height": 1,
            "chunks": 1,
        }
    )
    for _ in range(2):
        await blobs.chunk(
            {"blob_id": "b-4", "index": 0, "data": b64u(data), "sha256": chunk_digest}
        )
    result = await blobs.commit({"blob_id": "b-4", "bytes": len(data), "sha256": chunk_digest})
    assert result["bytes"] == len(data)


@pytest.mark.asyncio
async def test_abort_removes_pending_state(blobs) -> None:
    """``blob.abort`` drops the transfer entirely."""
    data = make_png()
    await blobs.begin(
        {
            "blob_id": "b-5",
            "media_type": "image/png",
            "bytes": len(data),
            "sha256": b64u(hashlib.sha256(data).digest()),
            "width": 1,
            "height": 1,
            "chunks": 1,
        }
    )
    await blobs.abort({"blob_id": "b-5", "reason": "user_cancelled"})
    with pytest.raises(BridgeError):
        await blobs.chunk(
            {"blob_id": "b-5", "index": 0, "data": b64u(data), "sha256": b64u(b"\x00" * 32)}
        )


@pytest.mark.asyncio
async def test_task_attachments_validate_metadata(blobs) -> None:
    """``attachments[]`` metadata must match ``blob.begin`` (§13.3 rule 6)."""
    data = make_png()
    digest = b64u(hashlib.sha256(data).digest())
    await blobs.begin(
        {
            "blob_id": "b-6",
            "media_type": "image/png",
            "bytes": len(data),
            "sha256": digest,
            "width": 1,
            "height": 1,
            "chunks": 1,
            "task_id": "t-1",
        }
    )
    await blobs.chunk(
        {"blob_id": "b-6", "index": 0, "data": b64u(data), "sha256": digest}
    )
    await blobs.commit({"blob_id": "b-6", "bytes": len(data), "sha256": digest})

    validated = await blobs.validate_task_attachments(
        {
            "attachments": [
                {
                    "kind": "blob",
                    "blob_id": "b-6",
                    "media_type": "image/png",
                    "bytes": len(data),
                    "sha256": digest,
                    "width": 1,
                    "height": 1,
                }
            ]
        }
    )
    assert validated[0]["path"]

    with pytest.raises(BridgeError) as excinfo:
        await blobs.validate_task_attachments(
            {
                "attachments": [
                    {
                        "kind": "blob",
                        "blob_id": "b-6",
                        "media_type": "image/png",
                        "bytes": len(data) + 1,
                        "sha256": digest,
                    }
                ]
            }
        )
    assert excinfo.value.code == "attachment_meta_mismatch"


@pytest.mark.asyncio
async def test_external_reference_sources_are_denied(blobs) -> None:
    """An attachment that is not an inline blob is ``attachment_source_denied`` (§13.1)."""
    with pytest.raises(BridgeError) as excinfo:
        await blobs.validate_task_attachments(
            {"attachments": [{"kind": "url", "url": "https://example.invalid/x.png"}]}
        )
    assert excinfo.value.code == "attachment_source_denied"


@pytest.mark.asyncio
async def test_unknown_blob_is_not_found(blobs) -> None:
    """Referencing a blob that was never committed is ``attachment_not_found``."""
    with pytest.raises(BridgeError) as excinfo:
        await blobs.validate_task_attachments(
            {"attachments": [{"kind": "blob", "blob_id": "missing", "media_type": "image/png",
                              "bytes": 1, "sha256": "x"}]}
        )
    assert excinfo.value.code == "attachment_not_found"


@pytest.mark.asyncio
async def test_too_many_attachments_is_rejected(blobs) -> None:
    """More images than ``image_max_count`` is ``attachment_count_exceeded`` (§13.2)."""
    with pytest.raises(BridgeError) as excinfo:
        await blobs.validate_task_attachments(
            {
                "attachments": [
                    {"kind": "blob", "blob_id": f"b-{index}", "media_type": "image/png",
                     "bytes": 1, "sha256": "x"}
                    for index in range(5)
                ]
            }
        )
    assert excinfo.value.code == "attachment_count_exceeded"


@pytest.mark.asyncio
async def test_expired_blob_is_not_found(blobs) -> None:
    """A committed blob older than ``BLOB_TTL_S`` is expired (§13.3 rule 4)."""
    data = make_png()
    digest = b64u(hashlib.sha256(data).digest())
    await blobs.begin(
        {
            "blob_id": "b-7",
            "media_type": "image/png",
            "bytes": len(data),
            "sha256": digest,
            "width": 1,
            "height": 1,
            "chunks": 1,
        }
    )
    await blobs.chunk({"blob_id": "b-7", "index": 0, "data": b64u(data), "sha256": digest})
    await blobs.commit({"blob_id": "b-7", "bytes": len(data), "sha256": digest})
    entry = blobs._committed["b-7"]
    entry["created_at"] = time.time() - 400
    with pytest.raises(BridgeError) as excinfo:
        await blobs.validate_task_attachments(
            {
                "attachments": [
                    {
                        "kind": "blob",
                        "blob_id": "b-7",
                        "media_type": "image/png",
                        "bytes": len(data),
                        "sha256": digest,
                    }
                ]
            }
        )
    assert excinfo.value.code == "attachment_not_found"


@pytest.mark.asyncio
async def test_outbound_plan_and_frames_order(blobs) -> None:
    """Outbound frames are ``begin`` → ``chunk``… → ``commit`` (§13.3, §18.4)."""
    data = make_png(2, 2)
    plans = blobs.plan_outbound([{"data": data, "media_type": "image/png", "name": "a.png"}])
    frames = frames_for_images(plans, "t-out")
    names = [name for name, _ in frames]
    assert names[0] == "blob.begin"
    assert names[-1] == "blob.commit"
    assert names.count("blob.chunk") == plans[0]["chunks"]
    begin = frames[0][1]
    assert begin["chunks"] == plans[0]["chunks"]
    assert begin["bytes"] == len(data)


@pytest.mark.asyncio
async def test_outbound_rejects_unsupported_type(blobs) -> None:
    """Outbound images are validated before any frame is produced (§13.2)."""
    with pytest.raises(BridgeError) as excinfo:
        blobs.plan_outbound([{"data": b"\x00\x01", "media_type": "image/png"}])
    assert excinfo.value.code in ("attachment_invalid", "attachment_bytes_mismatch")


@pytest.mark.asyncio
async def test_image_disabled_rejects_everything(tmp_path) -> None:
    """When ``image_enabled`` is false, no image is accepted."""
    service = BlobService(tmp_dir=tmp_path / "tmp", image_enabled=False)
    (tmp_path / "tmp").mkdir(parents=True, exist_ok=True)
    with pytest.raises(BridgeError) as excinfo:
        await service.begin(
            {
                "blob_id": "x",
                "media_type": "image/png",
                "bytes": 10,
                "sha256": "x",
                "width": 1,
                "height": 1,
                "chunks": 1,
            }
        )
    assert excinfo.value.code == "attachment_type_denied"


def test_chunk_size_matches_protocol_limit() -> None:
    """Chunking splits at ``max_chunk_bytes`` (768 KiB), never a private size."""
    from bridge.constants import MAX_CHUNK_BYTES

    assert MAX_CHUNK_BYTES == 786_432
    frames = build_blob_frames(
        {
            "blob_id": "b",
            "media_type": "image/png",
            "bytes": MAX_CHUNK_BYTES + 10,
            "sha256": "s",
            "width": 1,
            "height": 1,
            "chunks": 2,
            "name": None,
            "data": b"\x00" * (MAX_CHUNK_BYTES + 10),
        },
        "t",
    )
    assert len(frames) == 4
    assert len(b64u_dec(frames[1][1]["data"])) == MAX_CHUNK_BYTES
    assert len(b64u_dec(frames[2][1]["data"])) == 10
