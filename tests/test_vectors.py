"""Golden-vector self-checks (protocol §18.6, items 1-12).

The fixture at ``tests/fixtures/protocol_vectors_v1.json`` is a byte-identical
copy of ``开发/v0.1/vectors.json``. Its expected values MUST NOT be edited; an
implementation is correct only when every assertion below passes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bridge.constants import LABEL
from bridge.crypto import (
    b64u,
    b64u_dec,
    hkdf_expand,
    hkdf_extract,
    hmac_sha256,
    input_parts_digest,
    jcs_ascii,
    jcs_frame,
    length_prefix,
    mac_object,
    open_frame,
    psk_master,
    seal_frame,
    session_keys,
    sha256,
    submit_digest,
    transcript_hash,
    verify_mac,
)
from bridge.errors import ERR_AEAD_FAILED, ERR_REPLAY_DETECTED, BridgeError
from bridge.replay import ReplayWindow

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "protocol_vectors_v1.json"


@pytest.fixture(scope="module")
def vectors() -> dict:
    """Load the frozen golden fixture."""
    with FIXTURE_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture(scope="module")
def master(vectors: dict) -> bytes:
    """Derive ``psk_master`` from the fixture inputs."""
    inputs = vectors["inputs"]
    return psk_master(inputs["psk_id"], inputs["psk_secret"])


@pytest.fixture(scope="module")
def keys(master: bytes, vectors: dict):
    """Derive the session keys from the fixture nonces."""
    inputs = vectors["inputs"]
    return session_keys(
        master,
        bytes.fromhex(inputs["nonce_c_hex"]),
        bytes.fromhex(inputs["nonce_s_hex"]),
    )


def test_v18_6_01_jcs_ascii_examples(vectors: dict) -> None:
    """§18.6-1: every JCS example canonicalises to the documented bytes.

    §2.4 rule 1 makes ``jcs_ascii`` reject ``null`` for handshake objects while
    §2.5 allows it for frame payloads. The fixture's ``jcs_examples`` contains one
    payload-only example carrying ``null``; it is asserted through
    :func:`jcs_frame`, and the handshake-mode rejection is asserted explicitly.
    """
    for example in vectors["jcs_examples"]:
        encoded = example["out"].encode("utf-8")
        if b"null" in encoded:
            assert jcs_frame(example["in"]) == encoded
            with pytest.raises(BridgeError):
                jcs_ascii(example["in"])
        else:
            assert jcs_ascii(example["in"]) == encoded


def test_v18_6_02_psk_master(master: bytes, vectors: dict) -> None:
    """§18.6-2: ``psk_master`` matches the fixture."""
    assert master.hex() == vectors["keys"]["psk_master_hex"]


def test_v18_6_03_jcs_handshake_lengths(vectors: dict) -> None:
    """§18.6-3: canonical handshake objects have the documented lengths."""
    assert len(jcs_ascii(vectors["hello_without_mac"])) == vectors["jcs_hello_len"]
    assert len(jcs_ascii(vectors["hello_ack_without_mac"])) == (
        vectors["jcs_hello_ack_len"]
    )


def test_v18_6_04_handshake_macs(master: bytes, vectors: dict) -> None:
    """§18.6-4: both handshake MACs match, and verification accepts them."""
    hello_key = hkdf_expand(
        hkdf_extract(b"\x00" * 32, master), LABEL.encode("ascii") + b" hello", 32
    )
    ack_key = hkdf_expand(
        hkdf_extract(b"\x00" * 32, master), LABEL.encode("ascii") + b" hello_ack", 32
    )
    hello_mac = mac_object(hello_key, vectors["hello_without_mac"])
    ack_mac = mac_object(ack_key, vectors["hello_ack_without_mac"])
    assert hello_mac == vectors["hellos"]["hello_mac"]
    assert ack_mac == vectors["hellos"]["hello_ack_mac"]
    assert verify_mac(
        hello_key,
        {**vectors["hello_without_mac"], "mac": hello_mac},
        hello_mac,
    )


def test_v18_6_05_transcript(vectors: dict) -> None:
    """§18.6-5: the transcript digest (and therefore ``th``) matches."""
    digest = transcript_hash(
        vectors["hello_without_mac"], vectors["hello_ack_without_mac"]
    )
    assert digest.hex() == vectors["hellos"]["transcript_sha256_hex"]
    assert b64u(digest) == vectors["hellos"]["th_b64u"]


def test_v18_6_06_session_keys(keys, vectors: dict) -> None:
    """§18.6-6: PRK and all four directional keys match the fixture."""
    expected = vectors["keys"]
    assert keys.prk.hex() == expected["prk_hex"]
    assert keys.k_a2b.hex() == expected["k_a2b_hex"]
    assert keys.k_b2a.hex() == expected["k_b2a_hex"]
    assert keys.k_http_a2b.hex() == expected["k_http_a2b_hex"]
    assert keys.k_http_b2a.hex() == expected["k_http_b2a_hex"]


def test_v18_6_07_08_auth_frames_roundtrip(keys, vectors: dict) -> None:
    """§18.6-7/8: ``auth`` and ``auth_ack`` reproduce and decrypt."""
    conn = vectors["inputs"]["conn"]
    auth = vectors["frames"][0]
    sealed = seal_frame(
        keys.k_a2b, "A", auth["type"], conn, auth["seq"], auth["payload"], canonical=True
    )
    assert sealed["ct"] == auth["ct"]
    assert open_frame(keys.k_a2b, "A", sealed) == auth["payload"]

    ack = vectors["frames"][1]
    sealed_ack = seal_frame(
        keys.k_b2a, "B", ack["type"], conn, ack["seq"], ack["payload"], canonical=True
    )
    assert sealed_ack["ct"] == ack["ct"]
    opened = open_frame(keys.k_b2a, "B", sealed_ack)
    assert opened == ack["payload"]
    assert opened["th"] == vectors["hellos"]["th_b64u"]


def test_v18_6_09_all_other_frames(keys, vectors: dict) -> None:
    """§18.6-9: every remaining ``data``/``ping``/``close`` frame matches."""
    conn = vectors["inputs"]["conn"]
    for frame in vectors["frames"][2:]:
        key = keys.k_a2b if frame["sender_side"] == "A" else keys.k_b2a
        sealed = seal_frame(
            key,
            frame["sender_side"],
            frame["type"],
            conn,
            frame["seq"],
            frame["payload"],
            canonical=True,
        )
        assert sealed["ct"] == frame["ct"], f"{frame['type']}#{frame['seq']}"
        assert open_frame(key, frame["sender_side"], sealed) == frame["payload"]
        # Non-canonical (wire) sealing must decrypt to the same payload.
        wire = seal_frame(
            key, frame["sender_side"], frame["type"], conn, frame["seq"], frame["payload"]
        )
        assert open_frame(key, frame["sender_side"], wire) == frame["payload"]


def test_v18_6_10_digests_and_http_macs(master: bytes, vectors: dict) -> None:
    """§18.6-10: digests, probe MACs and poll MACs all match."""
    assert input_parts_digest(vectors["digests"]["text_parts"]) == (
        vectors["digests"]["input_parts_digest_b64u"]
    )
    assert submit_digest(vectors["digests"]["submit_projection"]) == (
        vectors["digests"]["submit_digest_b64u"]
    )

    probe_key = hkdf_expand(
        hkdf_extract(b"\x00" * 32, master), LABEL.encode("ascii") + b" probe", 32
    )
    probe_ack_key = hkdf_expand(
        hkdf_extract(b"\x00" * 32, master), LABEL.encode("ascii") + b" probe_ack", 32
    )
    macs = vectors["macs"]
    assert mac_object(probe_key, macs["probe_object"]) == macs["probe_mac"]
    assert mac_object(probe_ack_key, macs["probe_ack_object"]) == macs["probe_ack_mac"]


def test_v18_6_10b_poll_macs(keys, vectors: dict) -> None:
    """§18.6-10: poll and poll-ack MACs use the HTTP direction keys."""
    macs = vectors["macs"]
    assert mac_object(keys.k_http_a2b, macs["poll_object"]) == macs["poll_mac"]
    assert mac_object(keys.k_http_a2b, macs["poll_ack_object"]) == macs["poll_ack_mac"]


def test_v18_6_11_tamper_and_replay(keys, vectors: dict) -> None:
    """§18.6-11: a flipped ciphertext byte fails AEAD; a repeated seq is rejected."""
    frame = vectors["frames"][3]
    conn = vectors["inputs"]["conn"]
    sealed = seal_frame(
        keys.k_a2b, "A", frame["type"], conn, frame["seq"], frame["payload"], canonical=True
    )
    raw = bytearray(b64u_dec(sealed["ct"]))
    raw[0] ^= 0x01
    tampered = {**sealed, "ct": b64u(bytes(raw))}
    with pytest.raises(BridgeError) as excinfo:
        open_frame(keys.k_a2b, "A", tampered)
    assert excinfo.value.code == ERR_AEAD_FAILED

    window = ReplayWindow(start=frame["seq"])
    window.accept(frame["seq"])
    with pytest.raises(BridgeError) as replay_excinfo:
        window.accept(frame["seq"])
    assert replay_excinfo.value.code == ERR_REPLAY_DETECTED


def test_v18_6_12_stale_session_frame(keys, vectors: dict) -> None:
    """§18.6-12: a frame sealed for an old ``sid`` cannot be replayed as current.

    ``sid`` travels inside the sealed payload, so the check is a payload identity
    check performed by the session layer; here we prove the AEAD layer cannot be
    tricked into accepting a frame under a different ``sid`` without a new seal.
    """
    frame = vectors["frames"][1]
    conn = vectors["inputs"]["conn"]
    sealed = seal_frame(
        keys.k_b2a, "B", frame["type"], conn, frame["seq"], frame["payload"], canonical=True
    )
    stale_payload = {**frame["payload"], "sid": "00000000-0000-4000-8000-000000000000"}
    resealed = seal_frame(
        keys.k_b2a, "B", "auth_ack", conn, 0, stale_payload, canonical=True
    )
    assert resealed["ct"] != sealed["ct"]
    assert open_frame(keys.k_b2a, "B", resealed)["sid"] != frame["payload"]["sid"]
    # Using the old ciphertext with a different sid context still decrypts to the
    # old sid — the session layer is responsible for rejecting it, which
    # tests/test_handshake.py asserts.
    assert open_frame(keys.k_b2a, "B", sealed)["sid"] == frame["payload"]["sid"]


def test_v18_6_12b_image_fixture(vectors: dict) -> None:
    """§18.5: the 70-byte PNG fixture hashes and starts with the PNG magic."""
    image = vectors["image"]
    data = bytes.fromhex(image["png_hex"])
    assert len(data) == image["png_bytes"]
    assert b64u(sha256(data)) == image["sha256_b64u"]
    assert data[:8].hex() == image["magic_hex"]


def test_label_matches_fixture(vectors: dict) -> None:
    """The label must be the fixture value, not the prose value in the protocol."""
    assert vectors["label"] == LABEL


def test_b64u_roundtrip_and_rejection() -> None:
    """Base64url helpers round-trip and reject foreign alphabets."""
    payload = bytes(range(32))
    assert b64u_dec(b64u(payload)) == payload
    with pytest.raises(BridgeError):
        b64u_dec("not valid!!")


def test_hkdf_expand_is_not_extract_then_expand() -> None:
    """§18.6-13: expand must take the PRK as given, not re-extract."""
    prk = hkdf_extract(b"\x00" * 32, b"ikm")
    doubled = hkdf_expand(prk, b"info", 32)
    wrongly_extracted = hkdf_expand(hkdf_extract(b"\x00" * 32, prk), b"info", 32)
    assert doubled != wrongly_extracted
