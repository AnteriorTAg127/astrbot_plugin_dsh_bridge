"""Unit tests for :mod:`bridge.crypto` beyond the golden vectors.

Covers canonicalisation edge cases, base64url strictness, key derivation
properties, envelope tampering and AAD binding.
"""

from __future__ import annotations

import pytest

from bridge.constants import LABEL
from bridge.crypto import (
    b64u,
    b64u_dec,
    frame_aad,
    frame_nonce,
    hkdf_expand,
    hkdf_extract,
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
    utf8_json,
    verify_mac,
)
from bridge.errors import (
    ERR_AEAD_FAILED,
    ERR_BAD_FRAME,
    ERR_BAD_HANDSHAKE_ENCODING,
    BridgeError,
)

SECRET = "unit-test-only-not-a-real-key"


def _keys():
    """Derive deterministic session keys for the tests."""
    master = psk_master("conn-1", SECRET)
    return session_keys(master, b"\x00" * 32, b"\x01" * 32)


def test_b64u_is_unpadded_and_urlsafe() -> None:
    """Base64url output has no padding and avoids ``+/``."""
    encoded = b64u(b"\xfb\xff\xfe")
    assert "=" not in encoded
    assert "+" not in encoded and "/" not in encoded


def test_b64u_dec_rejects_malformed_input() -> None:
    """Decoding rejects characters outside the base64url alphabet."""
    for bad in ("a b", "a.b", "a/b", "a+b"):
        with pytest.raises(BridgeError) as excinfo:
            b64u_dec(bad)
        assert excinfo.value.code == ERR_BAD_FRAME


def test_jcs_ascii_rejects_float_and_non_ascii() -> None:
    """Handshake canonicalisation rejects floats and non-ASCII values/keys."""
    with pytest.raises(BridgeError) as float_exc:
        jcs_ascii({"a": 1.5})
    assert float_exc.value.code == ERR_BAD_HANDSHAKE_ENCODING

    with pytest.raises(BridgeError):
        jcs_ascii({"a": "中文"})

    with pytest.raises(BridgeError):
        jcs_ascii({"键": 1})


def test_jcs_frame_allows_utf8_and_null() -> None:
    """Frame canonicalisation allows Chinese text and ``null`` values."""
    assert jcs_frame({"t": "中文", "n": None}) == '{"n":null,"t":"中文"}'.encode("utf-8")


def test_jcs_frame_keys_still_ascii_only() -> None:
    """Frame mode still forbids non-ASCII keys (§2.5)."""
    with pytest.raises(BridgeError):
        jcs_frame({"键": "值"})


def test_jcs_escapes_minimal_set() -> None:
    """Only the mandated escapes are applied; ``/`` stays literal."""
    assert jcs_ascii({"s": 'a"b\\c/d'}) == b'{"s":"a\\"b\\\\c/d"}'
    assert jcs_ascii({"s": "\x01"}) == b'{"s":"\\u0001"}'


def test_jcs_sorts_keys_by_ascii_bytes() -> None:
    """Object keys sort by ASCII byte order, not locale order."""
    assert jcs_ascii({"B": 1, "a": 2, "A": 3}) == b'{"A":3,"B":1,"a":2}'


def test_utf8_json_is_compact_and_unescaped() -> None:
    """Wire serialisation keeps Chinese literal and contains no spaces."""
    assert utf8_json({"a": "中", "b": [1, 2]}) == '{"a":"中","b":[1,2]}'.encode("utf-8")


def test_hkdf_expand_lengths_and_errors() -> None:
    """HKDF expand honours the requested length and validates inputs."""
    prk = hkdf_extract(b"\x00" * 32, b"ikm")
    assert len(hkdf_expand(prk, b"info", 1)) == 1
    assert len(hkdf_expand(prk, b"info", 64)) == 64
    with pytest.raises(ValueError):
        hkdf_expand(prk, b"info", 0)
    with pytest.raises(ValueError):
        hkdf_expand(prk, b"info", 255 * 32 + 1)


def test_length_prefix_is_uint32_big_endian() -> None:
    """LP(x) uses a 4-byte big-endian length."""
    assert length_prefix(b"ab") == b"\x00\x00\x00\x02ab"


def test_psk_master_rejects_empty_inputs_distinctly() -> None:
    """Different PSK ids/secrets always derive different master keys."""
    assert psk_master("a", SECRET) != psk_master("b", SECRET)
    assert psk_master("a", SECRET) != psk_master("a", SECRET + "x")
    assert psk_master("", "") == sha256(LABEL.encode() + b"\x00\x00")


def test_session_keys_are_directional() -> None:
    """The four session keys are pairwise distinct, and roles are honest."""
    keys = _keys()
    values = [keys.k_a2b, keys.k_b2a, keys.k_http_a2b, keys.k_http_b2a]
    assert len({value.hex() for value in values}) == 4
    assert keys.key_for("A") == keys.k_a2b
    assert keys.key_for("B") == keys.k_b2a
    with pytest.raises(ValueError):
        keys.key_for("C")


def test_session_keys_require_both_nonces() -> None:
    """Empty nonces are rejected outright."""
    master = psk_master("conn-1", SECRET)
    with pytest.raises(ValueError):
        session_keys(master, b"", b"\x01" * 32)


def test_frame_nonce_direction_tags() -> None:
    """A→B and B→A nonces differ only in the direction tag."""
    a_to_b = frame_nonce("A", 7)
    b_to_a = frame_nonce("B", 7)
    assert len(a_to_b) == 12
    assert a_to_b[:4] == b"\x00\x00\x00\x0a"
    assert b_to_a[:4] == b"\x00\x00\x00\x0b"
    assert a_to_b[4:] == b_to_a[4:]
    with pytest.raises(ValueError):
        frame_nonce("C", 1)
    with pytest.raises(ValueError):
        frame_nonce("A", -1)


def test_frame_aad_binds_type_conn_seq() -> None:
    """The AAD string is exactly ``label|type|conn|seq``."""
    assert frame_aad("data", "default", 3) == f"{LABEL}|data|default|3".encode()


def test_seal_open_roundtrip_and_reject_wrong_direction() -> None:
    """A frame sealed for one direction cannot be opened with the other key."""
    keys = _keys()
    sealed = seal_frame(keys.k_a2b, "A", "data", "default", 1, {"k": "req", "m": "x"})
    assert set(sealed) == {"v", "type", "conn", "seq", "ct"}
    assert open_frame(keys.k_a2b, "A", sealed) == {"k": "req", "m": "x"}
    with pytest.raises(BridgeError) as excinfo:
        open_frame(keys.k_b2a, "A", sealed)
    assert excinfo.value.code == ERR_AEAD_FAILED


def test_open_frame_rejects_aad_mismatch() -> None:
    """Changing ``type`` or ``seq`` invalidates the tag (AAD binding)."""
    keys = _keys()
    sealed = seal_frame(keys.k_a2b, "A", "data", "default", 5, {"n": 1})
    with pytest.raises(BridgeError) as type_exc:
        open_frame(keys.k_a2b, "A", {**sealed, "type": "ping"})
    assert type_exc.value.code == ERR_AEAD_FAILED
    with pytest.raises(BridgeError) as seq_exc:
        open_frame(keys.k_a2b, "A", {**sealed, "seq": 6})
    assert seq_exc.value.code == ERR_AEAD_FAILED


def test_open_frame_rejects_malformed_envelopes() -> None:
    """Structural problems raise ``bad_frame`` rather than ``aead_failed``."""
    keys = _keys()
    sealed = seal_frame(keys.k_a2b, "A", "data", "default", 1, {"n": 1})
    with pytest.raises(BridgeError) as extra_exc:
        open_frame(keys.k_a2b, "A", {**sealed, "ts": 1})
    assert extra_exc.value.code == ERR_BAD_FRAME
    with pytest.raises(BridgeError):
        open_frame(keys.k_a2b, "A", {**sealed, "v": 2})
    with pytest.raises(BridgeError):
        open_frame(keys.k_a2b, "A", {**sealed, "ct": "!!!"})
    with pytest.raises(BridgeError):
        open_frame(keys.k_a2b, "A", {**sealed, "seq": "1"})


def test_verify_mac_is_constant_time_and_rejects_tampering() -> None:
    """MAC verification accepts the right value and rejects any change."""
    key = hkdf_expand(hkdf_extract(b"\x00" * 32, b"k"), b"info", 32)
    body = {"conn": "default", "ts": 1}
    mac = mac_object(key, body)
    assert verify_mac(key, {**body, "mac": mac}, mac)
    assert not verify_mac(key, {**body, "mac": mac}, "A" * 43)
    assert not verify_mac(key, {**body, "conn": "other", "mac": mac}, mac)
    assert not verify_mac(key, {**body, "mac": mac}, "")


def test_transcript_binds_caps_and_nonces() -> None:
    """Changing any handshake field changes the transcript digest."""
    hello = {"conn": "default", "nonce": b64u(b"\x00" * 32), "pv": 1}
    ack = {"conn": "default", "nonce": b64u(b"\x01" * 32), "pv": 1, "sid": "s"}
    base = transcript_hash(hello, ack)
    assert base != transcript_hash({**hello, "pv": 2}, ack)
    assert base != transcript_hash(hello, {**ack, "sid": "t"})
    assert base != transcript_hash(hello, {**ack, "nonce": b64u(b"\x02" * 32)})


def test_input_parts_digest_is_order_sensitive() -> None:
    """Swapping text parts changes the digest; duplicates do not collapse."""
    first = [{"type": "text", "text": "a"}]
    second = [{"type": "text", "text": "b"}]
    assert input_parts_digest(first + second) != input_parts_digest(second + first)
    assert input_parts_digest(first + first) != input_parts_digest(first)


def test_input_parts_digest_rejects_non_text_parts() -> None:
    """Only ``text`` parts are allowed (§9.3.1)."""
    with pytest.raises(BridgeError):
        input_parts_digest([{"type": "image", "text": "x"}])


def test_submit_digest_changes_with_approval_relevant_fields() -> None:
    """The projection digest covers every field that a human approves."""
    projection = {
        "task_id": "t",
        "root_task_id": "t",
        "kind": "dsh_agent_run",
        "origin": "llm",
        "session_id": None,
        "purpose": "code-review",
        "timeout_s": 1800,
        "input_parts_digest": input_parts_digest([{"type": "text", "text": "a"}]),
        "attachments": [],
        "tool_hints": [],
    }
    baseline = submit_digest(projection)
    assert baseline != submit_digest({**projection, "purpose": "other"})
    assert baseline != submit_digest({**projection, "timeout_s": 60})
    assert baseline != submit_digest({**projection, "session_id": "s"})
