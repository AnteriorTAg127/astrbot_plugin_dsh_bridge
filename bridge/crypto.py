"""Cryptographic primitives for dsh-bridge/v1.

Implements protocol §2 (encoding and canonicalisation), §3 (PSK derivation,
directional session keys) and §5 (AEAD envelope sealing/opening).

Only the standard library plus ``cryptography`` (already a runtime dependency of
AstrBot) are used. No primitives are invented here.

Label note:
    The domain separation label is taken from :data:`bridge.constants.LABEL`,
    which follows the frozen fixture ``vectors.json`` (``dsh-bridge/v2``). See the
    module docstring of :mod:`bridge.constants` for the rationale.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import struct
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .constants import (
    DIRECTION_TAG_A2B,
    DIRECTION_TAG_B2A,
    ENVELOPE_VERSION,
    HANDSHAKE_KEY_NAMES,
    INFO_A2B,
    INFO_B2A,
    INFO_HANDSHAKE,
    INFO_HTTP_A2B,
    INFO_HTTP_B2A,
    LABEL,
    SIDE_A,
)
from .errors import (
    ERR_AEAD_FAILED,
    ERR_BAD_FRAME,
    ERR_BAD_HANDSHAKE_ENCODING,
    BridgeError,
)

# --------------------------------------------------------------------------------------
# Encoding helpers (§2.3)
# --------------------------------------------------------------------------------------


def b64u(data: bytes) -> str:
    """Encode bytes as unpadded base64url (RFC 4648 §5).

    Args:
        data: Bytes to encode.

    Returns:
        Base64url text without ``=`` padding.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_dec(text: str) -> bytes:
    """Decode unpadded base64url text.

    Args:
        text: Base64url text, optionally padded by the sender.

    Returns:
        Decoded bytes.

    Raises:
        BridgeError: ``bad_frame`` when the text is not valid base64url.
    """
    if not isinstance(text, str):
        raise BridgeError(ERR_BAD_FRAME, details={"field": "b64u"})
    # Only accept the protocol alphabet; reject URL-unsafe or whitespace input.
    for char in text:
        if not (char.isalnum() or char in "-_="):
            raise BridgeError(ERR_BAD_FRAME, details={"field": "b64u"})
    stripped = text.rstrip("=")
    padding = "=" * (-len(stripped) % 4)
    try:
        return base64.urlsafe_b64decode(stripped + padding)
    except (binascii.Error, ValueError) as exc:
        raise BridgeError(ERR_BAD_FRAME, details={"field": "b64u"}) from exc


# --------------------------------------------------------------------------------------
# JCS-ASCII / jcs_frame (§2.4, §2.5)
# --------------------------------------------------------------------------------------

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


def _escape_string(value: str) -> str:
    """Escape a string with the minimal JCS escape set.

    Args:
        value: Raw string value.

    Returns:
        Escaped string content, without the surrounding quotes.
    """
    out: list[str] = []
    for char in value:
        escape = _ESCAPES.get(char)
        if escape is not None:
            out.append(escape)
        elif ord(char) < 0x20:
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(char)
    return "".join(out)


def _serialize(value: Any, ascii_values: bool) -> str:
    """Serialise ``value`` following the JCS subset rules.

    Args:
        value: JSON-compatible value (object/array/str/int/bool/None).
        ascii_values: When ``True`` (handshake mode) non-ASCII values and ``None``
            are rejected; when ``False`` (frame mode) they are allowed.

    Returns:
        Canonical JSON text with no whitespace and ASCII-sorted object keys.

    Raises:
        BridgeError: ``bad_handshake_encoding`` on any violation.
    """
    if value is None:
        if ascii_values:
            raise BridgeError(
                ERR_BAD_HANDSHAKE_ENCODING, details={"reason": "null_not_allowed"}
            )
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise BridgeError(
            ERR_BAD_HANDSHAKE_ENCODING, details={"reason": "float_not_allowed"}
        )
    if isinstance(value, str):
        if ascii_values:
            try:
                value.encode("ascii")
            except UnicodeEncodeError as exc:
                raise BridgeError(
                    ERR_BAD_HANDSHAKE_ENCODING,
                    details={"reason": "non_ascii_value"},
                ) from exc
        return f'"{_escape_string(value)}"'
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize(item, ascii_values) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise BridgeError(
                    ERR_BAD_HANDSHAKE_ENCODING, details={"reason": "non_string_key"}
                )
            try:
                key.encode("ascii")
            except UnicodeEncodeError as exc:
                raise BridgeError(
                    ERR_BAD_HANDSHAKE_ENCODING, details={"reason": "non_ascii_key"}
                ) from exc
        members = ",".join(
            f'"{_escape_string(key)}":{_serialize(value[key], ascii_values)}'
            for key in sorted(value)
        )
        return "{" + members + "}"
    raise BridgeError(
        ERR_BAD_HANDSHAKE_ENCODING,
        details={"reason": "unsupported_type", "type": type(value).__name__},
    )


def jcs_ascii(value: Any) -> bytes:
    """Canonicalise a handshake/MAC object to JCS-ASCII bytes (§2.4).

    Args:
        value: Object to canonicalise. Must not contain ``None``, floats or
            non-ASCII strings/keys.

    Returns:
        UTF-8 bytes of the canonical JSON text.

    Raises:
        BridgeError: ``bad_handshake_encoding`` when the object is not compliant.
    """
    return _serialize(value, ascii_values=True).encode("ascii")


def jcs_frame(value: Any) -> bytes:
    """Canonicalise a sealed-frame payload to canonical JSON bytes (§2.5).

    Identical to :func:`jcs_ascii` except that non-ASCII string values and ``None``
    are allowed. Object keys must still be ASCII.

    Args:
        value: Payload object.

    Returns:
        UTF-8 bytes of the canonical JSON text.

    Raises:
        BridgeError: ``bad_handshake_encoding`` when the object is not compliant.
    """
    return _serialize(value, ascii_values=False).encode("utf-8")


def utf8_json(value: Any) -> bytes:
    """Serialise a payload to compact UTF-8 JSON without ASCII escaping.

    Used on the wire where canonicalisation is not required (§2.3): senders may
    use any legal JSON serialisation as long as the peer decodes the same
    semantics. This helper exists so both code paths stay explicit.

    Args:
        value: JSON-compatible value.

    Returns:
        UTF-8 encoded JSON bytes.
    """
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


# --------------------------------------------------------------------------------------
# Hashes / MAC / HKDF (§3.1)
# --------------------------------------------------------------------------------------


def sha256(data: bytes) -> bytes:
    """Return the SHA-256 digest of ``data``.

    Args:
        data: Input bytes.

    Returns:
        32-byte digest.
    """
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Return HMAC-SHA256 of ``message`` under ``key``.

    Args:
        key: HMAC key.
        message: Message bytes.

    Returns:
        32-byte MAC.
    """
    return hmac.new(key, message, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 HKDF-Extract with SHA-256.

    Args:
        salt: Salt bytes (``b"\\x00" * 32`` for the pre-handshake key).
        ikm: Input keying material.

    Returns:
        32-byte pseudo-random key.
    """
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Expand with SHA-256.

    Written by hand on purpose: hosts that only expose an extract-then-expand
    helper (for example Node's ``crypto.hkdfSync``) silently change the output.
    ``vectors.json`` catches such a mistake.

    Args:
        prk: Pseudo-random key from :func:`hkdf_extract`.
        info: Context/application specific info bytes.
        length: Number of output bytes.

    Returns:
        ``length`` bytes of output keying material.

    Raises:
        ValueError: When ``length`` is not positive or exceeds 255*32 bytes.
    """
    if length <= 0:
        raise ValueError("length must be positive")
    if length > 255 * 32:
        raise ValueError("length exceeds HKDF maximum")
    output = b""
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac_sha256(prk, previous + info + bytes([counter]))
        output += previous
        counter += 1
    return output[:length]


def length_prefix(data: bytes) -> bytes:
    """Return ``LP(x) = uint32_be(len(x)) || x`` (§2.4).

    Args:
        data: Bytes to prefix.

    Returns:
        Length-prefixed bytes.
    """
    return struct.pack(">I", len(data)) + data


# --------------------------------------------------------------------------------------
# Key derivation (§3.2, §3.3, §3.4)
# --------------------------------------------------------------------------------------


def psk_master(psk_id: str, psk_secret: str) -> bytes:
    """Derive ``psk_master`` from the connection PSK (§3.2).

    Args:
        psk_id: Connection PSK identifier (not secret).
        psk_secret: Connection PSK secret.

    Returns:
        32-byte master key. The inputs are never truncated.
    """
    return sha256(
        LABEL.encode("ascii")
        + b"\x00"
        + psk_id.encode("utf-8")
        + b"\x00"
        + psk_secret.encode("utf-8")
    )


def handshake_key(master: bytes, name: str) -> bytes:
    """Derive one of the four handshake MAC keys (§3.3).

    Args:
        master: Output of :func:`psk_master`.
        name: One of ``hello`` / ``hello_ack`` / ``probe`` / ``probe_ack``.

    Returns:
        32-byte HMAC-only key. These keys MUST NOT be used for AEAD.

    Raises:
        ValueError: When ``name`` is not part of the closed vocabulary.
    """
    if name not in HANDSHAKE_KEY_NAMES:
        raise ValueError(f"unknown handshake key name: {name}")
    pre_key = hkdf_extract(b"\x00" * 32, master)
    return hkdf_expand(pre_key, LABEL.encode("ascii") + b" " + name.encode("ascii"), 32)


@dataclass(frozen=True)
class SessionKeys:
    """Direction-separated session keys for one handshake.

    Attributes:
        k_a2b: AEAD key for the A→B direction.
        k_b2a: AEAD key for the B→A direction.
        k_http_a2b: HMAC key for A→B HTTP poll/poll-ack.
        k_http_b2a: HMAC key for B→A HTTP poll/poll-ack.
        prk: The session pseudo-random key, kept for tests and diagnostics.
    """

    k_a2b: bytes
    k_b2a: bytes
    k_http_a2b: bytes
    k_http_b2a: bytes
    prk: bytes

    def key_for(self, side: str) -> bytes:
        """Return the outbound AEAD key for the local ``side``.

        Args:
            side: ``"A"`` or ``"B"`` — the sender side.

        Returns:
            The AEAD key for that direction.

        Raises:
            ValueError: When ``side`` is neither ``A`` nor ``B``.
        """
        if side == SIDE_A:
            return self.k_a2b
        if side == "B":
            return self.k_b2a
        raise ValueError(f"unknown side: {side}")

    def inbound_key_for(self, peer_side: str) -> bytes:
        """Return the AEAD key used to open frames produced by ``peer_side``.

        Args:
            peer_side: The peer's side (the frame sender).

        Returns:
            The AEAD key for that direction.
        """
        return self.key_for(peer_side)

    def http_key_for(self, side: str) -> bytes:
        """Return the HTTP MAC key for the direction originating at ``side``.

        Args:
            side: Side that sends the HTTP request.

        Returns:
            HMAC key for that direction.

        Raises:
            ValueError: When ``side`` is neither ``A`` nor ``B``.
        """
        if side == SIDE_A:
            return self.k_http_a2b
        if side == "B":
            return self.k_http_b2a
        raise ValueError(f"unknown side: {side}")


def session_keys(master: bytes, nonce_c: bytes, nonce_s: bytes) -> SessionKeys:
    """Derive the session keys after ``hello`` / ``hello_ack`` (§3.4).

    Args:
        master: Output of :func:`psk_master`.
        nonce_c: Initiator nonce, raw bytes.
        nonce_s: Responder nonce, raw bytes.

    Returns:
        :class:`SessionKeys` with all four directional keys.

    Raises:
        ValueError: When either nonce is empty.
    """
    if not nonce_c or not nonce_s:
        raise ValueError("nonces must be non-empty")
    prk = hkdf_extract(nonce_c + nonce_s, master)
    label = LABEL.encode("ascii")
    return SessionKeys(
        k_a2b=hkdf_expand(prk, label + INFO_A2B.encode("ascii"), 32),
        k_b2a=hkdf_expand(prk, label + INFO_B2A.encode("ascii"), 32),
        k_http_a2b=hkdf_expand(prk, label + INFO_HTTP_A2B.encode("ascii"), 32),
        k_http_b2a=hkdf_expand(prk, label + INFO_HTTP_B2A.encode("ascii"), 32),
        prk=prk,
    )


def transcript_hash(hello_without_mac: dict, hello_ack_without_mac: dict) -> bytes:
    """Compute ``th = SHA256(transcript)`` binding both handshake objects (§4.4).

    Args:
        hello_without_mac: The initiator ``hello`` object without ``mac``.
        hello_ack_without_mac: The responder ``hello_ack`` object without ``mac``.

    Returns:
        32-byte transcript digest.
    """
    transcript = (
        length_prefix(LABEL.encode("ascii") + INFO_HANDSHAKE.encode("ascii"))
        + length_prefix(jcs_ascii(hello_without_mac))
        + length_prefix(jcs_ascii(hello_ack_without_mac))
    )
    return sha256(transcript)


# --------------------------------------------------------------------------------------
# Envelope sealing / opening (§5.2)
# --------------------------------------------------------------------------------------


def frame_nonce(side: str, seq: int) -> bytes:
    """Build the 12-byte AEAD nonce for a frame (§3.5).

    Args:
        side: Sender side (``"A"`` or ``"B"``).
        seq: Per-direction sequence number.

    Returns:
        4-byte big-endian direction tag followed by the 8-byte big-endian ``seq``.

    Raises:
        ValueError: When ``side`` is invalid or ``seq`` is out of uint64 range.
    """
    if side == SIDE_A:
        tag = DIRECTION_TAG_A2B
    elif side == "B":
        tag = DIRECTION_TAG_B2A
    else:
        raise ValueError(f"unknown side: {side}")
    if seq < 0 or seq > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("seq out of uint64 range")
    return struct.pack(">I", tag) + struct.pack(">Q", seq)


def frame_aad(frame_type: str, conn: str, seq: int) -> bytes:
    """Build the AAD binding ``type``/``conn``/``seq`` (§5.2).

    Args:
        frame_type: Envelope ``type`` value.
        conn: Connection identifier.
        seq: Sequence number.

    Returns:
        UTF-8 AAD bytes.
    """
    return f"{LABEL}|{frame_type}|{conn}|{seq}".encode()


def seal_frame(
    key: bytes,
    side: str,
    frame_type: str,
    conn: str,
    seq: int,
    payload: dict,
    *,
    canonical: bool = False,
) -> dict:
    """Encrypt ``payload`` into an envelope (§5.1/§5.2).

    Args:
        key: Directional AEAD key.
        side: Sender side used for the nonce direction tag.
        frame_type: Envelope type (``auth``/``data``/``ping``/…).
        conn: Connection identifier.
        seq: Sequence number allocated under the send lock.
        payload: JSON payload to encrypt.
        canonical: When ``True`` the plaintext is ``jcs_frame(payload)`` — required
            only to reproduce the golden vectors. Production frames use compact
            UTF-8 JSON, which is semantically identical.

    Returns:
        ``{"v", "type", "conn", "seq", "ct"}`` where ``ct`` is base64url of
        ``ciphertext || tag``.
    """
    plaintext = jcs_frame(payload) if canonical else utf8_json(payload)
    aead = ChaCha20Poly1305(key)
    ciphertext = aead.encrypt(
        frame_nonce(side, seq), plaintext, frame_aad(frame_type, conn, seq)
    )
    return {
        "v": ENVELOPE_VERSION,
        "type": frame_type,
        "conn": conn,
        "seq": seq,
        "ct": b64u(ciphertext),
    }


def open_frame(key: bytes, peer_side: str, envelope: dict) -> dict:
    """Decrypt and validate an envelope produced by ``peer_side`` (§5.1/§5.2).

    Args:
        key: Directional AEAD key (the one for the peer's direction).
        peer_side: The side that produced this frame.
        envelope: Envelope object received from the transport.

    Returns:
        The decoded payload object.

    Raises:
        BridgeError: ``bad_frame`` for a structurally invalid envelope,
            ``aead_failed`` when authentication fails.
    """
    if not isinstance(envelope, dict):
        raise BridgeError(ERR_BAD_FRAME, details={"reason": "not_an_object"})
    expected_fields = {"v", "type", "conn", "seq", "ct"}
    if set(envelope) != expected_fields:
        raise BridgeError(
            ERR_BAD_FRAME,
            details={
                "reason": "field_set",
                "extra": sorted(set(envelope) - expected_fields),
            },
        )
    if envelope["v"] != ENVELOPE_VERSION:
        raise BridgeError(ERR_BAD_FRAME, details={"reason": "envelope_version"})
    frame_type = envelope["type"]
    conn = envelope["conn"]
    seq = envelope["seq"]
    if not isinstance(frame_type, str) or not frame_type:
        raise BridgeError(ERR_BAD_FRAME, details={"reason": "frame_type"})
    if not isinstance(conn, str) or not conn:
        raise BridgeError(ERR_BAD_FRAME, details={"reason": "conn"})
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise BridgeError(ERR_BAD_FRAME, details={"reason": "seq"})
    if not isinstance(envelope["ct"], str):
        raise BridgeError(ERR_BAD_FRAME, details={"reason": "ct"})
    try:
        ciphertext = b64u_dec(envelope["ct"])
    except BridgeError as exc:
        raise BridgeError(ERR_BAD_FRAME, details={"reason": "ct_encoding"}) from exc
    try:
        plaintext = ChaCha20Poly1305(key).decrypt(
            frame_nonce(peer_side, seq),
            ciphertext,
            frame_aad(frame_type, conn, seq),
        )
    except Exception as exc:  # cryptography raises InvalidTag
        raise BridgeError(ERR_AEAD_FAILED) from exc
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BridgeError(ERR_BAD_FRAME, details={"reason": "plaintext_json"}) from exc
    if not isinstance(payload, dict):
        raise BridgeError(ERR_BAD_FRAME, details={"reason": "payload_not_object"})
    return payload


# --------------------------------------------------------------------------------------
# MAC helpers for handshake / HTTP objects (§4.2, §4.3, §7.3, §7.4)
# --------------------------------------------------------------------------------------


def mac_object(key: bytes, obj_without_mac: dict) -> str:
    """Compute ``b64u(HMAC(key, jcs_ascii(obj)))`` for an object lacking ``mac``.

    Args:
        key: One of the handshake keys or an HTTP direction key.
        obj_without_mac: Object with every field except ``mac``.

    Returns:
        Base64url MAC string.
    """
    return b64u(hmac_sha256(key, jcs_ascii(obj_without_mac)))


def verify_mac(key: bytes, obj_with_mac: dict, expected: str) -> bool:
    """Constant-time verification of a ``mac`` field.

    Args:
        key: The MAC key for this object type.
        obj_with_mac: Object including ``mac``; the field is removed before MAC.
        expected: MAC value received from the peer.

    Returns:
        ``True`` when the MAC matches.

    Raises:
        BridgeError: ``bad_handshake_encoding`` when the object cannot be
            canonicalised (that is a protocol violation, not a mismatch).
    """
    if not isinstance(expected, str) or not expected:
        return False
    body = {key_: value for key_, value in obj_with_mac.items() if key_ != "mac"}
    computed = mac_object(key, body)
    return hmac.compare_digest(computed, expected)


# --------------------------------------------------------------------------------------
# Digests for cross-end submission and image payloads (§12.5, §13)
# --------------------------------------------------------------------------------------


def input_parts_digest(input_parts: list[dict]) -> str:
    """Digest the ordered text parts of a task submission (§12.5).

    Args:
        input_parts: ``[{"type": "text", "text": ...}]`` in original order.

    Returns:
        Base64url of ``SHA256(LP(text) || LP(text) || …)``.

    Raises:
        BridgeError: ``bad_params`` when a part is not a text part.
    """
    hasher = hashlib.sha256()
    for part in input_parts:
        if not isinstance(part, dict) or part.get("type") != "text":
            raise BridgeError(ERR_BAD_FRAME, details={"reason": "input_parts"})
        text = part.get("text")
        if not isinstance(text, str):
            raise BridgeError(ERR_BAD_FRAME, details={"reason": "input_parts"})
        hasher.update(length_prefix(text.encode("utf-8")))
    return b64u(hasher.digest())


def submit_digest(projection: dict) -> str:
    """Digest the approved projection of a cross-end submission (§12.5).

    The projection carries ``session_id: null`` and ``purpose: null`` for the
    common case, and ``jcs_ascii`` rejects ``null`` outright. §18.5 and the frozen
    fixture both compute this digest with the frame canonicaliser, therefore
    :func:`jcs_frame` is used here.

    Args:
        projection: Projection object without ``approval_ref``.

    Returns:
        Base64url of ``SHA256(jcs_frame(projection))``.
    """
    return b64u(sha256(jcs_frame(projection)))


def request_digest(approval_fields: dict) -> str:
    """Digest the approval identity fields to bind a decision (§12.2).

    Uses the frame canonicaliser for the same reason as :func:`submit_digest`:
    ``task_id`` / ``session_id`` / ``call_id`` may legitimately be ``null``.

    Args:
        approval_fields: Object with ``tool``/``reason``/``call_id``/``session_id``/
            ``task_id``; absent optional fields MUST be present as ``None`` so both
            ends hash the same field set.

    Returns:
        Base64url of ``SHA256(jcs_frame(fields))``.
    """
    return b64u(sha256(jcs_frame(approval_fields)))
