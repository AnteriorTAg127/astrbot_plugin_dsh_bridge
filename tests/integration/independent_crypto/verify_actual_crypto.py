#!/usr/bin/env python3
"""Independent, on-disk verification of the *actual* bridge crypto modules.

Purpose
-------
Prove that the shipped crypto modules of both repositories reproduce the frozen
golden fixture ``dsh-bridge/v1`` (``vectors.json``), and that a frame sealed by
one implementation opens in the other.

Rules this file obeys
---------------------
* It does **not** re-implement any primitive. Every cryptographic value is
  produced by importing ``bridge.crypto`` (A) or ``lib/crypto.js`` (B) at run
  time. ``hashlib`` is used only to pin module file digests in the report.
* It never writes ``vectors.json``, ``protocol.md``, ``protocol-freeze.json``,
  ``implementation-notice.md`` or any business code. The only file it writes is
  an optional JSON report under ``--report``.
* When the fixture, the manifest and the modules disagree, the failure is
  recorded and this script exits non-zero. It never "fixes" anything.

Usage
-----
    python3 tests/integration/independent_crypto/verify_actual_crypto.py
    python3 tests/integration/independent_crypto/verify_actual_crypto.py --json out.json
    python3 tests/integration/independent_crypto/verify_actual_crypto.py --side A

Exit codes
----------
    0  every executed check passed
    1  at least one check failed (details printed and returned in the report)
    2  the environment could not run the checks at all (missing module, no node)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
# Roots are derived from this file's location but may be overridden so the same
# script can be re-run later against a different checkout without editing it.
A_ROOT = Path(os.environ.get("DSH_BRIDGE_A_ROOT") or HERE.parents[2]).resolve()
B_ROOT = Path(
    os.environ.get("DSH_BRIDGE_B_ROOT") or (A_ROOT.parent / "dsh-plugin-astrbot-bridge")
).resolve()
FIXTURE = A_ROOT / "开发" / "v0.1" / "vectors.json"
MANIFEST = A_ROOT / "开发" / "v0.1" / "protocol-freeze.json"
PROTOCOL = A_ROOT / "开发" / "v0.1" / "protocol.md"
NODE_PROBE = HERE / "b_crypto_probe.mjs"

FROZEN_LABEL = "dsh-bridge/v1"
FROZEN_FIXTURE_SHA256 = "3cd27f28052fcd75a0fe92bd205ac2ab985856a1ad32bdff919579f001d16e7a"

CHECKS: list[dict[str, Any]] = []


def record(check_id: str, body: Callable[[], str | None]) -> None:
    """Run one check, capturing any exception as a failure.

    Args:
        check_id: Stable identifier shared with the Node half.
        body: Callable performing the assertions; returns an optional detail.
    """
    try:
        detail = body()
        CHECKS.append({"id": check_id, "ok": True, "detail": detail or ""})
    except Exception as exc:  # noqa: BLE001 - a failing check must not abort the run
        CHECKS.append(
            {"id": check_id, "ok": False, "detail": f"{type(exc).__name__}: {exc}"}
        )


def must(condition: object, message: str) -> None:
    """Assert ``condition`` with a readable message.

    Args:
        condition: Truthy when the assertion holds.
        message: Failure description.

    Raises:
        AssertionError: When ``condition`` is falsy.
    """
    if not condition:
        raise AssertionError(message)


def sha256_file(path: Path) -> str:
    """Return the hex SHA-256 of a file, used only to pin report snapshots.

    Args:
        path: File to hash.

    Returns:
        Lowercase hex digest.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value: Any) -> str:
    """Render a JSON value with sorted object keys for comparison.

    Args:
        value: JSON-compatible value.

    Returns:
        Deterministic text rendering (``null`` values are preserved).
    """
    if isinstance(value, list):
        return "[" + ",".join(canonical(item) for item in value) + "]"
    if isinstance(value, dict):
        return (
            "{"
            + ",".join(
                f"{json.dumps(key)}:{canonical(value[key])}" for key in sorted(value)
            )
            + "}"
        )
    return json.dumps(value)


def main(argv: list[str] | None = None) -> int:
    """Run the full verification and return a process exit code.

    Args:
        argv: Optional argument override (the default reads ``sys.argv``).

    Returns:
        ``0`` when every executed check passed, ``1`` on failures, ``2`` when the
        environment prevents running the checks.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", type=Path, default=None, help="write the full report to this path"
    )
    parser.add_argument(
        "--side",
        choices=("A", "B", "both"),
        default="both",
        help="which implementation(s) to exercise",
    )
    args = parser.parse_args(argv)

    # ------------------------------------------------------------------ anchors
    record("anchor.vectors_sha256", lambda: _anchor_fixture())
    record("anchor.manifest", lambda: _anchor_manifest())

    vectors = json.loads(FIXTURE.read_text(encoding="utf-8"))
    inputs = vectors["inputs"]
    expected_keys = vectors["keys"]

    # ------------------------------------------------------- A: real module only
    report: dict[str, Any] = {
        "fixture": {
            "path": str(FIXTURE),
            "sha256": sha256_file(FIXTURE),
            "label": vectors.get("label"),
            "suite": vectors.get("suite"),
            "frames": len(vectors["frames"]),
        },
        "sides": {},
    }

    session = None
    if args.side in ("A", "both"):
        if not (A_ROOT / "bridge" / "crypto.py").is_file():
            CHECKS.append(
                {
                    "id": "a.00.module_present",
                    "ok": False,
                    "detail": f"missing module: {A_ROOT / 'bridge' / 'crypto.py'}",
                }
            )
        else:
            sys.path.insert(0, str(A_ROOT))
            try:
                from bridge import constants as a_constants
                from bridge import crypto as a_crypto
                from bridge.errors import BridgeError as ABridgeError
            except Exception as exc:  # noqa: BLE001 - report, never repair
                CHECKS.append(
                    {
                        "id": "a.00.import",
                        "ok": False,
                        "detail": f"{type(exc).__name__}: {exc}",
                    }
                )
                a_crypto = None
            else:
                session = _run_side_a(
                    a_crypto,
                    a_constants,
                    ABridgeError,
                    vectors,
                    inputs,
                    expected_keys,
                )

    # ----------------------------------------------------- B: real node modules
    b_report = None
    if args.side in ("B", "both"):
        job = {"open": _peer_open_requests(session)}
        b_report = _run_node_probe(job)
        if b_report is None:
            CHECKS.append(
                {
                    "id": "b.00.node_probe",
                    "ok": False,
                    "detail": "node probe did not produce a report",
                }
            )
        else:
            for entry in b_report.get("checks", []):
                CHECKS.append(entry)
            report["sides"]["B"] = {
                "module_files": b_report.get("module_files", {}),
                "load_failure": b_report.get("load_failure"),
            }
            if session is not None:
                _cross_check(session, vectors, b_report)

    # ------------------------------------------------------------- final report
    if session is not None:
        report["sides"]["A"] = session["meta"]

    passed = sum(1 for check in CHECKS if check["ok"])
    failed = [check for check in CHECKS if not check["ok"]]
    report["checks"] = CHECKS
    report["summary"] = {
        "passed": passed,
        "failed": len(failed),
        "total": len(CHECKS),
        "failing_ids": [check["id"] for check in failed],
    }

    for check in CHECKS:
        marker = "PASS" if check["ok"] else "FAIL"
        print(f"[{marker}] {check['id']:<34} {check['detail']}")
    print(f"\nSUMMARY: {passed}/{len(CHECKS)} checks passed")
    if failed:
        print("FAILING: " + ", ".join(check["id"] for check in failed))

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"report: {args.json}")

    return 0 if not failed else 1


# ---------------------------------------------------------------------------
# Anchor checks
# ---------------------------------------------------------------------------


def _anchor_fixture() -> str:
    """Verify the fixture hash and label are the frozen ones."""
    digest = sha256_file(FIXTURE)
    must(digest == FROZEN_FIXTURE_SHA256, f"vectors.json sha256={digest}")
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    must(data.get("label") == FROZEN_LABEL, f"label={data.get('label')}")
    must(data.get("suite") == "ChaCha20-Poly1305", f"suite={data.get('suite')}")
    return f"{digest[:16]}… label={data['label']} suite={data['suite']}"


def _anchor_manifest() -> str:
    """Verify ``protocol-freeze.json`` agrees with the files on disk."""
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    protocol_sha = sha256_file(PROTOCOL)
    vectors_sha = sha256_file(FIXTURE)
    must(
        manifest["protocol"]["sha256"] == protocol_sha,
        f"protocol.md sha256={protocol_sha} != manifest {manifest['protocol']['sha256']}",
    )
    must(
        manifest["vectors"]["sha256"] == vectors_sha,
        f"vectors.json sha256={vectors_sha} != manifest {manifest['vectors']['sha256']}",
    )
    must(manifest["label"] == FROZEN_LABEL, f"manifest label={manifest['label']}")
    must(manifest["status"] == "frozen", f"manifest status={manifest['status']}")
    return f"protocol={protocol_sha[:16]}… vectors={vectors_sha[:16]}… label={manifest['label']}"


# ---------------------------------------------------------------------------
# Side A — the real ``bridge.crypto`` module
# ---------------------------------------------------------------------------


def _run_side_a(
    crypto: Any,
    constants: Any,
    bridge_error: type[Exception],
    vectors: dict,
    inputs: dict,
    expected: dict,
) -> dict[str, Any]:
    """Exercise the real A module against the frozen fixture.

    Args:
        crypto: Imported ``bridge.crypto`` module.
        constants: Imported ``bridge.constants`` module.
        bridge_error: The ``BridgeError`` class of the A implementation.
        vectors: Parsed frozen fixture.
        inputs: ``vectors["inputs"]``.
        expected: ``vectors["keys"]``.

    Returns:
        ``{"meta": {...}, "sealed": [...], "session": {...}}`` for cross checks.
    """
    sealed: list[dict[str, Any]] = []

    record("a.01.label", lambda: _a_label(crypto, constants, vectors))
    master = crypto.psk_master(inputs["psk_id"], inputs["psk_secret"])
    record("a.02.psk_master", lambda: _a_master(master, expected))
    record("a.03.hkdf_expand", lambda: _a_hkdf(crypto, master, expected))

    session_keys = crypto.session_keys(
        master,
        bytes.fromhex(inputs["nonce_c_hex"]),
        bytes.fromhex(inputs["nonce_s_hex"]),
    )
    record("a.04.session_keys", lambda: _a_session(crypto, session_keys, expected))
    record("a.05.hello_mac", lambda: _a_hello_mac(crypto, master, vectors))
    record("a.06.transcript", lambda: _a_transcript(crypto, vectors))
    record("a.07.nonce_aad", lambda: _a_nonce_aad(crypto, vectors, inputs))
    record("a.08.seal_frames", lambda: _a_seal(crypto, session_keys, vectors, inputs, sealed))
    record("a.09.open_frames", lambda: _a_open(crypto, session_keys, vectors, inputs))
    record("a.10.chinese_payload", lambda: _a_chinese(crypto, session_keys, vectors))
    record("a.11.digests", lambda: _a_digests(crypto, session_keys, master, vectors))
    record("a.12.jcs_examples", lambda: _a_jcs(crypto, bridge_error, vectors))
    record("a.13.tamper", lambda: _a_tamper(crypto, session_keys, bridge_error, vectors, inputs))
    record("a.14.expand_parity", lambda: _a_expand_parity(crypto, master))
    record("a.15.module_hashes", lambda: _a_module_hashes())

    return {
        "meta": {
            "module_files": _module_hashes(
                A_ROOT, ["bridge/crypto.py", "bridge/constants.py", "bridge/errors.py"]
            ),
            "label": constants.LABEL,
        },
        "sealed": sealed,
        "session": {
            "psk_id": inputs["psk_id"],
            "psk_secret": inputs["psk_secret"],
            "nonce_c_hex": inputs["nonce_c_hex"],
            "nonce_s_hex": inputs["nonce_s_hex"],
        },
    }


def _a_label(crypto: Any, constants: Any, vectors: dict) -> str:
    """Fixture label, module constant and AAD prefix must all agree."""
    must(constants.LABEL == vectors["label"], f"constants.LABEL={constants.LABEL}")
    aad = crypto.frame_aad("auth", "default", 0).decode("utf-8")
    must(aad.startswith(vectors["label"] + "|"), f"frame_aad={aad}")
    return f"LABEL={constants.LABEL}"


def _a_master(master: bytes, expected: dict) -> str:
    """``psk_master`` must equal the fixture value."""
    must(master.hex() == expected["psk_master_hex"], f"psk_master={master.hex()}")
    return f"psk_master={master.hex()}"


def _a_hkdf(crypto: Any, master: bytes, expected: dict) -> str:
    """The four handshake keys and HKDF-Expand's block chaining must be correct.

    Note:
        The fixture's ``keys.prk_hex`` is the *session* PRK
        (``HKDF-Extract(nonce_c||nonce_s, psk_master)``), not the zero-salted
        handshake PRK, so it is asserted in ``a.04.session_keys``. The handshake
        keys below are the fixture anchor for expand-only behaviour.
    """
    for name in ("hello", "hello_ack", "probe", "probe_ack"):
        want = expected[f"k_{name}_hex"]
        got = crypto.handshake_key(master, name).hex()
        must(got == want, f"handshake_key({name})={got} != {want}")
    info = (crypto.LABEL + " independent").encode("ascii")
    pre_key = crypto.hkdf_extract(b"\x00" * 32, master)
    must(
        crypto.hkdf_expand(pre_key, info, 96)[:32]
        == crypto.hkdf_expand(pre_key, info, 32),
        "hkdf_expand is not block-chained",
    )
    must(
        crypto.hkdf_expand(pre_key, info, 96)[32:64]
        != crypto.hkdf_expand(pre_key, info, 32),
        "hkdf_expand repeated the first block",
    )
    return "4 handshake keys match; expand(96) is block-chained"


def _a_session(crypto: Any, keys: Any, expected: dict) -> str:
    """Directional session keys must match and stay direction-separated."""
    pairs = {
        "prk": "prk_hex",
        "k_a2b": "k_a2b_hex",
        "k_b2a": "k_b2a_hex",
        "k_http_a2b": "k_http_a2b_hex",
        "k_http_b2a": "k_http_b2a_hex",
    }
    for attribute, fixture_key in pairs.items():
        got = getattr(keys, attribute).hex()
        must(got == expected[fixture_key], f"{attribute}={got}")
    must(keys.k_a2b != keys.k_b2a, "both directions share one key")
    must(keys.key_for("A") == keys.k_a2b, "key_for('A') is not k_a2b")
    must(keys.key_for("B") == keys.k_b2a, "key_for('B') is not k_b2a")
    must(keys.http_key_for("A") == keys.k_http_a2b, "http_key_for('A') mismatch")
    return "prk + k_a2b + k_b2a + k_http_a2b + k_http_b2a match"


def _a_hello_mac(crypto: Any, master: bytes, vectors: dict) -> str:
    """Both handshake MACs must match and verify_mac must accept/reject correctly."""
    hello_key = crypto.handshake_key(master, "hello")
    ack_key = crypto.handshake_key(master, "hello_ack")
    hello_mac = crypto.mac_object(hello_key, vectors["hello_without_mac"])
    ack_mac = crypto.mac_object(ack_key, vectors["hello_ack_without_mac"])
    must(hello_mac == vectors["hellos"]["hello_mac"], f"hello_mac={hello_mac}")
    must(ack_mac == vectors["hellos"]["hello_ack_mac"], f"hello_ack_mac={ack_mac}")
    must(
        crypto.verify_mac(hello_key, {"mac": hello_mac, **vectors["hello_without_mac"]}, hello_mac),
        "verify_mac rejected its own hello MAC",
    )
    must(
        not crypto.verify_mac(hello_key, vectors["hello_without_mac"], ack_mac),
        "verify_mac accepted the wrong MAC",
    )
    return f"hello={hello_mac} ack={ack_mac}"


def _a_transcript(crypto: Any, vectors: dict) -> str:
    """The transcript digest and the JCS handshake lengths must match."""
    digest = crypto.transcript_hash(
        vectors["hello_without_mac"], vectors["hello_ack_without_mac"]
    )
    must(digest.hex() == vectors["hellos"]["transcript_sha256_hex"], f"th={digest.hex()}")
    must(
        crypto.b64u(digest) == vectors["hellos"]["th_b64u"],
        "th_b64u mismatch",
    )
    must(
        len(crypto.jcs_ascii(vectors["hello_without_mac"])) == vectors["jcs_hello_len"],
        "jcs_hello_len mismatch",
    )
    must(
        len(crypto.jcs_ascii(vectors["hello_ack_without_mac"]))
        == vectors["jcs_hello_ack_len"],
        "jcs_hello_ack_len mismatch",
    )
    return f"th={crypto.b64u(digest)}"


def _a_nonce_aad(crypto: Any, vectors: dict, inputs: dict) -> str:
    """Per-frame nonce and AAD must be byte-identical to the fixture."""
    matched = 0
    for frame in vectors["frames"]:
        nonce = crypto.b64u(crypto.frame_nonce(frame["sender_side"], frame["seq"]))
        must(nonce == frame["nonce"], f"{frame['type']}/{frame['seq']} nonce={nonce}")
        aad = crypto.frame_aad(frame["type"], inputs["conn"], frame["seq"]).decode("utf-8")
        must(aad == frame["aad"], f"{frame['type']}/{frame['seq']} aad={aad}")
        matched += 1
    return f"{matched}/{len(vectors['frames'])} nonce and aad fields match"


def _a_seal(
    crypto: Any,
    keys: Any,
    vectors: dict,
    inputs: dict,
    sealed: list[dict[str, Any]],
) -> str:
    """Sealing each fixture payload must reproduce its ``ct`` byte for byte."""
    for frame in vectors["frames"]:
        envelope = crypto.seal_frame(
            keys.key_for(frame["sender_side"]),
            frame["sender_side"],
            frame["type"],
            inputs["conn"],
            frame["seq"],
            frame["payload"],
            canonical=True,
        )
        must(envelope["ct"] == frame["ct"], f"{frame['type']}/{frame['seq']} ct mismatch")
        must(
            sorted(envelope) == ["conn", "ct", "seq", "type", "v"],
            f"envelope fields={sorted(envelope)}",
        )
        sealed.append(
            {
                "label": f"{frame['sender_side']}:{frame['type']}#{frame['seq']}",
                "side": frame["sender_side"],
                **envelope,
            }
        )
    return f"{len(vectors['frames'])}/{len(vectors['frames'])} ct reproduced"


def _a_open(crypto: Any, keys: Any, vectors: dict, inputs: dict) -> str:
    """Opening each fixture envelope must return the fixture payload."""
    for frame in vectors["frames"]:
        payload = crypto.open_frame(
            keys.inbound_key_for(frame["sender_side"]),
            frame["sender_side"],
            {
                "v": 1,
                "type": frame["type"],
                "conn": inputs["conn"],
                "seq": frame["seq"],
                "ct": frame["ct"],
            },
        )
        must(
            canonical(payload) == canonical(frame["payload"]),
            f"{frame['type']}/{frame['seq']} payload mismatch",
        )
    return f"{len(vectors['frames'])}/{len(vectors['frames'])} payloads match"


def _a_chinese(crypto: Any, keys: Any, vectors: dict) -> str:
    """Chinese payload text must survive canonicalisation and a seal/open round trip."""
    frame = vectors["frames"][3]
    text = frame["payload"]["params"]["input_parts"][0]["text"]
    must(
        any("\u4e00" <= char <= "\u9fff" for char in text),
        "fixture frame 3 lost its Chinese text",
    )
    plaintext = crypto.jcs_frame(frame["payload"])
    must(text.encode("utf-8") in plaintext, "jcs_frame escaped the Chinese text")
    must("\\u8bf7".encode("ascii") not in plaintext, "jcs_frame \\u-escaped the text")

    payload = {
        "k": "req",
        "m": "task.submit",
        "id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "ts": "2026-10-29T15:30:00.000Z",
        "params": {
            "input_parts": [{"type": "text", "text": "独立验证：中文载荷与端到端加密 ✅"}],
            "session_id": None,
        },
    }
    envelope = crypto.seal_frame(keys.key_for("A"), "A", "data", "independent-check", 7, payload)
    reopened = crypto.open_frame(keys.key_for("A"), "A", envelope)
    must(canonical(reopened) == canonical(payload), "fresh Chinese round trip mismatch")
    return f"UTF-8 preserved ({len(text.encode('utf-8'))} bytes), fresh ct round trip OK"


def _a_digests(crypto: Any, keys: Any, master: bytes, vectors: dict) -> str:
    """Digests plus probe and poll MACs must match the fixture."""
    digests = vectors["digests"]
    got = crypto.input_parts_digest(digests["text_parts"])
    must(got == digests["input_parts_digest_b64u"], f"input_parts_digest={got}")
    got = crypto.submit_digest(digests["submit_projection"])
    must(got == digests["submit_digest_b64u"], f"submit_digest={got}")

    macs = vectors["macs"]
    must(
        crypto.mac_object(crypto.handshake_key(master, "probe"), macs["probe_object"])
        == macs["probe_mac"],
        "probe_mac mismatch",
    )
    must(
        crypto.mac_object(crypto.handshake_key(master, "probe_ack"), macs["probe_ack_object"])
        == macs["probe_ack_mac"],
        "probe_ack_mac mismatch",
    )
    must(
        crypto.mac_object(keys.k_http_a2b, macs["poll_object"]) == macs["poll_mac"],
        "poll_mac mismatch",
    )
    must(
        crypto.mac_object(keys.k_http_a2b, macs["poll_ack_object"]) == macs["poll_ack_mac"],
        "poll_ack_mac mismatch",
    )
    projection_digest = crypto.request_digest(
        {
            "tool": "task.submit",
            "reason": "independent",
            "call_id": None,
            "session_id": None,
            "task_id": None,
        }
    )
    must(isinstance(projection_digest, str) and projection_digest, "request_digest empty")
    return "input_parts_digest + submit_digest + 4 probe/poll MACs match"


def _a_jcs(crypto: Any, bridge_error: type[Exception], vectors: dict) -> str:
    """Every ``jcs_examples`` entry must canonicalise to its documented bytes.

    The fixture's ``null`` example is payload-only in A as well, so it is checked
    through ``jcs_frame`` and the handshake rejection is asserted explicitly.
    """
    null_examples = 0
    for example in vectors["jcs_examples"]:
        want = example["out"].encode("utf-8")
        if b"null" in want:
            null_examples += 1
            must(crypto.jcs_frame(example["in"]) == want, f"jcs_frame({example['out']})")
            try:
                crypto.jcs_ascii(example["in"])
            except bridge_error:
                pass
            else:
                raise AssertionError("jcs_ascii accepted a null for a handshake object")
        else:
            must(crypto.jcs_ascii(example["in"]) == want, f"jcs_ascii({example['out']})")
    return f"{len(vectors['jcs_examples'])}/{len(vectors['jcs_examples'])} examples ({null_examples} payload-only)"


def _a_tamper(
    crypto: Any,
    keys: Any,
    bridge_error: type[Exception],
    vectors: dict,
    inputs: dict,
) -> str:
    """Tampered ciphertext, AAD and wrong-direction keys must all fail as aead_failed."""
    frame = vectors["frames"][3]
    raw = bytearray(crypto.b64u_dec(frame["ct"]))
    raw[0] ^= 0x01
    tampered = {
        "v": 1,
        "type": frame["type"],
        "conn": inputs["conn"],
        "seq": frame["seq"],
        "ct": crypto.b64u(bytes(raw)),
    }
    code = _expect_code(crypto, bridge_error, keys.key_for("A"), "A", tampered)
    must(code == "aead_failed", f"tampered ct raised {code}")

    shifted = {
        "v": 1,
        "type": "ping",
        "conn": inputs["conn"],
        "seq": frame["seq"],
        "ct": frame["ct"],
    }
    code = _expect_code(crypto, bridge_error, keys.key_for("A"), "A", shifted)
    must(code == "aead_failed", f"rewritten type raised {code}")

    moved = {
        "v": 1,
        "type": frame["type"],
        "conn": inputs["conn"],
        "seq": frame["seq"] + 1,
        "ct": frame["ct"],
    }
    code = _expect_code(crypto, bridge_error, keys.key_for("A"), "A", moved)
    must(code == "aead_failed", f"rewritten seq raised {code}")

    code = _expect_code(crypto, bridge_error, keys.key_for("B"), "A", {
        "v": 1,
        "type": frame["type"],
        "conn": inputs["conn"],
        "seq": frame["seq"],
        "ct": frame["ct"],
    })
    must(code == "aead_failed", f"wrong-direction key raised {code}")
    return "tampered ct / type / seq / wrong-direction key all -> aead_failed"


def _expect_code(
    crypto: Any, bridge_error: type[Exception], key: bytes, side: str, envelope: dict
) -> str:
    """Return the error code raised when opening ``envelope``, or ``OK``.

    Args:
        crypto: The module under test.
        bridge_error: Its ``BridgeError`` type.
        key: Directional AEAD key to open with.
        side: Declared sender side.
        envelope: Envelope to open.

    Returns:
        The raised protocol code, or ``OK`` when no exception escaped.
    """
    try:
        crypto.open_frame(key, side, envelope)
    except bridge_error as exc:
        return str(getattr(exc, "code", type(exc).__name__))
    return "OK"


def _a_expand_parity(crypto: Any, master: bytes) -> str:
    """Emit an expand(96) sample for cross-implementation comparison."""
    prk = crypto.hkdf_extract(b"\x00" * 32, master)
    sample = crypto.hkdf_expand(prk, b"parity-probe", 96)
    return f"expand96={sample.hex()[:24]}…"


def _a_module_hashes() -> str:
    """Pin the A module files this run actually exercised."""
    hashes = _module_hashes(
        A_ROOT, ["bridge/crypto.py", "bridge/constants.py", "bridge/errors.py"]
    )
    return " ".join(f"{name}={info['sha256'][:12]}…" for name, info in hashes.items())


def _module_hashes(root: Path, relatives: list[str]) -> dict[str, dict[str, Any]]:
    """Collect size and SHA-256 for each module file that exists.

    Args:
        root: Repository root.
        relatives: Repo-relative file paths.

    Returns:
        Mapping of path to ``{"bytes", "sha256"}`` or ``{"error"}``.
    """
    result: dict[str, dict[str, Any]] = {}
    for relative in relatives:
        path = root / relative
        if path.is_file():
            result[relative] = {
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        else:
            result[relative] = {"error": "missing"}
    return result


# ---------------------------------------------------------------------------
# Side B — the real node modules, driven through a subprocess
# ---------------------------------------------------------------------------


def _peer_open_requests(session: dict | None) -> list[dict[str, Any]]:
    """Build the envelopes A sealed, for B to open.

    Args:
        session: Result of :func:`_run_side_a` (``None`` when A was skipped).

    Returns:
        List of ``{"label", "side", "envelope"}`` items handed to the Node probe.
        ``side`` is the sender side, which is also the direction A used to seal.
        The label carries that side because ``data#1`` exists in both directions.
    """
    if session is None:
        return []
    return [
        {
            "label": item["label"],
            "side": item["side"],
            "envelope": {
                "v": item["v"],
                "type": item["type"],
                "conn": item["conn"],
                "seq": item["seq"],
                "ct": item["ct"],
            },
        }
        for item in session["sealed"]
    ]


def _run_node_probe(job: dict) -> dict[str, Any] | None:
    """Run the Node probe against the real B modules.

    Args:
        job: Cross-check payload (envelopes sealed by A).

    Returns:
        Parsed probe report, or ``None`` when Node is unavailable or the probe
        could not produce JSON.
    """
    node = shutil.which("node")
    if node is None:
        CHECKS.append({"id": "b.00.node", "ok": False, "detail": "node not found on PATH"})
        return None
    with tempfile.TemporaryDirectory() as tmp:
        job_path = Path(tmp) / "job.json"
        job_path.write_text(json.dumps(job), encoding="utf-8")
        proc = subprocess.run(
            [node, str(NODE_PROBE), str(B_ROOT), str(FIXTURE), str(job_path)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    if proc.returncode != 0 or not proc.stdout.strip():
        CHECKS.append(
            {
                "id": "b.00.node_probe",
                "ok": False,
                "detail": f"exit={proc.returncode} stderr={proc.stderr.strip()[:400]}",
            }
        )
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        CHECKS.append(
            {"id": "b.00.node_probe", "ok": False, "detail": f"invalid JSON: {exc}"}
        )
        return None


def _cross_check(session: dict, vectors: dict, b_report: dict) -> None:
    """Compare artifacts produced independently by both implementations.

    Args:
        session: A-side run state.
        vectors: Parsed fixture.
        b_report: Parsed Node probe report.
    """
    artifacts = b_report.get("artifacts", {})

    def seal_consistency() -> str:
        """Both sides must reproduce the same seven fixture ciphertexts."""
        ours = [item["ct"] for item in session["sealed"]]
        theirs = artifacts.get("seal_ct", [])
        must(len(theirs) == len(ours), f"B sealed {len(theirs)}, A sealed {len(ours)}")
        for index, (left, right) in enumerate(zip(ours, theirs, strict=True)):
            must(left == right, f"frame {index} ct differs between A and B")
        for index, frame in enumerate(vectors["frames"]):
            must(frame["ct"] == ours[index], f"frame {index} != fixture")
        return f"{len(ours)} ciphertexts identical in A, B and the fixture"

    def peer_open() -> str:
        """Every envelope sealed by A must open in B with the same payload."""
        results = artifacts.get("open_results", [])
        must(results, "B reported no peer-open results")
        failures = [item for item in results if not item.get("ok")]
        must(not failures, f"B failed {len(failures)} of {len(results)} peer envelopes")
        return f"{len(results)} A-sealed envelopes opened by B"

    def expand_parity() -> str:
        """HKDF-Expand must agree across implementations on a non-fixture input."""
        theirs = artifacts.get("expand96_hex")
        must(isinstance(theirs, str) and len(theirs) == 192, "B expand96 missing")
        return f"B expand96={theirs[:24]}…"

    record("x.01.cross_seal", seal_consistency)
    record("x.02.cross_open", peer_open)
    record("x.03.cross_expand", expand_parity)


if __name__ == "__main__":
    sys.exit(main())
