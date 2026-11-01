/**
 * Node-side half of the independent crypto verification.
 *
 * This file is a *driver*, not an implementation: every cryptographic value it
 * reports comes from the real B module (`lib/crypto.js` + `lib/constants.js`)
 * imported at run time. Nothing is re-implemented here, so a divergence in the
 * probe can only mean a divergence in the module under test.
 *
 * Usage:
 *   node b_crypto_probe.mjs <B_ROOT> <fixture.json> [job.json]
 *
 * `job.json` is optional and carries peer-produced artifacts the probe must
 * consume:
 *   { "open": [ { "side": "A", "envelope": { "v":1, "type":"data", ... } } ] }
 *
 * The probe prints one JSON object on stdout and exits 0 whenever the module
 * could be loaded; individual check failures are reported inside that object so
 * the caller can distinguish "module broken" from "module unloadable".
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [, , bRootArg, fixtureArg, jobArg] = process.argv;
if (!bRootArg || !fixtureArg) {
  console.error('usage: node b_crypto_probe.mjs <B_ROOT> <fixture.json> [job.json]');
  process.exit(2);
}

const B_ROOT = path.resolve(bRootArg);
const checks = [];
const artifacts = {};

/**
 * Record one check result, catching any thrown value so a single failure never
 * hides the remaining checks.
 * @param {string} id - stable check id shared with the Python half.
 * @param {() => string|void} body - check body; may return a detail string.
 * @returns {void}
 */
function check(id, body) {
  try {
    const detail = body();
    checks.push({ id, ok: true, detail: detail ?? '' });
  } catch (error) {
    checks.push({
      id,
      ok: false,
      detail: `${error?.name ?? 'Error'}: ${error?.message ?? String(error)}`,
    });
  }
}

/**
 * Assert a condition with a readable failure message.
 * @param {boolean} condition - value that must be true.
 * @param {string} message - failure description.
 * @returns {void}
 */
function must(condition, message) {
  if (!condition) throw new Error(message);
}

/** Deep-equality via a key-sorted JSON rendering (payloads are plain JSON). */
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

const fixture = JSON.parse(readFileSync(fixtureArg, 'utf8'));
const job = jobArg ? JSON.parse(readFileSync(jobArg, 'utf8')) : {};

let crypto;
let constants;
let BridgeError;
let loadFailure = null;
try {
  crypto = await import(pathToFileURL(path.join(B_ROOT, 'lib', 'crypto.js')).href);
  constants = await import(pathToFileURL(path.join(B_ROOT, 'lib', 'constants.js')).href);
  ({ BridgeError } = await import(pathToFileURL(path.join(B_ROOT, 'lib', 'errors.js')).href));
} catch (error) {
  loadFailure = `${error?.name ?? 'Error'}: ${error?.message ?? String(error)}`;
}

if (loadFailure !== null) {
  process.stdout.write(
    JSON.stringify({
      side: 'B',
      module_files: {},
      load_failure: loadFailure,
      checks: [{ id: 'b.00.import', ok: false, detail: loadFailure }],
      artifacts: {},
    }),
  );
  process.exit(0);
}

/** Hex view of a Buffer, used for reporting only. */
const hex = (value) => Buffer.from(value).toString('hex');

const INPUTS = fixture.inputs;
const KEYS = fixture.keys;
const MACS = fixture.macs;

const MASTER = crypto.pskMaster(INPUTS.psk_id, INPUTS.psk_secret);
const SESSION = crypto.sessionKeys(
  MASTER,
  Buffer.from(INPUTS.nonce_c_hex, 'hex'),
  Buffer.from(INPUTS.nonce_s_hex, 'hex'),
);

// --- B.01 label constant agrees with the frozen fixture -----------------------------
check('b.01.label', () => {
  must(constants.LABEL === fixture.label, `LABEL=${constants.LABEL} != ${fixture.label}`);
  // Derivation and AAD must use the same constant; prove it via pskMaster output.
  must(
    crypto
      .pskMaster(INPUTS.psk_id, INPUTS.psk_secret)
      .toString('hex') === KEYS.psk_master_hex,
    'pskMaster does not use the frozen LABEL',
  );
  return `LABEL=${constants.LABEL}`;
});

// --- B.02 psk_master ---------------------------------------------------------------
check('b.02.psk_master', () => {
  const actual = hex(MASTER);
  must(actual === KEYS.psk_master_hex, `psk_master=${actual}`);
  return `psk_master=${actual}`;
});

// --- B.03 HKDF-Expand (expand-only, RFC 5869) --------------------------------------
check('b.03.hkdf_expand', () => {
  // `keys.prk_hex` in the fixture is the *session* PRK, so it is asserted below
  // in b.06. The four handshake keys are the fixture anchor for expand-only use.
  const prk = crypto.hkdfExtract(Buffer.alloc(32), MASTER);

  for (const name of ['hello', 'hello_ack', 'probe', 'probe_ack']) {
    const expected = KEYS[`k_${name}_hex`];
    const info = Buffer.from(`${constants.LABEL} ${name}`, 'utf8');
    const actual = hex(crypto.hkdfExpand(prk, info, 32));
    must(actual === expected, `expand(${name})=${actual} != ${expected}`);
    must(hex(crypto.handshakeKey(MASTER, name)) === expected, `handshakeKey(${name})`);
  }

  // RFC 5869 §2.3 block chaining: a longer request must extend the shorter one.
  const info = Buffer.from(`${constants.LABEL}  independent`, 'utf8');
  const short = crypto.hkdfExpand(prk, info, 32);
  const long = crypto.hkdfExpand(prk, info, 96);
  must(long.subarray(0, 32).equals(short), 'expand is not block-chained');
  must(!long.subarray(32, 64).equals(short), 'expand repeated the first block');

  // A 96-byte request must actually be contiguous 96 bytes, not a short view.
  must(long.length === 96, `expand(96) length=${long.length}`);
  return '4 handshake keys match; expand(96) is block-chained';
});

// --- B.04 hello / hello_ack MACs ---------------------------------------------------
check('b.04.hello_mac', () => {
  const helloMac = crypto.macObject(
    crypto.handshakeKey(MASTER, 'hello'),
    fixture.hello_without_mac,
  );
  const ackMac = crypto.macObject(
    crypto.handshakeKey(MASTER, 'hello_ack'),
    fixture.hello_ack_without_mac,
  );
  must(helloMac === fixture.hellos.hello_mac, `hello_mac=${helloMac}`);
  must(ackMac === fixture.hellos.hello_ack_mac, `hello_ack_mac=${ackMac}`);
  must(
    crypto.verifyMac(crypto.handshakeKey(MASTER, 'hello'), fixture.hello_without_mac, helloMac),
    'verifyMac rejected its own hello MAC',
  );
  must(
    !crypto.verifyMac(
      crypto.handshakeKey(MASTER, 'hello'),
      fixture.hello_without_mac,
      ackMac,
    ),
    'verifyMac accepted the wrong MAC',
  );
  artifacts.hello_mac = helloMac;
  artifacts.hello_ack_mac = ackMac;
  return `hello=${helloMac} ack=${ackMac}`;
});

// --- B.05 transcript th ------------------------------------------------------------
check('b.05.transcript', () => {
  const th = crypto.handshakeTranscript(fixture.hello_without_mac, fixture.hello_ack_without_mac);
  must(
    hex(th) === fixture.hellos.transcript_sha256_hex,
    `th=${hex(th)} != ${fixture.hellos.transcript_sha256_hex}`,
  );
  must(crypto.b64u(th) === fixture.hellos.th_b64u, 'th_b64u mismatch');
  must(
    Buffer.byteLength(crypto.jcsAscii(fixture.hello_without_mac)) === fixture.jcs_hello_len,
    'jcs_hello_len mismatch',
  );
  must(
    Buffer.byteLength(crypto.jcsAscii(fixture.hello_ack_without_mac)) ===
      fixture.jcs_hello_ack_len,
    'jcs_hello_ack_len mismatch',
  );
  artifacts.th_b64u = fixture.hellos.th_b64u;
  return `th=${crypto.b64u(th)}`;
});

// --- B.06 directional keys ---------------------------------------------------------
check('b.06.session_keys', () => {
  const expected = {
    prk: KEYS.prk_hex,
    kA2b: KEYS.k_a2b_hex,
    kB2a: KEYS.k_b2a_hex,
    kHttpA2b: KEYS.k_http_a2b_hex,
    kHttpB2a: KEYS.k_http_b2a_hex,
  };
  for (const [field, want] of Object.entries(expected)) {
    must(hex(SESSION[field]) === want, `${field}=${hex(SESSION[field])} != ${want}`);
  }
  must(!SESSION.kA2b.equals(SESSION.kB2a), 'directions share one key');
  return 'prk + kA2b + kB2a + kHttpA2b + kHttpB2a match';
});

// --- B.07 nonce / AAD per frame ----------------------------------------------------
check('b.07.nonce_aad', () => {
  for (const frame of fixture.frames) {
    const nonce = crypto.b64u(crypto.frameNonce(frame.sender_side, frame.seq));
    must(nonce === frame.nonce, `${frame.type}/${frame.seq} nonce=${nonce}`);
    const aad = crypto.frameAad(frame.type, INPUTS.conn, frame.seq).toString('utf8');
    must(aad === frame.aad, `${frame.type}/${frame.seq} aad=${aad}`);
  }
  return `${fixture.frames.length}/${fixture.frames.length} nonce and aad fields match`;
});

// --- B.08 seal every fixture frame -------------------------------------------------
const sealedCts = [];
check('b.08.seal_frames', () => {
  for (const frame of fixture.frames) {
    const envelope = crypto.sealFrame(
      SESSION,
      frame.sender_side,
      frame.type,
      INPUTS.conn,
      frame.seq,
      frame.payload,
    );
    must(envelope.ct === frame.ct, `${frame.type}/${frame.sender_side}#${frame.seq} ct mismatch`);
    const fields = Object.keys(envelope).sort().join(',');
    must(fields === 'conn,ct,seq,type,v', `envelope fields=${fields}`);
    sealedCts.push(envelope.ct);
  }
  return `${sealedCts.length}/${fixture.frames.length} ct reproduced`;
});

// --- B.09 open every fixture frame -------------------------------------------------
check('b.09.open_frames', () => {
  const opened = [];
  for (const frame of fixture.frames) {
    const payload = crypto.openFrame(SESSION, frame.sender_side, {
      v: 1,
      type: frame.type,
      conn: INPUTS.conn,
      seq: frame.seq,
      ct: frame.ct,
    });
    must(
      canonical(payload) === canonical(frame.payload),
      `${frame.type}/${frame.seq} payload mismatch`,
    );
    opened.push(canonical(payload));
  }
  artifacts.opened = opened;
  return `${opened.length}/${fixture.frames.length} payloads match`;
});

// --- B.10 Chinese payload stays UTF-8 on the wire ----------------------------------
check('b.10.chinese_payload', () => {
  const text = fixture.frames[3].payload.params.input_parts[0].text;
  must(/[\u4e00-\u9fff]/u.test(text), 'fixture frame 3 lost its Chinese text');

  const plaintext = crypto.framePlaintext(fixture.frames[3].payload);
  must(plaintext.includes(Buffer.from(text, 'utf8')), 'plaintext escaped the Chinese text');
  must(!plaintext.includes(Buffer.from('\\u8bf7', 'utf8')), 'plaintext \\u-escaped ASCII-wise');
  must(plaintext.equals(Buffer.from(crypto.jcsFrame(fixture.frames[3].payload), 'utf8')), 'jcsFrame mismatch');
  artifacts.chinese_plaintext_hex = plaintext.toString('hex');
  return `UTF-8 preserved (${Buffer.byteLength(text)} bytes), no \\uXXXX escaping`;
});

// --- B.11 digests and HTTP MACs ----------------------------------------------------
check('b.11.digests', () => {
  const inputParts = crypto.inputPartsDigest(fixture.digests.text_parts);
  must(inputParts === fixture.digests.input_parts_digest_b64u, `input_parts_digest=${inputParts}`);
  const submit = crypto.submitDigest(fixture.digests.submit_projection);
  must(submit === fixture.digests.submit_digest_b64u, `submit_digest=${submit}`);
  must(
    crypto.macObject(SESSION.kHttpA2b, MACS.poll_object) === MACS.poll_mac,
    'poll_mac mismatch',
  );
  must(
    crypto.macObject(SESSION.kHttpA2b, MACS.poll_ack_object) === MACS.poll_ack_mac,
    'poll_ack_mac mismatch',
  );
  must(
    crypto.macObject(crypto.handshakeKey(MASTER, 'probe'), MACS.probe_object) === MACS.probe_mac,
    'probe_mac mismatch',
  );
  must(
    crypto.macObject(crypto.handshakeKey(MASTER, 'probe_ack'), MACS.probe_ack_object) ===
      MACS.probe_ack_mac,
    'probe_ack_mac mismatch',
  );
  return 'input_parts_digest + submit_digest + 4 HTTP/probe MACs match';
});

// --- B.12 jcs examples -------------------------------------------------------------
check('b.12.jcs_examples', () => {
  let nullExamples = 0;
  for (const example of fixture.jcs_examples) {
    const want = example.out;
    if (want.includes('null')) {
      nullExamples += 1;
      must(crypto.jcsFrame(example.in) === want, `jcsFrame(${want})`);
    } else {
      must(crypto.jcsAscii(example.in) === want, `jcsAscii(${want})`);
    }
  }
  return `${fixture.jcs_examples.length}/${fixture.jcs_examples.length} examples (${nullExamples} payload-only)`;
});

// --- B.13 tampered ciphertext ------------------------------------------------------
check('b.13.tamper', () => {
  const frame = fixture.frames[3];
  const body = crypto.b64uDec(frame.ct);
  body[0] ^= 0x01;
  let code = null;
  try {
    crypto.openFrame(SESSION, frame.sender_side, {
      v: 1,
      type: frame.type,
      conn: INPUTS.conn,
      seq: frame.seq,
      ct: crypto.b64u(body),
    });
  } catch (error) {
    code = error instanceof BridgeError ? error.code : `NOT_BridgeError:${error?.message}`;
  }
  must(code === 'aead_failed', `tamper raised ${code}`);
  artifacts.tamper_code = code;
  return 'tampered ct -> aead_failed';
});

// --- B.14 fresh Chinese payload (non-fixture inputs) -------------------------------
const chinesePayload = {
  k: 'req',
  m: 'task.submit',
  id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
  ts: '2026-10-29T15:30:00.000Z',
  params: {
    input_parts: [{ type: 'text', text: '独立验证：中文载荷与端到端加密 ✅' }],
    session_id: null,
  },
};
const chineseEnvelope = { v: 1, type: 'data', conn: 'independent-check', seq: 7 };
check('b.14.chinese_fresh_seal', () => {
  const envelope = crypto.sealFrame(
    SESSION,
    'A',
    chineseEnvelope.type,
    chineseEnvelope.conn,
    chineseEnvelope.seq,
    chinesePayload,
  );
  const opened = crypto.openFrame(SESSION, 'A', envelope);
  must(canonical(opened) === canonical(chinesePayload), 'round trip payload mismatch');
  artifacts.chinese_ct = envelope.ct;
  artifacts.chinese_plaintext_len = Buffer.byteLength(crypto.framePlaintext(chinesePayload));
  return `ct=${envelope.ct.length} chars, round trip OK`;
});

// --- B.15 open peer-produced envelopes (from A) ------------------------------------
const openResults = [];
check('b.15.open_peer', () => {
  for (const item of job.open ?? []) {
    try {
      const payload = crypto.openFrame(SESSION, item.side, item.envelope);
      openResults.push({ label: item.label, ok: true, payload: canonical(payload) });
    } catch (error) {
      openResults.push({
        label: item.label,
        ok: false,
        error: `${error?.name}: ${error?.message ?? String(error)}`,
      });
    }
  }
  const failed = openResults.filter((item) => !item.ok);
  must(failed.length === 0, `${failed.length} peer envelopes failed to open`);
  return `${openResults.length} peer envelopes opened`;
});

// --- B.16 expand parity with A on a non-fixture input ------------------------------
check('b.16.expand_parity', () => {
  const prk = crypto.hkdfExtract(Buffer.alloc(32), MASTER);
  artifacts.expand96_hex = hex(crypto.hkdfExpand(prk, Buffer.from('parity-probe', 'utf8'), 96));
  return 'expand96 emitted for cross-implementation comparison';
});

/** sha256 of a file, so the report can pin the exact module snapshot. */
function fileDigest(file) {
  return readFileSync(file);
}

const moduleFiles = {};
for (const relative of ['lib/crypto.js', 'lib/constants.js', 'lib/errors.js']) {
  try {
    moduleFiles[relative] = {
      bytes: fileDigest(path.join(B_ROOT, relative)).length,
      sha256: crypto.sha256(fileDigest(path.join(B_ROOT, relative))).toString('hex'),
    };
  } catch (error) {
    moduleFiles[relative] = { error: String(error?.message ?? error) };
  }
}

process.stdout.write(
  JSON.stringify(
    {
      side: 'B',
      module_files: moduleFiles,
      load_failure: null,
      checks,
      artifacts: {
        ...artifacts,
        seal_ct: sealedCts,
        open_results: openResults,
      },
    },
    null,
    1,
  ),
);
process.exit(0);
