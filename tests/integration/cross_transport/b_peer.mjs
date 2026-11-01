#!/usr/bin/env node
/**
 * B-side (DSH) peer process for the cross-language transport harness.
 *
 * Test scaffolding only: it imports the real `lib/session.js`, `lib/router.js`
 * and `lib/transport/*.js` modules from the B checkout and drives them over a
 * real loopback socket. It patches nothing; the only wrapping it does is a
 * transparent recording proxy so the harness can observe handshake objects, the
 * `seq` allocation and inbound envelopes.
 *
 * Control channel: JSON lines on stdin; events as JSON lines on the control fd
 * (inherited pipe, default 3), which keeps the control stream separate from the
 * bridge's own stdout logging.
 *
 * The registered handlers simply echo their params. They exercise the real
 * Router + Session byte path and MUST NOT be reported as task execution.
 *
 * @module astrbot_plugin_dsh_bridge/tests/integration/cross_transport/b_peer
 */

import readline from 'node:readline';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const fs = require('node:fs');

const B_ROOT = process.env.DSH_BRIDGE_B_ROOT;
if (!B_ROOT) {
  process.stderr.write('DSH_BRIDGE_B_ROOT is required\n');
  process.exit(2);
}

const { Session, buildCaps } = await import(`${B_ROOT}/lib/session.js`);
const { Router } = await import(`${B_ROOT}/lib/router.js`);
const { WsTransport } = await import(`${B_ROOT}/lib/transport/ws.js`);
const { WebhookTransport } = await import(`${B_ROOT}/lib/transport/webhook.js`);
const { LongPollTransport } = await import(`${B_ROOT}/lib/transport/longpoll.js`);

/** Control pipe fd, assigned by the parent so the peer never guesses. */
const CONTROL_FD = Number(process.env.DSH_BRIDGE_CONTROL_FD ?? 3);

/** Message names whose handlers this peer answers with an echo. */
const ECHO_MESSAGES = ['task.status', 'task.list_open', 'event.ack', 'approval.lookup', 'session.list'];

/**
 * Parse one `--name value` style argument list.
 * @param {string[]} argv - process arguments (without node/script).
 * @returns {Record<string,string>} parsed options.
 */
function parseArgs(argv) {
  const out = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) continue;
    out[token.slice(2)] = argv[index + 1];
    index += 1;
  }
  return out;
}

const options = parseArgs(process.argv.slice(2));
const transportName = options.transport;
const mode = options.mode;
const peerPort = Number(options['peer-port']);
const bindPort = Number(options['bind-port'] ?? 0);
const connPath = options.path ?? '/dsh-bridge';
const connId = options.conn ?? 'default';
const pskId = options['psk-id'];
const pskSecret = options['psk-secret'];
const pollWaitS = Number(options['poll-wait-s'] ?? 2);
const handshakeTimeoutMs = Number(options['handshake-timeout-ms'] ?? 20000);
/** Probe period for the webhook carrier (§7.3 rule 5); overview-only knob. */
const probeIntervalMs = Number(options['probe-interval-s'] ?? 30) * 1000;

/** Whether the control pipe is still writable. */
let controlOpen = true;

/**
 * Write one event line to the control pipe.
 * @param {object} object - event payload.
 * @returns {void}
 */
function emit(object) {
  if (!controlOpen) return;
  try {
    fs.writeSync(CONTROL_FD, `${JSON.stringify(object)}\n`);
  } catch {
    controlOpen = false;
  }
}

// B resolves two addresses per connection: the peer it POSTs to and the local
// endpoint it binds for reverse delivery (§7.3 bidirectional reachability).
// `peerHost`/`peerPort` and `bindHost`/`bindPort` name them explicitly, which is
// what the harness always supplies so a peer can never be this endpoint.
const conn = {
  id: connId,
  pskId,
  pskSecret,
  mode,
  host: '127.0.0.1',
  port: mode === 'connect' ? peerPort : bindPort || peerPort,
  peerHost: '127.0.0.1',
  peerPort,
  bindHost: '127.0.0.1',
  bindPort: mode === 'listen' ? bindPort || peerPort : bindPort || 0,
  path: connPath,
  tlsEnabled: false,
  allowPrivateAddr: false,
};

/**
 * Build the B-side caps object with the real builder (§4.5).
 * @returns {object} caps.
 */
function capsFor() {
  return buildCaps({
    side: 'B',
    host: 'dsh',
    version: '0.1.0',
    transports: [transportName],
    tls: false,
    rolesInitiate: true,
    rolesExecute: true,
    approvals: { business_decision: true, cross_end_submit: true, native_tool: true },
    attachments: {
      mime: ['image/gif', 'image/jpeg', 'image/png', 'image/webp'],
      max_bytes: 10_485_760,
      max_count: 4,
      max_total_bytes: 20_971_520,
      max_pixels: 64_000_000,
      max_dimension: 8192,
    },
  });
}

/**
 * Create the selected carrier.
 * @returns {object} transport instance.
 */
function makeTransport() {
  if (transportName === 'ws') return new WsTransport();
  if (transportName === 'webhook') return new WebhookTransport({ probeIntervalMs });
  if (transportName === 'longpoll') return new LongPollTransport({ pollWaitS });
  throw new Error(`unknown transport ${transportName}`);
}

/** Observations of the current attempt, reset by `reconnect`. */
const observed = {
  sentPlain: [],
  repliedPlain: [],
  sentEnvelopes: [],
  receivedPlain: [],
  receivedEnvelopes: [],
  messages: [],
  securityEvents: [],
  states: [],
  pollAcks: [],
  pollsServed: [],
};

/** Monotonic counters of the current attempt (numbers cannot share `observed`). */
const counters = { pollRounds: 0 };

/** The live link, replaced wholesale on reconnect. */
let link = null;

/**
 * Build one router that echoes the request vocabulary.
 * @param {object} session - session the replies are sent through.
 * @returns {object} router.
 */
function makeRouter(session) {
  const router = new Router();
  for (const name of ECHO_MESSAGES) {
    router.register(name, 'req', async (params, context) => ({
      echo: params,
      handled_by: 'B',
      router_m: context.message.m,
    }));
  }
  router.setReplySink(async (message) => session.sendMessage(message));
  return router;
}

/**
 * Create and start a brand-new session over a brand-new carrier.
 * @returns {Promise<string|null>} failure code, or null on success.
 */
async function startFresh() {
  const transport = makeTransport();
  const session = new Session(
    {
      conn,
      side: 'B',
      role: mode === 'listen' ? 'responder' : 'initiator',
      transportName,
      caps: capsFor(),
      handshakeTimeoutMs,
      reqTimeoutS: 10,
    },
    transport,
    {
      onMessage: async (message) => {
        observed.messages.push(message);
        const router = link?.router;
        if (router === undefined) return;
        await router.dispatch(message);
      },
      onSecurityEvent: (event) => observed.securityEvents.push(event),
      onState: (state) => observed.states.push(state),
    },
  );
  const router = makeRouter(session);

  // Observe inbound handshake objects and envelopes. The session wires its
  // carrier hooks as closures over these methods, so wrapping them observes
  // every inbound object without patching library code.
  const realOnPlain = session._onPlain.bind(session);
  session._onPlain = (object) => {
    observed.receivedPlain.push({ ...object });
    return realOnPlain(object);
  };
  const realOnEnvelope = session._onEnvelope.bind(session);
  session._onEnvelope = (envelope) => {
    observed.receivedEnvelopes.push({ ...envelope });
    return realOnEnvelope(envelope);
  };

  // Transparent recording proxies: the real carrier still performs every send.
  const realSendEnvelope = transport.sendEnvelope.bind(transport);
  transport.sendEnvelope = async (envelope) => {
    observed.sentEnvelopes.push({ ...envelope });
    return realSendEnvelope(envelope);
  };
  const realSendPlain = transport.sendPlain.bind(transport);
  transport.sendPlain = async (object) => {
    observed.sentPlain.push({ ...object });
    return realSendPlain(object);
  };
  if (typeof transport.respondPlain === 'function') {
    const realRespondPlain = transport.respondPlain.bind(transport);
    transport.respondPlain = (object) => {
      observed.repliedPlain.push({ ...object });
      return realRespondPlain(object);
    };
  }
  // Downstream evidence (§7.4): count the polls this endpoint *made* and record
  // the `acks` it sent for frames those polls handed back. A frame can only be
  // acked after a poll delivered it, so an ack naming `evt#<seq>` is proof the
  // event arrived over GET /poll rather than being pushed.
  if (typeof transport._pollOnce === 'function') {
    const realPollOnce = transport._pollOnce.bind(transport);
    transport._pollOnce = async () => {
      counters.pollRounds += 1;
      return realPollOnce();
    };
  }
  if (typeof transport._sendAck === 'function') {
    const realSendAck = transport._sendAck.bind(transport);
    transport._sendAck = async (refs) => {
      observed.pollAcks.push([...refs]);
      return realSendAck(refs);
    };
  }
  // Downstream evidence, listening side (§7.4): record every poll this endpoint
  // *served*. The real handler still writes the response; the wrapper only reads
  // back what it did — `statusCode` (`200` with `frames`, `204` empty window,
  // `4xx` on a rejected MAC) and whether the body carried frames. The body is
  // captured by teeing `res.end` for the duration of this one call, because the
  // handler returns `undefined` and the frames only exist as written bytes.
  if (typeof transport._onPoll === 'function') {
    const realOnPoll = transport._onPoll.bind(transport);
    transport._onPoll = async (req, res) => {
      const realEnd = res.end.bind(res);
      let captured = '';
      res.end = (chunk, ...rest) => {
        if (chunk !== undefined && chunk !== null) captured += Buffer.from(chunk).toString('utf8');
        return realEnd(chunk, ...rest);
      };
      try {
        return await realOnPoll(req, res);
      } finally {
        res.end = realEnd;
        let body = null;
        try {
          body = captured === '' ? null : JSON.parse(captured);
        } catch {
          body = null;
        }
        observed.pollsServed.push({
          status: res.statusCode,
          has_frames: Array.isArray(body?.frames) && body.frames.length > 0,
        });
      }
    };
  }

  link = { session, transport, router };
  try {
    await session.start();
  } catch (error) {
    try {
      await transport.stop();
    } catch {
      // Already torn down by the failed start.
    }
    return error?.code ?? String(error);
  }
  return null;
}

/**
 * Current state snapshot handed to the parent.
 * @returns {object} snapshot without secret material.
 */
function snapshot() {
  const session = link?.session;
  return {
    state: session?.state ?? 'none',
    sid: session?.sid ?? null,
    peer_caps_side: session?.peerCaps?.side ?? null,
    sent_plain_types: observed.sentPlain.map((item) => item.type),
    received_plain_types: observed.receivedPlain.map((item) => item.type),
    received_plain: observed.receivedPlain,
    replied_plain: observed.repliedPlain,
    sent_plain: observed.sentPlain,
    received_envelope_types: observed.receivedEnvelopes.map((item) => item.type),
    received_envelopes: observed.receivedEnvelopes,
    sent_envelope_seqs: observed.sentEnvelopes.map((item) => item.seq),
    sent_envelope_types: observed.sentEnvelopes.map((item) => item.type),
    sent_envelopes: observed.sentEnvelopes,
    security_events: observed.securityEvents,
    states: observed.states,
    received: observed.messages,
    // Downstream evidence: polls made, polls *served* (the listening side), the
    // frames acked (only a poll can produce these), and whether this endpoint
    // owns an inbound server.
    poll_rounds: counters.pollRounds,
    poll_acks: observed.pollAcks,
    polls_served: observed.pollsServed,
    has_server: link?.transport?._server != null,
    has_runner: link?.transport?._server != null,
    bound_port: link?.transport?.boundPort ?? 0,
    carrier: typeof link?.transport?.diagnostics === 'function' ? link.transport.diagnostics() : null,
  };
}

/**
 * Whether an inbound message matches a filter.
 * @param {object} message - inbound message.
 * @param {object} match - filter with optional `m` (message name) and `id`.
 * @returns {boolean} true when every given field matches.
 */
function matches(message, match) {
  if (match === undefined) return true;
  if (match.m !== undefined && message.m !== match.m) return false;
  if (match.id !== undefined && message.id !== match.id) return false;
  if (match.k !== undefined && message.k !== match.k) return false;
  return true;
}

/**
 * Execute one command.
 * @param {object} cmd - command object with `op`.
 * @returns {Promise<object>} reply payload.
 */
async function handle(cmd) {
  if (cmd.op === 'snapshot') return { event: 'snapshot', ...snapshot() };
  if (cmd.op === 'call') {
    try {
      const result = await link.session.call(cmd.m, cmd.params ?? {}, Number(cmd.timeout_s ?? 10));
      return { event: 'result', ok: true, result };
    } catch (error) {
      return { event: 'result', ok: false, error: { code: error?.code ?? String(error) } };
    }
  }
  if (cmd.op === 'emit') {
    await link.session.sendMessage({
      k: 'evt',
      m: cmd.m,
      id: cmd.id_value,
      ts: new Date().toISOString(),
      params: cmd.params ?? {},
    });
    // Report the sealed frame the session allocated for this emit so the harness
    // can correlate it with the peer's inbound `evt` by `seq`.
    return {
      event: 'emitted',
      sent_envelope: observed.sentEnvelopes.at(-1) ?? null,
      own_seqs: observed.sentEnvelopes.filter((item) => item.type === 'data').map((item) => item.seq),
    };
  }
  if (cmd.op === 'wait_messages') {
    const want = Number(cmd.count ?? 1);
    const match = cmd.match;
    const deadline = Date.now() + Number(cmd.timeout_s ?? 10) * 1000;
    const seen = () => observed.messages.filter((message) => matches(message, match));
    while (seen().length < want && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    return {
      event: 'messages',
      messages: observed.messages,
      matched: seen(),
      count: seen().length,
      total: observed.messages.length,
    };
  }
  if (cmd.op === 'burst') {
    const count = Number(cmd.count ?? 100);
    const message = cmd.m ?? 'task.status';
    const settled = await Promise.allSettled(
      Array.from({ length: count }, (_, index) =>
        link.session.call(message, { task_id: `burst-${index}` }, 15),
      ),
    );
    const failures = settled
      .filter((entry) => entry.status === 'rejected')
      .map((entry) => ({ code: entry.reason?.code ?? String(entry.reason) }));
    return {
      event: 'burst',
      count,
      failures,
      seqs: observed.sentEnvelopes.map((item) => item.seq),
      types: observed.sentEnvelopes.map((item) => item.type),
    };
  }
  if (cmd.op === 'reconnect') {
    // A session is single-use (one sid, one nonce pair): reconnecting means
    // tearing down the carrier and building a brand-new session (§6.3, §7.4).
    await link.session.close('draining', 'reconnect');
    for (const list of Object.values(observed)) list.length = 0;
    const failure = await startFresh();
    if (failure !== null) return { event: 'reconnect_error', code: failure };
    return { event: 'reconnected', ...snapshot() };
  }
  if (cmd.op === 'close') {
    await link.session.close('draining', 'harness_done');
    return { event: 'closed' };
  }
  return { event: 'unknown_op', op: cmd.op };
}

const startFailure = await startFresh();
if (startFailure !== null) {
  emit({ event: 'start_error', code: startFailure, detail: String(startFailure).slice(0, 200) });
  process.exit(3);
}
emit({ event: 'ready', ...snapshot() });

const rl = readline.createInterface({ input: process.stdin });
for await (const line of rl) {
  const trimmed = line.trim();
  if (trimmed === '') continue;
  const cmd = JSON.parse(trimmed);
  const reply = await handle(cmd);
  reply.id = cmd.id ?? null;
  emit(reply);
  if (cmd.op === 'close') break;
}
try {
  await link.session.close('draining', 'harness_done');
} catch {
  // Session may already be closed by the peer.
}
process.exit(0);
