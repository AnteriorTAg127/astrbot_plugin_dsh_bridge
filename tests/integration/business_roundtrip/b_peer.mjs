#!/usr/bin/env node
/**
 * B-side (DSH) peer process for the business round-trip acceptance suite.
 *
 * Test scaffolding only: it imports the *real* B modules and runs the real
 * composition path for one connection — `Supervisor` (real `TransportManager`,
 * real `Session`, real `Router`, real `TaskService` / `NotifyService` /
 * `ApprovalService` / `SessionService`, real durable `BridgeStore` under a
 * temporary root) over a real loopback WebSocket to the A peer. It patches no
 * bridge module.
 *
 * What is stubbed is the host boundary, and only that, marked `M`:
 *   - `ctx.agents` — a recording registry whose agents never call a model, so
 *     "the peer's agent ran once" is a real delivery, not a model answer;
 *   - `ctx.attachments` — unused by these cases (no image transfer);
 *   - `ctx.tools` — the model-facing tool registry (no model is present).
 * The approval seam is *not* stubbed: `ctx` is a real Cordis `Context`, so the
 * real `@deepseek-ai/dsh-user-approval` service is mounted, `ctx.waterfall(…)`
 * behaves as in the harness, and `ApprovalService.attach()` installs the real
 * listener.
 *
 * Control channel: commands are JSON lines on stdin; events are JSON lines
 * appended to the file named by `DSH_BR_CONTROL_PATH`, which keeps the control
 * stream off the child's stdout logging and needs no POSIX fd passing.
 */

import { appendFileSync } from 'node:fs';
import readline from 'node:readline';

const B_ROOT = process.env.DSH_BR_CONTROL_B_ROOT;
const CONTROL_PATH = process.env.DSH_BR_CONTROL_PATH;
const DATA_ROOT = process.env.DSH_BR_DATA_ROOT;
if (!B_ROOT || !CONTROL_PATH || !DATA_ROOT) {
  process.stderr.write('DSH_BR_CONTROL_B_ROOT, DSH_BR_CONTROL_PATH and DSH_BR_DATA_ROOT are required\n');
  process.exit(2);
}

const { Context, Service } = await import(`${B_ROOT}/node_modules/@deepseek-ai/cordis/lib/index.js`);
const { Supervisor, normaliseConfig } = await import(`${B_ROOT}/lib/index.js`);
const { BridgeStore } = await import(`${B_ROOT}/lib/store.js`);
const { Logger } = await import(`${B_ROOT}/lib/log.js`);
const { AgentHost } = await import(`${B_ROOT}/lib/host/agents.js`);
const { AttachmentHost } = await import(`${B_ROOT}/lib/host/attachments.js`);
const UserApproval = await import(`${B_ROOT}/node_modules/@deepseek-ai/dsh-user-approval/lib/index.js`);

/** Provide one Cordis service under a fixed name. */
class Facility extends Service {
  /**
   * @param {Context} ctx - owning context.
   * @param {string} name - service name.
   */
  constructor(ctx, name) {
    super(ctx, name);
  }
}

/**
 * Recording agent registry (`ctx.agents`) — the host/model boundary, marked `M`.
 *
 * It never contacts a model. Each delivery is counted, and `whenIdle()` settles
 * on the next macrotask so `TaskService._runInbound` can reach `succeeded` for
 * real; a held session stays busy until `release()`.
 */
/**
 * Host default model (`ctx.get('agentDefaultModel')`) — the policy source that
 * B's v0.3 delivery boundary requires before it will drive an agent at all.
 *
 * The real DSH host exposes this service; a harness without it makes every task
 * fail with `no_model_route`, which is not what these end-to-end cases measure.
 */
class DefaultModel extends Facility {
  /**
   * @param {Context} ctx - owning context.
   */
  constructor(ctx) {
    super(ctx, 'agentDefaultModel');
  }

  /**
   * @returns {{provider: string, model: string}} the harness default route.
   */
  currentSelection() {
    return { provider: 'harness', model: 'harness-model' };
  }
}

class RecordingAgents extends Facility {
  /**
   * @param {Context} ctx - owning context.
   * @param {number} [delayMs] - test-only delay before a delivery is counted.
   */
  constructor(ctx, delayMs = 0) {
    super(ctx, 'agents');
    /** @type {Map<string, object>} */
    this.map = new Map();
    /** @type {Array<{session_id: string, strategy: string, text: string}>} */
    this.deliveries = [];
    /** @type {Set<string>} */
    this.held = new Set();
    // A real delay makes the wait* timeout unit observable (>60ms, <seconds).
    this.delayMs = Math.max(0, Number(delayMs) || 0);
  }

  /** @returns {{id: string, status: string}[]} */
  list() {
    return [...this.map.values()].map((agent) => ({ id: agent.id, status: agent.status }));
  }

  /**
   * @param {string} sessionId - session id.
   * @returns {object|undefined}
   */
  get(sessionId) {
    return this.map.get(String(sessionId));
  }

  /**
   * @param {object} input - `{sessionId}`.
   * @returns {Promise<object>}
   */
  async create(input) {
    return { agent: this._agent(input.sessionId), dispose: async () => {} };
  }

  /**
   * @param {object} input - `{resumeSessionId}`.
   * @returns {Promise<object>}
   */
  async resume(input) {
    return { agent: this._agent(input.resumeSessionId), dispose: async () => {} };
  }

  /** @param {string} sessionId - session id. @returns {void} */
  release(sessionId) {
    const agent = this.map.get(String(sessionId));
    this.held.delete(String(sessionId));
    if (agent !== undefined) {
      this._emitTurnEnd(agent);
      agent._release();
    }
  }

  /**
   * Publish one durable `turn/end` for a delivery.
   * @param {object} agent - agent that finished the turn.
   * @returns {void}
   */
  _emitTurnEnd(agent) {
    // v0.3 R6 extracts the assistant text before deciding success: a turn that
    // ends without any assistant output must be parked, not reported as a
    // completed task with an empty result. The real host appends both events,
    // so the harness publishes them in the same order.
    // The bridge can only attribute a turn it saw open: the real host appends
    // `turn/start` before any assistant output, so the harness must do the same
    // or every delivery is classified unknown and parked for a human.
    this._turnSeq = (this._turnSeq ?? 0) + 1;
    this.ctx.emit('session/event', { id: agent.id }, {
      type: 'turn/start',
      seq: this._turnSeq,
      time: Date.now(),
      data: { turn: 1 },
    });
    this._turnSeq += 1;
    this.ctx.emit('session/event', { id: agent.id }, {
      type: 'assistant/message',
      seq: this._turnSeq,
      time: Date.now(),
      data: {
        turn: 1,
        step: 0,
        message: {
          content: [{ type: 'text', text: 'harness assistant reply' }],
          source: { provider: 'harness', model: 'harness-model' },
        },
      },
    });
    this._turnSeq += 1;
    this.ctx.emit('session/event', { id: agent.id }, {
      type: 'turn/end',
      seq: this._turnSeq,
      time: Date.now(),
      data: { turn: 1, reason: { kind: 'completed' } },
    });
  }

  /** @param {string} sessionId - session id. @returns {void} */
  hold(sessionId) {
    this.held.add(String(sessionId));
  }

  /**
   * @param {string} sessionId - session id.
   * @returns {object} agent.
   */
  _agent(sessionId) {
    const id = String(sessionId);
    const existing = this.map.get(id);
    if (existing !== undefined) return existing;
    /** @type {Array<() => void>} */
    let idleWaiters = [];
    const agents = this;
    const agent = {
      id,
      status: 'idle',
      options: {},
      _release() {
        agent.status = 'idle';
        const waiters = idleWaiters;
        idleWaiters = [];
        for (const resolve of waiters) resolve();
      },
      followup(message) {
        agents._record(agent, 'followup', message);
      },
      steer(message) {
        agents._record(agent, 'steer', message);
      },
      inject(message) {
        agents._record(agent, 'inject', message);
      },
      whenIdle() {
        if (agent.status !== 'running') return Promise.resolve();
        return new Promise((resolve) => idleWaiters.push(resolve));
      },
    };
    this.map.set(id, agent);
    return agent;
  }

  /**
   * @param {object} agent - fake agent.
   * @param {string} strategy - delivery strategy.
   * @param {object} message - message object.
   * @returns {void}
   */
  _record(agent, strategy, message) {
    const text = (message?.content ?? [])
      .map((block) => (block?.type === 'text' ? String(block.text ?? '') : ''))
      .join('');
    // Busy is claimed before the delay, so `whenIdle()` cannot resolve while the
    // delivery is still pending; the delivery itself lands after `delayMs`.
    agent.status = 'running';
    const commit = () => {
      this.deliveries.push({ session_id: agent.id, strategy, text });
      if (!this.held.has(agent.id)) {
        // v0.3 R6: the bridge only claims success when it can attribute a
        // completed `turn/end` to this delivery. The real host publishes that
        // durable session event, so the harness must too.
        this._emitTurnEnd(agent);
        setImmediate(() => agent._release());
      }
    };
    if (this.delayMs > 0) setTimeout(commit, this.delayMs);
    else commit();
  }
}

/** `ctx.attachments` — unused here (no image case), present so caps are honest. */
class Attachments extends Facility {
  /** @param {Context} ctx - owning context. */
  constructor(ctx) {
    super(ctx, 'attachments');
  }
}

/** `ctx.tools` — the model-facing registry; no model is present in this process. */
class Tools extends Facility {
  /** @param {Context} ctx - owning context. */
  constructor(ctx) {
    super(ctx, 'tools');
    /** @type {Map<string, object>} */
    this.registered = new Map();
  }

  /**
   * @param {object} definition - tool definition.
   * @returns {() => void} disposer.
   */
  register(definition) {
    this.registered.set(definition.name, definition);
    return () => {
      this.registered.delete(definition.name);
    };
  }
}

const connId = process.env.DSH_BR_CONN ?? 'business';
const pskId = process.env.DSH_BR_PSK_ID;
const pskSecret = process.env.DSH_BR_PSK_SECRET;
const peerPort = Number(process.env.DSH_BR_PEER_PORT);
// Test-only: makes a delivery take measurable wall-clock time so the wait*
// command timeout units can be checked against a real delay.
const deliveryDelayMs = Number(process.env.DSH_BR_DELIVERY_DELAY_MS ?? 0);

let controlOpen = true;

/**
 * Append one control event.
 * @param {object} object - event payload.
 * @returns {void}
 */
function emit(object) {
  if (!controlOpen) return;
  try {
    appendFileSync(CONTROL_PATH, `${JSON.stringify(object)}\n`);
  } catch {
    controlOpen = false;
  }
}

/**
 * Deterministic error code for any thrown value.
 * @param {unknown} error - thrown value.
 * @returns {string} code.
 */
function codeOf(error) {
  return String(error?.code ?? error?.name ?? error);
}

const logger = new Logger('business-peer');

const app = new Context();
const agents = new RecordingAgents(app, deliveryDelayMs);
new DefaultModel(app);
new Attachments(app);
new Tools(app);
// The real harness approval service, mounted exactly as the deployment does.
new UserApproval.ApprovalService(app, { policy: 'ask' });

const store = new BridgeStore({ dataRoot: DATA_ROOT, logger: logger.child('store') });
await store.init();

const settings = normaliseConfig({
  side: 'B',
  remoteNativeApproval: true,
  approvalTimeoutSeconds: Number(process.env.DSH_BR_APPROVAL_TIMEOUT ?? 600),
  heartbeatInterval: 5,
  reconnectMaxBackoff: 2,
  wakeMaxChain: 8,
  wakeRatePerMinute: 10,
});

const connection = {
  id: connId,
  mode: 'connect',
  transport: 'ws',
  transportFallback: [],
  host: '127.0.0.1',
  port: peerPort,
  bindHost: '',
  bindPort: 0,
  peerHost: '',
  peerPort: 0,
  path: '/dsh-bridge',
  tlsEnabled: false,
  pskId,
  pskSecret,
  allowPrivateAddr: false,
};

const agentHost = new AgentHost({ ctx: app, logger: logger.child('agents') });

const supervisor = new Supervisor({
  ctx: app,
  settings,
  connection,
  store,
  agentHost,
  attachmentHost: new AttachmentHost({ ctx: app }),
  logger: logger.child('conn'),
});

await supervisor.start();

/** Services of the live session, once ready. */
let services = null;

/**
 * Wake a session so a delivery strategy is observable.
 * @param {string} sessionId - session id.
 * @returns {void}
 */
function ensureAgent(sessionId) {
  const id = String(sessionId ?? '');
  if (id === '') return;
  if (agents.get(id) === undefined) agents._agent(id);
}

// The carrier loop reports readiness asynchronously, so readiness is observed the
// same way the host observes it: `readyServices()` becomes non-null after the
// real handshake, and every later session replaces it.
// Readiness has two parts, and only the second one makes a native request
// claimable: the session must be wired (`readyServices()`), and the approval
// bridge must be attached to the real `approval/request` waterfall. Attachment is
// awaited inside `_startSession` *after* `readyServices()` becomes non-null, so a
// request sent in that window would delegate instead of claim and the harness would
// be testing a startup race. Both are therefore waited for here.
const readyDeadline = Date.now() + 45_000;
while (Date.now() < readyDeadline) {
  const ready = supervisor.readyServices();
  if (ready !== null) {
    services = ready;
    const approvals = ready.approvals;
    const needsBridge = approvals.remoteApprovalEnabled === true;
    if (!needsBridge || approvals._bridge !== null) {
      emit({ event: 'ready', state: supervisor.session.state, sid: supervisor.session.sid });
      break;
    }
  }
  await new Promise((resolve) => setTimeout(resolve, 25));
}
if (services === null) {
  emit({ event: 'start_error', code: 'not_ready', state: supervisor.session?.state ?? 'none' });
  process.exit(3);
}

/**
 * Wait until a predicate returns a truthy value, bounded.
 * @param {() => Promise<unknown>} probe - async predicate.
 * @param {number} timeoutMs - bound.
 * @returns {Promise<unknown>} the first truthy value.
 * @throws {Error} `timeout` when the bound expires.
 */
async function until(probe, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await probe();
    if (value) return value;
    if (Date.now() > deadline) throw new Error('timeout');
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

/**
 * Snapshot of every observable business fact on this side.
 * @returns {Promise<object>} snapshot.
 */
async function snapshot() {
  const tasks = await store.list('tasks');
  const notifies = await store.list('notifies');
  const approvals = await store.list('approvals');
  return {
    state: supervisor.session?.state ?? 'none',
    sid: supervisor.session?.sid ?? null,
    authz: await store.authzSnapshot(),
    tasks: tasks.map((task) => ({
      task_id: task.task_id,
      status: task.status,
      direction: task.direction,
      origin: task.origin,
      eseq: task.eseq ?? 0,
      attempts: task.attempts ?? 0,
      needs_human: task.needs_human === true,
      session_id: task.session_id ?? null,
      result: task.result ?? null,
      error: task.error ?? null,
    })),
    notifies: notifies.map((record) => ({
      notify_id: record.notify_id,
      delivered: record.delivered === true,
      attempts: record.attempts ?? 0,
      event: record.payload?.event ?? null,
      task_id: record.payload?.task_id ?? null,
    })),
    approvals: approvals.map((record) => ({
      approval_id: record.approval_id,
      approval_type: record.approval_type,
      decided: record.decided === true,
      outcome: record.decision?.outcome ?? null,
      channel: record.decision?.channel ?? null,
      session_id: record.session_id ?? null,
      expires_at: record.expires_at ?? null,
      source: record.source ?? null,
      gate_scope: record.gate_scope ?? null,
      conn: record.conn ?? null,
      released_by_task: record.released_by_task ?? null,
      consumed_by_task: record.consumed_by_task ?? null,
      submit_digest: record.submit_digest ?? null,
    })),
    deliveries: agents.deliveries.slice(),
  };
}

/** Pending native approvals claimed through the real waterfall. */
const nativePending = new Map();

/**
 * The live services, re-read from the supervisor so a reconnect is honoured.
 * @returns {object} services of the current session.
 */
function live() {
  const ready = supervisor.readyServices();
  if (ready !== null) services = ready;
  if (services === null) throw new Error('not_ready');
  return services;
}

/**
 * Execute one command object.
 * @param {object} cmd - command with `op`.
 * @returns {Promise<object>} reply payload (without the id).
 */
async function execute(cmd) {
  if (cmd.op === 'snapshot') return await snapshot();
  if (cmd.op === 'call') {
    try {
      const result = await supervisor.session.call(cmd.m, cmd.params ?? {}, Number(cmd.timeout_s ?? 20));
      return { event: 'result', ok: true, result };
    } catch (error) {
      return { event: 'result', ok: false, code: codeOf(error), details: error?.details ?? null };
    }
  }
  if (cmd.op === 'submit_outbound') {
    try {
      const result = await live().tasks.submitOutbound({
        text: String(cmd.text ?? ''),
        origin: cmd.origin ?? 'human',
        purpose: cmd.purpose ?? null,
        sessionId: cmd.session_id ?? null,
        toolHints: cmd.tool_hints ?? [],
        timeoutS: cmd.timeout_s ?? 300,
      });
      return { event: 'submitted', ok: true, ...result };
    } catch (error) {
      return { event: 'submitted', ok: false, code: codeOf(error) };
    }
  }
  if (cmd.op === 'submit_gated') {
    // Production path: the tool opens this side's human gate (approval.request to
    // the peer) and sends nothing until a human answers.
    try {
      const result = await live().tasks.submitOutbound({
        text: String(cmd.text ?? ''),
        origin: 'llm',
        purpose: cmd.purpose ?? null,
        sessionId: cmd.session_id ?? null,
        timeoutS: cmd.timeout_s ?? 300,
        requireApproval: true,
      });
      return { event: 'gated', ok: true, ...result };
    } catch (error) {
      return { event: 'gated', ok: false, code: codeOf(error) };
    }
  }
  if (cmd.op === 'wait_task') {
    const want = new Set(cmd.statuses ?? []);
    try {
      // `timeout_s` is seconds on the wire (the harness and the A-side peer both
      // read it as seconds); `until` is bounded in milliseconds.
      const task = await until(async () => {
        const stored = await store.getTask(String(cmd.task_id));
        if (stored === null) return null;
        return want.size === 0 || want.has(stored.status) ? stored : null;
      }, Number(cmd.timeout_s ?? 30) * 1000);
      return { event: 'task', task };
    } catch {
      return { event: 'task_timeout', task: await store.getTask(String(cmd.task_id)) };
    }
  }
  if (cmd.op === 'wait_delivery') {
    const count = Number(cmd.count ?? 1);
    try {
      // Same unit rule as `wait_task`: the wire value is seconds, `until` is ms.
      await until(
        async () => agents.deliveries.length >= count,
        Number(cmd.timeout_s ?? 20) * 1000,
      );
      return { event: 'delivered', count: agents.deliveries.length, deliveries: agents.deliveries };
    } catch {
      return { event: 'delivery_timeout', count: agents.deliveries.length, deliveries: agents.deliveries };
    }
  }
  if (cmd.op === 'hold') {
    agents.hold(String(cmd.session_id));
    return { event: 'held' };
  }
  if (cmd.op === 'release') {
    agents.release(String(cmd.session_id));
    return { event: 'released' };
  }
  if (cmd.op === 'ensure_agent') {
    ensureAgent(cmd.session_id);
    return { event: 'ensured' };
  }
  if (cmd.op === 'archive_session') {
    try {
      const result = await live().sessions.manage({
        session_id: String(cmd.session_id),
        action: 'archive',
      });
      return { event: 'archived', ...result };
    } catch (error) {
      return { event: 'archive_error', code: codeOf(error) };
    }
  }
  if (cmd.op === 'native_request') {
    // A genuine harness request: the real waterfall through the real Cordis
    // context. The promise is kept, because a claimed request only settles on a
    // human answer (or a fail-closed terminal event).
    const sessionId = String(cmd.session_id);
    const controller = new AbortController();
    const request = {
      agent: { session: { id: sessionId } },
      toolName: String(cmd.tool ?? 'bash'),
      reason: cmd.reason ?? null,
      signal: controller.signal,
    };
    const promise = Promise.resolve().then(() =>
      app.waterfall('approval/request', request, () => Promise.resolve('delegated')),
    );
    // The bridge persists its own record before it forwards, and settles that same
    // record `unavailable` if the peer refuses. Whether the record is still pending
    // is therefore a race against the refusal, not evidence about the peer: the
    // harness reports the id it minted and lets the case ask the *peer* whether the
    // request arrived.
    let approval;
    try {
      approval = await until(async () => {
        const rows = await store.list('approvals');
        return rows.find((row) => row.session_id === sessionId) ?? null;
      }, Number(cmd.timeout_s ?? 20) * 1000);
    } catch {
      return { event: 'native_request', ok: false, code: 'never_persisted' };
    }
    nativePending.set(approval.approval_id, { promise, controller });
    return {
      event: 'native_request',
      ok: true,
      approval_id: approval.approval_id,
      approval_type: approval.approval_type,
      expires_at: approval.expires_at,
      request_digest: approval.request_digest,
      // `decided` at this instant means the forward already failed and the claim
      // settled closed; `outcome` names the settlement so a case can report it.
      settled_on_arrival: approval.decided === true,
      outcome: approval.decision?.outcome ?? null,
      channel: approval.decision?.channel ?? null,
    };
  }
  if (cmd.op === 'native_diag') {
    const approvals = live().approvals;
    return {
      event: 'diag',
      remoteApprovalEnabled: approvals.remoteApprovalEnabled,
      sessionKey: approvals._sessionKey,
      authz: [...approvals._authz.entries()],
      authzVersion: approvals._authzVersion,
      bridge: approvals._bridge !== null,
      ctxApproval: typeof app.approval,
    };
  }
  if (cmd.op === 'native_delegate_probe') {
    // An unauthorized session must delegate, never claim: the same real
    // waterfall, with a session A never granted.
    const value = await app.waterfall(
      'approval/request',
      { agent: { session: { id: String(cmd.session_id) } }, toolName: 'bash' },
      () => Promise.resolve('delegated'),
    );
    return { event: 'delegate_probe', value };
  }
  if (cmd.op === 'native_outcome') {
    const entry = nativePending.get(String(cmd.approval_id));
    if (entry === undefined) return { event: 'native_outcome', ok: false, code: 'unknown' };
    const timeoutS = Number(cmd.timeout_s ?? 20);
    const value = await Promise.race([
      entry.promise.catch((error) => `<${codeOf(error)}>`),
      new Promise((resolve) => setTimeout(() => resolve('<pending>'), timeoutS * 1000)),
    ]);
    return { event: 'native_outcome', ok: true, outcome: value };
  }
  if (cmd.op === 'close') {
    await supervisor.stop();
    await store.close();
    return { event: 'closed' };
  }
  return { event: 'unknown_op', op: cmd.op };
}

const rl = readline.createInterface({ input: process.stdin });
for await (const line of rl) {
  const trimmed = line.trim();
  if (trimmed === '') continue;
  const cmd = JSON.parse(trimmed);
  let reply;
  try {
    reply = await execute(cmd);
  } catch (error) {
    reply = { event: 'error', code: codeOf(error), detail: String(error?.message ?? error).slice(0, 300) };
  }
  reply.id = cmd.id ?? null;
  emit(reply);
  if (cmd.op === 'close') break;
}

try {
  await supervisor.stop();
} catch {
  // Already torn down by the close command.
}
try {
  await store.close();
} catch {
  // Already closed by the close command.
}
process.exit(0);
