"""Assembly wiring tests for the native approval receiver (T1–T3).

The receiver fix landed in ``bridge/app/*`` behind three composition hooks that
``main.py`` had not wired yet (``native-approval-receiver-decision.md`` §7):

* **T1** — ``ApprovalService`` trust must come from **this handshake's**
  authenticated ``Session.peer_side`` and must fail closed before it exists;
* **T2** — startup and "same connection, new sid" / connection loss must
  invalidate pending native tool approvals as ``unavailable`` without killing a
  new sid's new requests or sending a late decision;
* **T3** — ``NotifyService(on_event=...)`` must reach a real
  ``Session.send_message`` with the original ``evt`` shape, and a not-ready
  session must raise so the persistent outbox retries instead of dropping.

Everything here drives the **real plugin object** (``DshBridgePlugin``): the real
``initialize`` assembly, the real ``ApprovalService``/``NotifyService``/``Store``,
the real ``Router`` and the real ``Session`` over the in-process
``FakeTransport``. Only AstrBot's own ``Context`` is replaced by a minimal host
double (no frame/transport logic is faked) — no private service is injected into
``ApprovalService`` to bypass a check, and no fake network layer stands in for
``Session.send_message``.
"""

from __future__ import annotations

import asyncio
import importlib
import sys
import time
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parent.parent

#: Import the plugin the way AstrBot does (``astrbot_plugin_dsh_bridge.main``), while
#: keeping the plain ``bridge`` package imported by the other tests identical. Without
#: the alias the composition root would import ``astrbot_plugin_dsh_bridge.bridge.*``
#: as separate module objects and every ``isinstance``/enum identity would diverge.
_PACKAGE = PLUGIN_ROOT.name
if _PACKAGE not in sys.path and PLUGIN_ROOT.parent.exists():
    sys.path.insert(0, str(PLUGIN_ROOT.parent))
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))
for _name, _module in list(sys.modules.items()):
    if _name == "bridge" or _name.startswith("bridge."):
        sys.modules.setdefault(f"{_PACKAGE}.{_name}", _module)

from _session_doubles import (  # noqa: E402  (package path set above)
    TEST_PSK_ID,
    TEST_PSK_SECRET,
    FakeTransport,
    make_caps,
    settle,
)
from bridge.app.approvals import request_digest_for  # noqa: E402
from bridge.constants import (  # noqa: E402
    APPROVAL_NATIVE_TOOL,
    MSG_APPROVAL_DECISION,
    NOTIFY_BACKOFF_S,
    OUTCOME_UNAVAILABLE,
)
from bridge.errors import BridgeError  # noqa: E402
from bridge.session import (  # noqa: E402
    Role,
    Session,
    SessionConfig,
    SessionState,
)

main = importlib.import_module(f"{_PACKAGE}.main")


class StubPlatform:
    """Platform instance double exposing only ``meta().id``."""

    def __init__(self, platform_id: str) -> None:
        """Create the double.

        Args:
            platform_id: Value returned by ``meta().id``.
        """
        self._platform_id = platform_id

    def meta(self):
        """Return the metadata the real host matches against.

        Returns:
            An object carrying the platform instance id.
        """
        from types import SimpleNamespace

        return SimpleNamespace(id=self._platform_id)


class HostContext:
    """Minimal stand-in for AstrBot's plugin ``Context``.

    Only the host surface the composition root calls is implemented: LLM tool and
    Web API registration are recorded, message delivery is captured. It never feeds
    session, transport or approval state, so the trust and delivery assertions below
    still run against the real bridge code.
    """

    def __init__(self) -> None:
        """Create an empty host with one registered platform."""
        self.llm_tools: list[str] = []
        self.web_routes: list[str] = []
        self.sent_messages: list[tuple[str, object]] = []
        self.platforms: dict[str, StubPlatform] = {"platform": StubPlatform("platform")}

    def add_llm_tools(self, *tools) -> None:
        """Record the registered LLM tools."""
        self.llm_tools = [getattr(tool, "name", type(tool).__name__) for tool in tools]

    def register_web_api(self, route, handler, methods, desc) -> None:
        """Record a Dashboard route (never served here)."""
        self.web_routes.append(route)

    def get_config(self) -> dict:
        """Return an empty host configuration."""
        return {}

    def get_platform_inst(self, platform_id: str):
        """Resolve a platform exactly like the real ``Context``.

        Args:
            platform_id: Platform instance id to look up.

        Returns:
            The matching platform double, or ``None``.
        """
        return self.platforms.get(platform_id)

    async def get_using_provider_async(self, umo=None):
        """Report "no chat provider" like an unconfigured host."""
        return None

    async def send_message(self, umo, chain) -> bool:
        """Capture one active message instead of touching a real platform."""
        self.sent_messages.append((umo, chain))
        return True


class AdminEvent:
    """Minimal AstrBot message event shaped like an administrator's command."""

    def __init__(self, sender_id: str) -> None:
        """Record the sender.

        Args:
            sender_id: Platform sender id used for the audit actor.
        """
        self.role = "admin"
        self._sender_id = sender_id

    def get_sender_id(self) -> str:
        """Return the platform sender id."""
        return self._sender_id


def native_request(approval_id: str, *, session_id: str = "s-1", **overrides) -> dict:
    """Build a genuine ``approval.request`` payload (§12.2).

    Args:
        approval_id: Approval identifier.
        session_id: DSH session id the request belongs to.
        **overrides: Field overrides.

    Returns:
        Parameter dictionary with a digest recomputed from the real fields.
    """
    params = {
        "approval_id": approval_id,
        "approval_type": APPROVAL_NATIVE_TOOL,
        "task_id": None,
        "root_task_id": None,
        "session_id": session_id,
        "tool": "bash",
        "reason": "run a shell command",
        "display_reason": {"en": "Run a shell command", "zh": "执行 shell 命令"},
        "call_id": None,
        "expires_at": None,
        "notify_id": f"n-{approval_id}",
        "origin_side": "B",
    }
    params.update(overrides)
    params["request_digest"] = request_digest_for(
        params["tool"],
        params["reason"],
        params["call_id"],
        params["session_id"],
        params["task_id"],
    )
    return params


class Pair:
    """Two linked real sessions; A is the plugin's session and dispatches for real."""

    def __init__(self, conn: str = "default", plugin=None) -> None:
        """Build the pair.

        Args:
            conn: Connection identifier shared by both sides.
            plugin: Plugin whose ``_on_session_message`` handles A's messages.
        """
        self.conn = conn
        self.b_messages: list[dict] = []
        self.a_cfg = SessionConfig(
            conn=conn,
            side="A",
            role=Role.INITIATOR,
            transport="ws",
            psk_id=TEST_PSK_ID,
            psk_secret=TEST_PSK_SECRET,
            caps=make_caps("A"),
        )
        self.b_cfg = SessionConfig(
            conn=conn,
            side="B",
            role=Role.RESPONDER,
            transport="ws",
            psk_id=TEST_PSK_ID,
            psk_secret=TEST_PSK_SECRET,
            caps=make_caps("B", native_tool=True),
        )
        self.a_transport = FakeTransport(Role.INITIATOR)
        self.b_transport = FakeTransport(Role.RESPONDER)
        self.a = Session(
            self.a_cfg,
            self.a_transport,
            plugin._on_session_message if plugin is not None else self._capture,
            lambda code, detail: None,
        )
        self.b = Session(
            self.b_cfg,
            self.b_transport,
            self._capture,
            lambda code, detail: None,
        )
        self.a_transport.peer_session = self.b
        self.b_transport.peer_session = self.a

    async def _capture(self, message: dict) -> None:
        """Record messages received by B (A is handled by the plugin)."""
        self.b_messages.append(message)

    async def handshake(self) -> None:
        """Run the full four-step handshake to ``ready`` on both sides."""
        await self.b.start()
        await self.a.start()

    async def close(self) -> None:
        """Close both sessions, tolerating failures."""
        for session in (self.a, self.b):
            try:
                await session.close("draining", "test_done")
            except Exception:
                pass


class Assembly:
    """A real plugin instance whose single session is a real in-process session."""

    def __init__(self, plugin, pair: Pair, data_dir: Path) -> None:
        """Store the assembled objects.

        Args:
            plugin: Real ``DshBridgePlugin`` after ``initialize``.
            pair: Linked A/B session pair (A is the plugin's session).
            data_dir: Temporary plugin data directory.
        """
        self.plugin = plugin
        self.pair = pair
        self.data_dir = data_dir

    @property
    def store(self):
        """Return the plugin's real store."""
        return self.plugin._store

    @property
    def approvals(self):
        """Return the plugin's real approval service."""
        return self.plugin._approvals

    @property
    def notify(self):
        """Return the plugin's real notify service."""
        return self.plugin._notify

    async def send_request(self, params: dict, pair: Pair | None = None) -> dict:
        """Deliver a real ``approval.request`` over the sealed session to A.

        Args:
            params: Request parameters.
            pair: Session pair to send over; defaults to the assembled one.

        Returns:
            The router reply object (``rep{ok:...}``).

        Raises:
            BridgeError: When the transport reports a refusal rather than a reply.
        """
        target = pair if pair is not None else self.pair
        rep = await target.b.call("approval.request", params)
        return rep

    async def dispatch_request(self, params: dict, pair: Pair | None = None) -> dict:
        """Deliver a request over the sealed session, keeping the error code.

        Args:
            params: Request parameters.
            pair: Session pair to send over; defaults to the assembled one.

        Returns:
            ``{"ok": True}`` or ``{"ok": False, "code": "..."}``.
        """
        try:
            await self.send_request(params, pair)
        except BridgeError as exc:
            return {"ok": False, "code": exc.code}
        return {"ok": True}

    async def event_messages(self) -> list[dict]:
        """Return every ``approval.decision`` object A actually sent on the wire."""
        return [
            message
            for message in self.pair.b_messages
            if message.get("m") == MSG_APPROVAL_DECISION
        ]


@pytest.fixture
async def assembly(tmp_path, monkeypatch):
    """Initialise the real plugin with one real session, then tear it down.

    Args:
        tmp_path: pytest temporary directory.
        monkeypatch: pytest monkeypatch fixture.

    Yields:
        An :class:`Assembly` whose A side is the plugin's live session.
    """
    monkeypatch.setattr(main, "get_astrbot_plugin_data_path", lambda: str(tmp_path))
    context = HostContext()
    plugin = main.DshBridgePlugin(
        context, {"dashboard_enabled": False, "approval_timeout_seconds": 600}
    )
    await plugin.initialize()

    pair = Pair(plugin=plugin)
    plugin._session = pair.a
    await pair.handshake()
    # Publish the transition the way the transport would, so the composition root
    # performs its own trust binding instead of the test poking at the service.
    plugin._on_session_state(SessionState.READY, "test_handshake")

    assembled = Assembly(plugin, pair, tmp_path)
    try:
        yield assembled
    finally:
        await pair.close()
        await plugin.terminate()


# -- T1: trust comes from this handshake, never from the wire -------------------------


@pytest.mark.asyncio
async def test_trust_binds_to_the_handshake_peer_side(assembly) -> None:
    """The anchor equals the authenticated ``Session.peer_side`` of this handshake."""
    assert assembly.pair.a.peer_side == "B"
    assert assembly.approvals._trusted_native_origin() == "B"
    assert assembly.plugin._trusted_peer == "B"
    assert assembly.plugin._trusted_sid == assembly.pair.a.sid
    # The capability set that decides whether an outbound ``approval.lookup`` is
    # allowed comes from the same authenticated handshake.
    assert assembly.approvals._peer_caps == assembly.pair.a.peer_caps
    assert "approval.lookup" in assembly.approvals._peer_caps["features"]


@pytest.mark.asyncio
async def test_native_request_is_accepted_after_the_handshake(assembly) -> None:
    """A genuine request from the authenticated peer is queued, not answered."""
    reply = await assembly.dispatch_request(native_request("ap-ok"))
    assert reply["ok"] is True
    stored = await assembly.store.get_approval("ap-ok")
    assert stored is not None
    assert stored["approval_type"] == APPROVAL_NATIVE_TOOL
    assert stored["state"] == "pending"
    assert stored["outcome"] is None
    assert stored["origin_side"] == "B"


@pytest.mark.asyncio
async def test_payload_cannot_grant_native_trust(assembly) -> None:
    """A payload claiming a peer side does not create trust (fail closed on wire)."""
    params = native_request("ap-wire")
    params["_peer_side"] = "B"
    params["origin_side"] = "B"
    # Drop the composition root's binding: nothing in the payload may restore it.
    assembly.approvals.bind_peer_side(main.UNVERIFIED_PEER_SIDE)
    reply = await assembly.dispatch_request(params)
    assert reply["ok"] is False
    assert reply["code"] == "capability_unavailable"
    assert await assembly.store.get_approval("ap-wire") is None


@pytest.mark.asyncio
async def test_native_request_is_refused_before_the_handshake(
    tmp_path, monkeypatch
) -> None:
    """Before ``ready`` there is no authenticated side: refuse, never default to B."""
    monkeypatch.setattr(main, "get_astrbot_plugin_data_path", lambda: str(tmp_path))
    plugin = main.DshBridgePlugin(HostContext(), {"dashboard_enabled": False})
    await plugin.initialize()
    try:
        # No connection is configured, so no handshake ever happened.
        assert plugin._session is None
        assert plugin._trusted_peer is None
        assert plugin._approvals._trusted_native_origin() == main.UNVERIFIED_PEER_SIDE
        reply = await plugin._router.dispatch(
            {
                "k": "req",
                "m": "approval.request",
                "id": "req-pre-handshake",
                "ts": "2026-01-01T00:00:00.000Z",
                "params": native_request("ap-pre"),
            }
        )
        assert reply is not None
        assert reply["ok"] is False
        assert reply["error"]["code"] == "capability_unavailable"
        assert await plugin._store.get_approval("ap-pre") is None
    finally:
        await plugin.terminate()


# -- T2: startup / new sid / connection loss lifecycle -------------------------------


@pytest.mark.asyncio
async def test_startup_invalidates_pending_native_approvals(
    tmp_path, monkeypatch
) -> None:
    """``initialize`` finalises the previous process's pending native approvals."""
    monkeypatch.setattr(main, "get_astrbot_plugin_data_path", lambda: str(tmp_path))
    first = main.DshBridgePlugin(HostContext(), {"dashboard_enabled": False})
    await first.initialize()
    pair = Pair(plugin=first)
    first._session = pair.a
    await pair.handshake()
    first._on_session_state(SessionState.READY, "test_handshake")
    assert (await first._approvals.handle_request(native_request("ap-restart")))[
        "accepted"
    ]
    await first.terminate()

    # A new process over the same data directory sees the row and must retire it.
    second = main.DshBridgePlugin(HostContext(), {"dashboard_enabled": False})
    await second.initialize()
    try:
        stored = await second._store.get_approval("ap-restart")
        assert stored is not None
        assert stored["state"] == "decided"
        assert stored["outcome"] == OUTCOME_UNAVAILABLE
        assert stored["actor_kind"] == "system"
        applied, reason = await second._approvals.human_decide(
            "ap-restart", allowed=True, actor="astrbot_admin:alice", channel="web"
        )
        assert applied is False and reason == "already_decided"
    finally:
        await second.terminate()
        await pair.close()


@pytest.mark.asyncio
async def test_new_sid_invalidates_the_old_one_without_killing_the_new(
    assembly,
) -> None:
    """A new sid on the same connection retires the old sid's pending request only."""
    assert (await assembly.dispatch_request(native_request("ap-old")))["ok"] is True
    old = await assembly.store.get_approval("ap-old")
    assert old is not None and old["state"] == "pending"

    # Same connection, new handshake: a fresh sid appears.
    old_sid = assembly.pair.a.sid
    new_pair = Pair(plugin=assembly.plugin)
    await new_pair.handshake()
    assert new_pair.a.sid != old_sid
    assembly.plugin._session = new_pair.a
    assembly.plugin._on_session_state(SessionState.READY, "test_new_sid")

    assert assembly.plugin._trusted_sid == new_pair.a.sid
    assert assembly.plugin._trusted_peer == "B"
    # Real entry points wait for the sweep before touching an approval.
    await assembly.plugin._flush_native_sweeps()
    retired = await assembly.store.get_approval("ap-old")
    assert retired is not None
    assert retired["outcome"] == OUTCOME_UNAVAILABLE
    assert retired["actor_kind"] == "system"
    assert await assembly.event_messages() == []

    # The new sid's request survives the sweep and stays answerable.
    reply = await assembly.dispatch_request(
        native_request("ap-new", session_id="s-2"), pair=new_pair
    )
    assert reply["ok"] is True
    fresh = await assembly.store.get_approval("ap-new")
    assert fresh is not None and fresh["state"] == "pending"
    await new_pair.close()


@pytest.mark.asyncio
async def test_connection_loss_retires_pending_and_no_late_decision_is_sent(
    assembly,
) -> None:
    """A lost link leaves pending native approvals ``unavailable`` and unsendable."""
    assert (await assembly.dispatch_request(native_request("ap-lost")))["ok"] is True
    await assembly.pair.a.close("draining", "test_link_lost")
    assembly.plugin._on_session_state(SessionState.CLOSED, "test_link_lost")

    assert assembly.approvals._trusted_native_origin() == main.UNVERIFIED_PEER_SIDE
    # A lost link also withdraws the negotiated lookup capability, so a remote
    # evidence query cannot be attempted against an unknown peer.
    assert assembly.approvals._peer_caps is None

    # The human-facing command is a real entry point: it waits for the sweep, so a
    # late "approve" on a dead link cannot land. The retired row is not a pending
    # item any more, so the command resolves nothing and never reports an approval.
    lines = [
        line
        async for line in assembly.plugin._decide_from_command(
            AdminEvent("admin-1"), "ap-lost", allowed=True, reason=None
        )
    ]
    assert lines == ["未找到对应的待审批项，请检查审批号。"]

    # The orphaned promise is terminal now: a system-owned ``unavailable`` row that
    # no longer waits for an answer that could never be delivered.
    retired = await assembly.store.get_approval("ap-lost")
    assert retired is not None
    assert retired["state"] == "decided"
    assert retired["outcome"] == OUTCOME_UNAVAILABLE
    assert retired["actor"] == "system"
    assert retired["actor_kind"] == "system"
    # The store records the invalidation channel as the ``unavailable`` token.
    assert retired["channel"] == OUTCOME_UNAVAILABLE
    assert retired["decided_reason"] == "disconnected"

    # A late answer cannot rewrite the first (system) decision, whichever entry
    # point tries: the store reports ``already_decided`` and keeps the row intact.
    applied, failure = await assembly.approvals.human_decide(
        "ap-lost", allowed=True, actor="astrbot_admin:admin-1", channel="im"
    )
    assert applied is False and failure == "already_decided"

    stored = await assembly.store.get_approval("ap-lost")
    assert stored is not None
    assert stored["state"] == "decided"
    assert stored["outcome"] == OUTCOME_UNAVAILABLE
    assert stored["actor"] == "system"
    assert stored["actor_kind"] == "system"
    assert stored["decided_at"] == retired["decided_at"]
    # Nothing was emitted for the late answer: no approval.decision on the wire.
    assert await assembly.event_messages() == []


# -- T3: on_event reaches a real ``Session.send_message`` -----------------------------


@pytest.mark.asyncio
async def test_human_decision_is_sent_through_the_real_session(assembly) -> None:
    """``NotifyService.on_event`` performs a real ``evt`` send with the original shape."""
    assert (await assembly.dispatch_request(native_request("ap-send")))["ok"] is True
    applied, _reason = await assembly.approvals.human_decide(
        "ap-send", allowed=True, actor="astrbot_admin:alice", channel="web"
    )
    assert applied is True

    events = await assembly.event_messages()
    assert len(events) == 1
    event = events[0]
    assert event["k"] == "evt"
    assert event["m"] == MSG_APPROVAL_DECISION
    assert isinstance(event["id"], str) and event["id"]
    assert event["ts"].endswith("Z") and len(event["ts"]) == 24
    assert event["params"]["approval_id"] == "ap-send"
    assert event["params"]["outcome"] == "allowed-once"
    assert event["params"]["actor_kind"] == "human"
    stored = await assembly.store.get_approval("ap-send")
    assert stored is not None
    assert event["params"]["request_digest"] == stored["request_digest"]

    notify_id = event["params"]["notify_id"]
    await assembly.notify.on_ack({"notify_id": notify_id, "outcome": "processed"})
    row = await assembly.store.get_notify(notify_id)
    assert row is not None and row["delivered"] is True


class FrozenClock:
    """Controllable stand-in for the ``time`` module used by the store.

    The outbox due check is the only thing that needs wall time here: moving the
    clock forward is how a test makes a backed-off row due without sleeping for the
    real backoff. The clock is injected into the store module only, so session and
    envelope timestamps keep using the real ``time`` module.
    """

    def __init__(self, now: float) -> None:
        """Start at ``now``.

        Args:
            now: Initial fake wall-clock time.
        """
        self.now = now

    def time(self) -> float:
        """Return the current fake time."""
        return self.now


@pytest.mark.asyncio
async def test_not_ready_session_raises_so_the_outbox_retries(
    assembly, monkeypatch
) -> None:
    """A not-ready send fails into the outbox, which retries once the row is due."""
    assert (await assembly.dispatch_request(native_request("ap-retry")))["ok"] is True

    class NotReadySession:
        """A session that still exists but lost ``ready`` (link flapping)."""

        state = SessionState.HANDSHAKING
        sid = "sid-not-ready"
        peer_side = None

        async def send_message(self, message: dict) -> None:
            """Fail the test if anything is sent while not ready."""
            raise AssertionError("must not send while not ready")

    # Advance the store's clock instead of widening ``pending_notifies``'s "due
    # now" filter: the retry below is observed for real, through the real store
    # row and the real background resend loop.
    store_module = sys.modules[type(assembly.store).__module__]
    clock = FrozenClock(time.time())
    monkeypatch.setattr(store_module, "time", clock)

    assembly.plugin._session = NotReadySession()
    applied, _reason = await assembly.approvals.human_decide(
        "ap-retry", allowed=True, actor="astrbot_admin:alice", channel="web"
    )
    assert applied is True

    failed_at = clock.now
    # The raise was persisted as a backoff, not a drop: nothing is due yet.
    assert [
        row
        for row in await assembly.store.pending_notifies()
        if row["message"] == MSG_APPROVAL_DECISION
    ] == []

    sent: list[dict] = []

    class SpySession:
        """A ready session that records what the resend loop delivers."""

        state = SessionState.READY

        async def send_message(self, message: dict) -> None:
            """Record one message object."""
            sent.append(message)

    assembly.plugin._session = SpySession()
    clock.now = failed_at + NOTIFY_BACKOFF_S[1] + 1
    due = [
        row
        for row in await assembly.store.pending_notifies()
        if row["message"] == MSG_APPROVAL_DECISION
    ]
    assert len(due) == 1
    notify_id = due[0]["notify_id"]
    row = await assembly.store.get_notify(notify_id)
    assert row is not None
    assert row["delivered"] is False
    assert row["undelivered"] is False
    assert row["attempts"] == 1
    # The first retry was scheduled in the future and becomes due only now.
    assert row["next_at"] > failed_at
    assert row["next_at"] <= clock.now

    # The real background resend loop retries the due row over the ready session.
    for _ in range(60):
        if sent:
            break
        await asyncio.sleep(0.05)
    assert sent, "the outbox never retried the pending decision"
    assert sent[0]["k"] == "evt"
    assert sent[0]["m"] == MSG_APPROVAL_DECISION
    assert sent[0]["params"]["approval_id"] == "ap-retry"
    assert sent[0]["params"]["notify_id"] == notify_id

    # Only the peer's ack retires the outbox row; after it the loop stops resending.
    await assembly.notify.on_ack({"notify_id": notify_id, "outcome": "processed"})
    delivered = await assembly.store.get_notify(notify_id)
    assert delivered is not None and delivered["delivered"] is True

    stored = await assembly.store.get_approval("ap-retry")
    # The decision is real and human-owned; only its delivery was pending.
    assert stored is not None and stored["outcome"] == "allowed-once"


@pytest.mark.asyncio
async def test_event_sender_uses_the_row_message_name(assembly) -> None:
    """The envelope's ``m`` comes from the outbox row, not a hard-coded name."""
    sent: list[dict] = []

    class SpySession:
        """Capture ``send_message`` calls while staying ``ready``."""

        state = SessionState.READY

        async def send_message(self, message: dict) -> None:
            """Record one message object."""
            sent.append(message)

    assembly.plugin._session = SpySession()
    await assembly.plugin._send_event_message(
        {"approval_id": "ap-x"},
        {"message": "decision.request"},
        "task-1",
        "task-1",
    )
    assert len(sent) == 1
    assert sent[0]["k"] == "evt"
    assert sent[0]["m"] == "decision.request"
    assert sent[0]["params"] == {"approval_id": "ap-x"}


@pytest.mark.asyncio
async def test_no_event_sender_is_never_a_silent_drop(assembly) -> None:
    """A row without an assembled sender raises instead of disappearing."""
    from bridge.app.notify import NotifyService

    bare = NotifyService(assembly.store, conn="default")
    with pytest.raises(RuntimeError):
        await bare._send(
            {
                "notify_id": "n-bare",
                "message": MSG_APPROVAL_DECISION,
                "params": {},
                "task_id": "",
                "root_task_id": "",
                "attempts": 0,
            }
        )


# -- human-only decision path --------------------------------------------------------


@pytest.mark.asyncio
async def test_human_decide_is_the_only_deciding_entry(assembly) -> None:
    """Agents cannot decide, and the wire cannot approve on a human's behalf."""
    assert (await assembly.dispatch_request(native_request("ap-human")))["ok"] is True
    with pytest.raises(BridgeError):
        await assembly.approvals.human_decide(
            "ap-human", allowed=True, actor="agent:planner", channel="web"
        )
    stored = await assembly.store.get_approval("ap-human")
    assert stored is not None and stored["state"] == "pending"

    # A ``native_tool`` decision arriving on the wire is not a human act.
    await assembly.pair.b.send_message(
        {
            "k": "evt",
            "m": MSG_APPROVAL_DECISION,
            "id": "evt-1",
            "ts": "2026-01-01T00:00:00.000Z",
            "params": {
                "approval_id": "ap-human",
                "outcome": "allowed-once",
                "actor": "dsh-agent",
                "actor_kind": "agent",
                "channel": "web",
                "reason": None,
                "decided_at": "2026-01-01T00:00:00.000Z",
                "request_digest": stored["request_digest"],
                "notify_id": "n-wire",
            },
        }
    )
    await settle()
    after = await assembly.store.get_approval("ap-human")
    assert after is not None and after["state"] == "pending"
    assert await assembly.event_messages() == []


# -- caps stay put -------------------------------------------------------------------


def test_assembly_does_not_change_a_caps() -> None:
    """A still advertises ``native_tool: false`` after the wiring (frozen bytes)."""
    caps = main.HostCapabilities(
        version="0.1.0",
        transports=["longpoll", "webhook", "ws"],
        tls=False,
        image_enabled=True,
        image_max_count=4,
        image_max_bytes=10_485_760,
        image_total_max_bytes=20_971_520,
    ).caps()
    assert caps["approvals"][APPROVAL_NATIVE_TOOL] is False
    assert "native_tool_receive" not in caps["approvals"]


@pytest.mark.asyncio
async def test_wiring_is_idempotent_on_repeated_state_callbacks(assembly) -> None:
    """Repeated ``ready`` callbacks do not re-retire the live sid's approvals."""
    assert (await assembly.dispatch_request(native_request("ap-idem")))["ok"] is True
    for _ in range(3):
        assembly.plugin._on_session_state(SessionState.READY, "test_ready_again")
        await settle()
    stored = await assembly.store.get_approval("ap-idem")
    assert stored is not None and stored["state"] == "pending"
    assert assembly.plugin._trusted_sid == assembly.pair.a.sid


__all__ = []
