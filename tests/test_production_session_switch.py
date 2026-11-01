"""Production session lifecycle: first activation, carrier switch, release, stop.

The regression under test is the composition root's session bookkeeping in
``main.py``:

* ``__init__`` must create the per-carrier session map (``_sessions``). Without
  it the very first ``on_transport`` callback of a configured connection crashed
  in ``_bind_fresh_session`` and no link was ever established.
* ``connect()`` must resolve the handshake target from the **live** carrier
  (``_live_session()``) instead of the still-unset ``_session`` attribute, or a
  first activation can never start its handshake at all.
* a carrier switch must bind a *fresh* session (new ``sid``), release and close
  the previous one, and retire the previous session's pending native-tool
  promises as ``unavailable`` without touching the new session's requests.
* ``terminate``/``stop`` must close and unmap the session and be idempotent.

Everything that decides behaviour is production code: the real
``DshBridgePlugin`` with its real ``initialize()`` / ``_run_connection`` /
``_bind_fresh_session`` / ``_release_session`` / ``_live_session`` /
``terminate`` / ``TransportManager``, and real ``bridge.session.Session``
objects running the production four-step handshake (real PSK derivation, nonces,
AEAD and sequence bookkeeping).

Only two external boundaries are doubled:

* AstrBot's plugin ``Context`` (:class:`HostContext`) — the host surface the
  composition root calls; it feeds no session, transport or approval state.
* the carrier factory (``build_transport``) — the same seam
  ``test_transport_fallback_runtime`` uses. :class:`ControllableCarrier` answers
  the handshake from an in-process peer instead of a socket, so ``start`` /
  ``stop`` / ``alive`` / ``degraded`` behave like the shipped carriers.
"""

from __future__ import annotations

import asyncio
import importlib
import pkgutil
import sys
import time
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parent.parent

#: Import the plugin the way AstrBot does (``astrbot_plugin_dsh_bridge.main``) while
#: keeping the plain ``bridge`` package identical to the tree every other test imports.
#: The composition root uses package-relative imports, so without the alias it would
#: build a *second* copy of ``bridge.*``: ``build_transport`` patched on the plain
#: manager would be invisible (a real socket carrier dials 127.0.0.1:8765) and
#: ``Session``/``SessionState`` identity would diverge across trees.
#:
#: The alias is only ever a ``setdefault`` of modules that are *not* loaded under the
#: package name, so an already-imported package tree is never overwritten. Whatever
#: ``main`` actually references is then read back from ``sys.modules``: that object is
#: the patch target and the type source, which keeps both import orders consistent.
_PACKAGE = PLUGIN_ROOT.name
if _PACKAGE not in sys.path and PLUGIN_ROOT.parent.exists():
    sys.path.insert(0, str(PLUGIN_ROOT.parent))
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

import bridge  # noqa: E402  (package path set above)

# Load the whole plain tree, then alias every module under the plugin package name.
for _info in pkgutil.walk_packages(bridge.__path__, "bridge."):
    importlib.import_module(_info.name)
for _name, _module in list(sys.modules.items()):
    if _name == "bridge" or _name.startswith("bridge."):
        sys.modules.setdefault(f"{_PACKAGE}.{_name}", _module)

main = importlib.import_module(f"{_PACKAGE}.main")
#: The modules ``main`` actually references (plain tree when the alias applied).
manager_mod = sys.modules[f"{_PACKAGE}.bridge.transport.manager"]
session_mod = sys.modules[f"{_PACKAGE}.bridge.session"]

from _session_doubles import (  # noqa: E402
    TEST_PSK_ID,
    TEST_PSK_SECRET,
    make_caps,
)
from bridge.app.approvals import request_digest_for  # noqa: E402
from bridge.constants import (  # noqa: E402
    APPROVAL_CROSS_END_SUBMIT,
    APPROVAL_NATIVE_TOOL,
    MSG_APPROVAL_DECISION,
    OUTCOME_UNAVAILABLE,
    STATUS_NEEDS_HUMAN,
    STATUS_PENDING_APPROVAL,
)

#: Session types of the tree the plugin actually runs, not of the other copy.
Role = session_mod.Role
Session = session_mod.Session
SessionConfig = session_mod.SessionConfig
SessionState = session_mod.SessionState

#: One connect-side connection with a fallback, so a real switch is reachable.
CONNECTION_CONFIG: dict = {
    "dashboard_enabled": False,
    "approval_timeout_seconds": 600,
    "heartbeat_interval": 30,
    "connections": [
        {
            "conn_id": "default",
            "conn_mode": "connect",
            "conn_transport": "ws",
            "conn_transport_fallback": ["longpoll"],
            "conn_host": "127.0.0.1",
            "conn_port": 8765,
            "conn_psk_id": TEST_PSK_ID,
            "conn_psk_secret": TEST_PSK_SECRET,
        }
    ],
}


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

    Only the host surface the composition root calls is implemented, so no
    session, transport or approval state can leak in from here.
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


class PeerLink:
    """Outbound carrier used by the in-process peer (side B).

    Reverse traffic is handed to the manager's hooks, which the production
    composition root turns into ``_on_plain`` / ``_on_envelope`` on the live
    session — so the peer never reaches into the plugin directly.
    """

    def __init__(self, hooks: object) -> None:
        """Store the hooks of the carrier that adopted this peer.

        Args:
            hooks: :class:`bridge.transport.base.TransportHooks` of the carrier.
        """
        self._hooks = hooks

    async def start(self, cfg: object, hooks: object) -> None:
        """No-op start: the peer never dials."""

    async def stop(self) -> None:
        """No-op stop: the peer owns no socket."""

    async def send_plain(self, obj: dict) -> dict | None:
        """Deliver a plaintext handshake object inbound.

        Args:
            obj: ``hello_ack`` object.

        Returns:
            The peer's reply, if any (``None`` for a responder).
        """
        return await self._hooks.on_plain(obj)

    async def send_envelope(self, env: dict) -> None:
        """Deliver one sealed envelope inbound.

        Args:
            env: Sealed envelope object.
        """
        await self._hooks.on_envelope(env)

    def alive(self) -> bool:
        """The in-process link is always usable."""
        return True


class ControllableCarrier:
    """Carrier double at the factory seam, with a real in-process peer.

    The lifecycle contract matches the shipped carriers (``start``/``stop``/
    ``alive``/``degraded``), so the real manager drives it unchanged. Every
    activation starts a *new* responder session, exactly like a peer process
    restarting its end of a new handshake.
    """

    def __init__(self, name: str) -> None:
        """Create a carrier that is not started yet.

        Args:
            name: Carrier name (``ws`` / ``longpoll``).
        """
        self.name = name
        self.started = False
        self.stopped = False
        self.hooks: object | None = None
        self.peer: Session | None = None
        self.peer_messages: list[dict] = []
        self.peer_security: list[str] = []
        self._degraded = False

    async def start(self, cfg: object, hooks: object) -> None:
        """Start the peer responder so the initiator can handshake.

        Args:
            cfg: Session configuration built by the composition root.
            hooks: Inbound callbacks of this carrier.
        """
        self.hooks = hooks
        peer_cfg = SessionConfig(
            conn=cfg.conn,
            side="B",
            role=Role.RESPONDER,
            transport=self.name,
            psk_id=cfg.psk_id,
            psk_secret=cfg.psk_secret,
            caps=make_caps("B", native_tool=True),
            heartbeat_s=3600,
            mode="listen",
        )
        peer = Session(
            peer_cfg,
            PeerLink(hooks),
            self._on_peer_message,
            self._on_peer_security,
        )
        self.peer = peer
        await peer.start()
        self.started = True

    async def _on_peer_message(self, message: dict) -> None:
        """Record one inbound application message of the peer."""
        self.peer_messages.append(message)

    def _on_peer_security(self, code: str, detail: str) -> None:
        """Record one security event reported by the peer."""
        self.peer_security.append(code)

    async def stop(self) -> None:
        """Mark the carrier stopped (no socket to close)."""
        self.stopped = True
        self.started = False

    async def send_plain(self, obj: dict) -> dict | None:
        """Deliver a plaintext handshake object to the peer.

        Args:
            obj: ``hello`` object.

        Returns:
            The peer's ``hello_ack``.
        """
        assert self.peer is not None, "carrier used before start"
        return await self.peer.handle_plain(obj)

    async def send_envelope(self, env: dict) -> None:
        """Deliver one sealed envelope to the peer.

        Args:
            env: Envelope object.
        """
        assert self.peer is not None, "carrier used before start"
        await self.peer.handle_envelope(env)

    def alive(self) -> bool:
        """Whether the carrier is up and not degraded."""
        return self.started and not self.stopped and not self._degraded

    def degraded(self) -> bool:
        """Whether the carrier reports itself unusable (webhook probe style)."""
        return self._degraded

    def set_degraded(self) -> None:
        """Report ``transport_degraded`` exactly like a failing carrier probe."""
        self._degraded = True
        assert self.hooks is not None
        self.hooks.on_state("degraded", "transport_degraded")

    def diagnostics(self) -> dict:
        """Return carrier state for the manager's status output."""
        return {"name": self.name, "alive": self.alive(), "degraded": self._degraded}


class CarrierFactory:
    """Stands in for ``build_transport`` at the carrier boundary."""

    def __init__(self) -> None:
        """Create a factory that has produced nothing yet."""
        self.instances: list[ControllableCarrier] = []

    def __call__(self, name: str, cfg: object) -> ControllableCarrier:
        """Build one carrier per activation.

        Args:
            name: Carrier name requested by the manager.
            cfg: Session configuration (unused).

        Returns:
            The new carrier.
        """
        carrier = ControllableCarrier(name)
        self.instances.append(carrier)
        return carrier


class Harness:
    """A real plugin plus the carriers its manager actually built."""

    def __init__(self, plugin, factory: CarrierFactory) -> None:
        """Store the assembled objects.

        Args:
            plugin: Real ``DshBridgePlugin`` after ``initialize``.
            factory: Carrier factory the manager built from.
        """
        self.plugin = plugin
        self.factory = factory

    @property
    def session(self) -> Session | None:
        """Return the plugin's currently installed session."""
        return self.plugin._session

    @property
    def store(self):
        """Return the plugin's real store."""
        return self.plugin._store

    def assert_connected(self) -> Session:
        """Assert the plugin holds one live, authenticated session.

        Returns:
            The live session.
        """
        session = self.plugin._session
        assert session is not None, (
            "the first carrier activation never bound a session: "
            f"state={self.plugin._connection_state}/{self.plugin._connection_reason}"
        )
        assert session.state is SessionState.READY
        assert session.peer_side == "B"
        assert isinstance(session.sid, str) and session.sid
        return session


async def wait_until(predicate, timeout_s: float = 5.0) -> bool:
    """Poll ``predicate`` until it holds or the timeout expires.

    Args:
        predicate: Zero-argument predicate.
        timeout_s: Maximum wait in seconds.

    Returns:
        ``True`` when the predicate held before the timeout.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return predicate()


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


@pytest.fixture
async def bridge(tmp_path, monkeypatch):
    """Initialise the real plugin with one configured connection.

    Args:
        tmp_path: pytest temporary directory.
        monkeypatch: pytest monkeypatch fixture.

    Yields:
        A :class:`Harness` whose plugin completed its first handshake.
    """
    monkeypatch.setattr(main, "get_astrbot_plugin_data_path", lambda: str(tmp_path))
    factory = CarrierFactory()
    monkeypatch.setattr(manager_mod, "build_transport", factory)
    plugin = main.DshBridgePlugin(HostContext(), CONNECTION_CONFIG)
    await plugin.initialize()
    harness = Harness(plugin, factory)
    try:
        assert await wait_until(
            lambda: (
                plugin._session is not None
                and plugin._session.state is SessionState.READY
            )
        ), (
            "the configured connection never completed a handshake: "
            f"state={plugin._connection_state}/{plugin._connection_reason}"
        )
        yield harness
    finally:
        await plugin.terminate()


# -- construction: the session map exists -------------------------------------------


@pytest.mark.asyncio
async def test_construction_provides_the_per_carrier_session_map() -> None:
    """``__init__`` creates ``_sessions`` empty, so the first bind cannot crash."""
    plugin = main.DshBridgePlugin(HostContext(), {})
    assert isinstance(plugin._sessions, dict)
    assert plugin._sessions == {}
    assert plugin._session is None


# -- first activation: bind + connect can start -------------------------------------


@pytest.mark.asyncio
async def test_first_carrier_activation_binds_a_session_and_starts_it(bridge) -> None:
    """The first activation binds a session and ``connect()`` completes it."""
    plugin = bridge.plugin
    assert len(bridge.factory.instances) == 1
    carrier = bridge.factory.instances[0]
    assert carrier.started is True

    session = bridge.assert_connected()
    # The session is reachable through the map the manager populates, i.e. the
    # handshake target was resolved from the live carrier, not from ``_session``.
    assert plugin._sessions == {id(carrier): session}
    assert plugin._connection_state == SessionState.READY.value
    assert plugin._trusted_peer == "B"
    assert plugin._trusted_sid == session.sid
    # The peer really authenticated the same handshake over the wire.
    assert carrier.peer is not None
    assert carrier.peer.state is SessionState.READY
    assert carrier.peer.sid == session.sid
    assert carrier.peer.peer_side == "A"


# -- carrier switch: fresh session, old promise retired ------------------------------


@pytest.mark.asyncio
async def test_carrier_switch_binds_a_new_session_and_retires_the_old_promise(
    bridge,
) -> None:
    """A fallback switch gets a new session; the old sid's promise dies with it."""
    plugin = bridge.plugin
    first_carrier = bridge.factory.instances[0]
    first = bridge.assert_connected()
    first_sid = first.sid
    assert first_carrier.peer is not None

    # A genuine request from the authenticated old peer is queued, not answered.
    reply = await first_carrier.peer.call("approval.request", native_request("ap-old"))
    assert reply["accepted"] is True
    queued = await bridge.store.get_approval("ap-old")
    assert queued is not None
    assert queued["state"] == "pending"
    assert queued["outcome"] is None

    # A local cross-end gate is pending for an inbound submission. It is bound
    # to the same dead answer channel, so the production switch must park its
    # task instead of leaving it pending for the new session.
    cross_task_id = "33333333-3333-4333-8333-333333333333"
    cross_params = {
        "task_id": cross_task_id,
        "root_task_id": cross_task_id,
        "kind": "astr_agent_run",
        "origin": "llm",
        "input_parts": [{"type": "text", "text": "cross-end deploy"}],
        "attachments": [],
        "tool_hints": [],
        "session_id": None,
        "purpose": "deploy",
        "timeout_s": 60,
        "meta": {},
        "approval_ref": None,
    }
    await bridge.store.upsert_task(
        {
            "task_id": cross_task_id,
            "root_task_id": cross_task_id,
            "direction": "inbound",
            "kind": "astr_agent_run",
            "origin": "llm",
            "status": STATUS_PENDING_APPROVAL,
            "payload": cross_params,
            "session_id": None,
            "purpose": "deploy",
            "request_hash": "",
        }
    )
    cross = await plugin._approvals.create_cross_end_submit(
        task={"task_id": cross_task_id, "root_task_id": cross_task_id},
        tool="astr_agent_run",
        reason="cross-end task submission",
        display_reason={"en": "Run", "zh": "执行"},
        params=cross_params,
    )
    assert cross["approval_type"] == APPROVAL_CROSS_END_SUBMIT

    # The production loop reacts to the carrier's own degradation report.
    first_carrier.set_degraded()
    assert await wait_until(
        lambda: (
            len(bridge.factory.instances) > 1
            and plugin._manager is not None
            and plugin._manager.current() == "longpoll"
            and plugin._session is not None
            and plugin._session is not first
            and plugin._session.state is SessionState.READY
        )
    ), (
        f"the fallback carrier never got a live session (state={plugin._connection_state})"
    )

    second_carrier = bridge.factory.instances[-1]
    second = bridge.assert_connected()
    assert second_carrier is not first_carrier
    assert second_carrier.name == "longpoll"
    assert second is not first
    # A new handshake means a new sid: no nonce/sid reuse across carriers.
    assert isinstance(second.sid, str) and second.sid
    assert second.sid != first_sid

    # The old session was released: closed and unmapped; the new one owns the map.
    assert plugin._sessions == {id(second_carrier): second}
    assert id(first_carrier) not in plugin._sessions
    assert first.state is SessionState.CLOSED
    assert first_carrier.stopped is True
    assert plugin._trusted_peer == "B"
    assert plugin._trusted_sid == second.sid

    # A request on the new session goes through the real inbound entry point,
    # which finishes the pending sweep first: the new row must survive it.
    assert second_carrier.peer is not None
    reply = await second_carrier.peer.call(
        "approval.request", native_request("ap-new", session_id="s-2")
    )
    assert reply["accepted"] is True

    retired = await bridge.store.get_approval("ap-old")
    assert retired is not None
    assert retired["state"] == "decided"
    assert retired["outcome"] == OUTCOME_UNAVAILABLE
    assert retired["actor_kind"] == "system"
    fresh = await bridge.store.get_approval("ap-new")
    assert fresh is not None
    assert fresh["state"] == "pending"
    assert fresh["outcome"] is None

    # The old cross-end gate is fail-closed and its task is parked, not pending.
    cross_approval = None
    parked = None
    for _ in range(200):
        cross_approval = await bridge.store.get_approval(cross["approval_id"])
        parked = await bridge.store.get_task(cross_task_id)
        if (
            cross_approval is not None
            and cross_approval["state"] == "decided"
            and parked is not None
            and parked["status"] == STATUS_NEEDS_HUMAN
        ):
            break
        await asyncio.sleep(0.01)
    assert cross_approval is not None
    assert parked is not None
    assert cross_approval["outcome"] == OUTCOME_UNAVAILABLE
    assert parked["status"] == STATUS_NEEDS_HUMAN

    # No decision was ever emitted for the retired promise, on either link.
    for carrier in bridge.factory.instances:
        assert [
            message
            for message in carrier.peer_messages
            if message.get("m") == MSG_APPROVAL_DECISION
        ] == []


# -- release + stop: close, unmap, idempotent ---------------------------------------


@pytest.mark.asyncio
async def test_terminate_releases_the_session_and_is_idempotent(bridge) -> None:
    """``terminate`` closes and unmaps the session; a second stop is a no-op."""
    plugin = bridge.plugin
    manager = plugin._manager
    assert manager is not None
    carrier = manager.transport()
    assert carrier is not None
    session = bridge.assert_connected()

    await plugin.terminate()

    # The manager released the carrier, which closed and unmapped its session.
    assert carrier.stopped is True
    assert session.state is SessionState.CLOSED
    assert plugin._sessions == {}
    assert plugin._session is None
    assert plugin._manager is None
    assert plugin._store is None

    # Stopping the already-stopped plugin and manager changes nothing and raises
    # nothing: shutdown runs more than once on a reload path.
    await plugin.terminate()
    await manager.stop()
    await manager.stop()
    assert plugin._sessions == {}
    assert session.state is SessionState.CLOSED


__all__ = []
