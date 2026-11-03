"""Agent-facing session creation must reserve the session on the peer first.

``dsh_create_session`` used to mint a fresh ``uuid.uuid4()`` locally and authorize
it without ever asking the peer. The peer never knew that session, so the first
task targeting it failed with ``session_not_found``. The fix keeps a separate
peer-first path for agent-facing creation while the inbound ``session.create``
handler keeps its lazy local mint (AstrBot creates its session on demand).

These cases use the real ``Store`` and ``SessionService``. Only the live peer
link is a recording double, so every outbound call the implementation makes is
observable; no business logic is mocked away.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from bridge.app.sessions import SessionService
from bridge.errors import BridgeError
from bridge.session import SessionState

PLUGIN_ROOT = Path(__file__).resolve().parent.parent

#: Import the plugin the way AstrBot does while keeping the plain ``bridge``
#: package identical to the one the other tests import (module identity matters).
_PACKAGE = PLUGIN_ROOT.name
if _PACKAGE not in sys.path and PLUGIN_ROOT.parent.exists():
    sys.path.insert(0, str(PLUGIN_ROOT.parent))
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))
for _name, _module in list(sys.modules.items()):
    if _name == "bridge" or _name.startswith("bridge."):
        sys.modules.setdefault(f"{_PACKAGE}.{_name}", _module)

main = importlib.import_module(f"{_PACKAGE}.main")

#: Session id the peer claims to have created. Deliberately fixed so a locally
#: minted UUID can never accidentally satisfy the assertions.
PEER_SESSION = "6b1f3e0a-8c2d-4f5b-9a71-0c3d4e5f6071"
PEER_AUTHZ_VERSION = 7


class RecordingSession:
    """``Session`` double that records requests and returns a scripted reply."""

    def __init__(
        self,
        *,
        reply: dict | None = None,
        error: Exception | None = None,
        state: SessionState = SessionState.READY,
    ) -> None:
        """Create the double.

        Args:
            reply: Reply body returned by ``call``; defaults to a peer session.
            error: Exception raised by ``call`` instead of replying.
            state: Advertised session state.
        """
        self.state = state
        self.reply = (
            {
                "session_id": PEER_SESSION,
                "authorized": True,
                "granted_by": "agent_auto",
                "authz_version": PEER_AUTHZ_VERSION,
            }
            if reply is None
            else reply
        )
        self.error = error
        self.calls: list[dict] = []
        self.sent: list[dict] = []

    async def call(
        self, message: str, params: dict, timeout_s: float | None = None
    ) -> dict:
        """Record one outbound request and return or raise the scripted result.

        Args:
            message: Message name.
            params: Request parameters.
            timeout_s: Optional reply timeout override.

        Returns:
            The scripted reply.

        Raises:
            Exception: The scripted error, when one was configured.
        """
        self.calls.append(
            {"message": message, "params": params, "timeout_s": timeout_s}
        )
        if self.error is not None:
            raise self.error
        return dict(self.reply)

    async def send_message(self, message: dict) -> None:
        """Record a pushed event (``session.authz``).

        Args:
            message: Event message.
        """
        self.sent.append(message)

    async def close(self, code: str, reason: str) -> None:
        """Accept ``terminate``'s close call without side effects.

        Args:
            code: Close code.
            reason: Close reason.
        """


def peer_request(service: SessionService, session: RecordingSession) -> None:
    """Install the live-session provider used by agent-facing creation.

    Args:
        service: Session service under test.
        session: Session double the provider returns.
    """
    service.set_session_provider(lambda: session)


@pytest.mark.asyncio
async def test_agent_creation_round_trips_and_authorizes_the_peer_id(sessions) -> None:
    """The authorized id is exactly the one the peer returned, and it was asked."""
    peer = RecordingSession()
    peer_request(sessions, peer)

    result = await sessions.create_peer_session(
        {"request_id": "agent-req-1", "purpose": "code-review", "title": "审查"}
    )

    assert [call["message"] for call in peer.calls] == ["session.create"]
    assert peer.calls[0]["params"] == {
        "request_id": "agent-req-1",
        "purpose": "code-review",
        "title": "审查",
    }
    assert result["session_id"] == PEER_SESSION
    assert result["authorized"] is True
    assert result["granted_by"] == "agent_auto"
    assert await sessions._store.is_authorized(PEER_SESSION)
    grants = await sessions.admin_grants()
    assert [grant["session_id"] for grant in grants] == [PEER_SESSION]


@pytest.mark.asyncio
async def test_agent_creation_without_a_live_session_grants_nothing(sessions) -> None:
    """No provider means no round trip and therefore no authorization at all."""
    with pytest.raises(BridgeError) as excinfo:
        await sessions.create_peer_session(
            {"request_id": "agent-req-2", "purpose": "code-review"}
        )
    assert excinfo.value.code == "not_ready"
    assert await sessions.admin_grants() == []


@pytest.mark.asyncio
async def test_agent_creation_requires_the_ready_state(sessions) -> None:
    """A connecting/closing carrier is not a live link and must not authorize."""
    peer = RecordingSession(state=SessionState.CONNECTING)
    peer_request(sessions, peer)
    with pytest.raises(BridgeError) as excinfo:
        await sessions.create_peer_session(
            {"request_id": "agent-req-3", "purpose": "code-review"}
        )
    assert excinfo.value.code == "not_ready"
    assert peer.calls == []
    assert await sessions.admin_grants() == []


@pytest.mark.parametrize(
    "code",
    [
        "timeout",
        "session_create_denied",
        "session_quota_exceeded",
        "capability_unavailable",
        "unknown_message",
    ],
)
@pytest.mark.asyncio
async def test_peer_errors_leave_no_local_grant(sessions, code) -> None:
    """Every peer-side failure is reported as-is and authorizes nothing locally."""
    peer = RecordingSession(error=BridgeError(code))
    peer_request(sessions, peer)
    with pytest.raises(BridgeError) as excinfo:
        await sessions.create_peer_session(
            {"request_id": f"agent-req-{code}", "purpose": "code-review"}
        )
    assert excinfo.value.code == code
    assert [call["message"] for call in peer.calls] == ["session.create"]
    assert await sessions.admin_grants() == []


@pytest.mark.asyncio
async def test_transport_failure_is_reported_without_a_grant(sessions) -> None:
    """An unexpected carrier error becomes ``capability_unavailable``, not a grant."""
    peer = RecordingSession(error=RuntimeError("link died"))
    peer_request(sessions, peer)
    with pytest.raises(BridgeError) as excinfo:
        await sessions.create_peer_session(
            {"request_id": "agent-req-crash", "purpose": "code-review"}
        )
    assert excinfo.value.code == "capability_unavailable"
    assert await sessions.admin_grants() == []


@pytest.mark.parametrize(
    "reply",
    [
        {"authorized": True, "authz_version": 3},
        {"session_id": PEER_SESSION, "authorized": True},
        {"session_id": "", "authorized": True, "authz_version": 3},
    ],
)
@pytest.mark.asyncio
async def test_malformed_peer_replies_leave_no_local_grant(sessions, reply) -> None:
    """A reply without a usable id/version cannot be turned into a local grant."""
    peer = RecordingSession(reply=reply)
    peer_request(sessions, peer)
    with pytest.raises(BridgeError) as excinfo:
        await sessions.create_peer_session(
            {"request_id": "agent-req-bad-reply", "purpose": "code-review"}
        )
    assert excinfo.value.code == "capability_unavailable"
    assert await sessions.admin_grants() == []


@pytest.mark.asyncio
async def test_same_request_id_round_trips_once(sessions) -> None:
    """Reusing the idempotency key returns the cached grant without a new call."""
    peer = RecordingSession()
    peer_request(sessions, peer)
    params = {"request_id": "agent-req-idem", "purpose": "code-review"}
    first = await sessions.create_peer_session(params)
    second = await sessions.create_peer_session(params)
    assert len(peer.calls) == 1
    assert first["session_id"] == second["session_id"] == PEER_SESSION
    assert len(await sessions.admin_grants()) == 1


@pytest.mark.asyncio
async def test_peer_replay_reuses_the_existing_grant(sessions) -> None:
    """A replayed peer id is bound again to the same grant, never a second one."""
    peer = RecordingSession()
    peer_request(sessions, peer)
    params = {"request_id": "agent-req-replay", "purpose": "code-review"}
    first = await sessions.create_peer_session(params)

    # Simulate a crash between the peer's successful create and the local commit:
    # the peer will replay the same id for the same request key.
    db = sessions._store._conn()
    await db.execute("DELETE FROM session_create_requests")
    await db.commit()

    second = await sessions.create_peer_session(params)
    assert len(peer.calls) == 2
    assert second["session_id"] == first["session_id"] == PEER_SESSION
    assert len(await sessions.admin_grants()) == 1


@pytest.mark.asyncio
async def test_a_revoked_create_key_is_not_resurrected(sessions) -> None:
    """Replaying a creation key after an admin revoke must fail closed."""
    peer = RecordingSession()
    peer_request(sessions, peer)
    params = {"request_id": "agent-req-revoked", "purpose": "code-review"}
    await sessions.create_peer_session(params)
    await sessions.admin_revoke(PEER_SESSION)

    with pytest.raises(BridgeError) as excinfo:
        await sessions.create_peer_session(params)
    assert excinfo.value.code == "session_create_denied"
    assert len(peer.calls) == 1
    assert not await sessions._store.is_authorized(PEER_SESSION)
    assert len(await sessions.admin_grants()) == 1


@pytest.mark.asyncio
async def test_pushed_version_is_strictly_above_the_peer_version(sessions) -> None:
    """B accepts only a strictly higher version; the push must therefore exceed it."""
    peer = RecordingSession()
    peer_request(sessions, peer)
    pushed: list[dict] = []

    async def on_change(snapshot: dict) -> None:
        """Record every snapshot offered to the peer."""
        pushed.append(snapshot)

    sessions._on_authz_changed = on_change
    result = await sessions.create_peer_session(
        {"request_id": "agent-req-version", "purpose": "code-review"}
    )

    assert result["authz_version"] > PEER_AUTHZ_VERSION
    assert pushed and pushed[-1]["version"] > PEER_AUTHZ_VERSION


@pytest.mark.asyncio
async def test_version_floor_never_lowers_the_local_counter(store) -> None:
    """Adopting a peer version only ever raises; a lower value changes nothing."""
    service = SessionService(
        store, conn="default", allow_agent_create=True, max_agent_sessions=10
    )
    await service.init()
    await service.admin_set_policy(True, 10)
    before = (await service.snapshot())["version"]

    assert await store.raise_authz_version_floor(before - 1) == before
    assert await store.raise_authz_version_floor(before + 10) == before + 10


@pytest.mark.asyncio
async def test_policy_denial_does_not_contact_the_peer(sessions) -> None:
    """A locally denied creation fails before any peer session is reserved."""
    peer = RecordingSession()
    peer_request(sessions, peer)
    await sessions.admin_set_policy(False, 10)
    with pytest.raises(BridgeError) as excinfo:
        await sessions.create_peer_session(
            {"request_id": "agent-req-policy", "purpose": "code-review"}
        )
    assert excinfo.value.code == "session_create_denied"
    assert peer.calls == []
    assert await sessions.admin_grants() == []


@pytest.mark.asyncio
async def test_quota_denial_does_not_contact_the_peer(sessions) -> None:
    """An exhausted local quota is refused before the peer round trip."""
    peer = RecordingSession()
    peer_request(sessions, peer)
    await sessions.admin_set_policy(True, 0)
    with pytest.raises(BridgeError) as excinfo:
        await sessions.create_peer_session(
            {"request_id": "agent-req-quota", "purpose": "code-review"}
        )
    assert excinfo.value.code == "session_quota_exceeded"
    assert peer.calls == []
    assert await sessions.admin_grants() == []


@pytest.mark.asyncio
async def test_inbound_create_still_mints_locally_without_the_peer(sessions) -> None:
    """The inbound handler keeps lazy local creation: AstrBot may lack the session.

    This is the deliberate asymmetry: when the *peer* asks A to create an
    AstrBot-side session, A may mint it because AstrBot materializes it on
    demand. That path must not be rerouted through the peer, or it would recurse.
    """
    peer = RecordingSession()
    peer_request(sessions, peer)
    result = await sessions.create_session(
        {"request_id": "peer-chosen-request", "purpose": "inbound"}
    )
    assert result["session_id"] != PEER_SESSION
    assert peer.calls == []
    assert await sessions._store.is_authorized(result["session_id"])


@pytest.mark.asyncio
async def test_inbound_create_rejects_the_outbound_namespace(sessions) -> None:
    """A peer key in the outbound namespace could alias an agent-created session."""
    peer = RecordingSession()
    peer_request(sessions, peer)
    with pytest.raises(BridgeError) as excinfo:
        await sessions.create_session(
            {"request_id": "outbound:agent-req-1", "purpose": "inbound"}
        )
    assert excinfo.value.code == "bad_params"
    assert peer.calls == []
    assert await sessions.admin_grants() == []


class _Host:
    """Minimal AstrBot host double for the composition-root test."""

    def add_llm_tools(self, *tools) -> None:
        """Ignore LLM tool registration.

        Args:
            tools: Tool adapters.
        """

    def register_web_api(self, route, handler, methods, desc) -> None:
        """Ignore Dashboard route registration.

        Args:
            route: Route path.
            handler: Request handler.
            methods: HTTP methods.
            desc: Route description.
        """

    def get_config(self) -> dict:
        """Return an empty host configuration.

        Returns:
            Empty mapping.
        """
        return {}


@pytest.mark.asyncio
async def test_llm_create_session_uses_the_peer_first_path(
    tmp_path, monkeypatch
) -> None:
    """The composition root wires the live provider and the tool uses it."""
    monkeypatch.setattr(
        main, "get_astrbot_plugin_data_path", lambda: str(tmp_path / "plugin_data")
    )
    plugin = main.DshBridgePlugin(_Host(), {"dashboard_enabled": False})
    try:
        await plugin.initialize()
        service = plugin._sessions_svc
        assert service is not None
        assert service._session_provider is not None

        peer = RecordingSession()
        plugin._session = peer
        assert service._session_provider() is peer

        text = await plugin.llm_create_session(SimpleNamespace(), "plugin-test", "标题")
        assert PEER_SESSION in text
        assert [call["message"] for call in peer.calls] == ["session.create"]
        assert await service._store.is_authorized(PEER_SESSION)
    finally:
        await plugin.terminate()
