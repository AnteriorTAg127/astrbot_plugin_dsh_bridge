"""Host boundary contracts: delivery verdicts, platform reachability, session UMO.

These tests pin the AstrBot contracts the bridge depends on:

* ``Context.send_message`` returns ``True``/``False`` and raises ``ValueError`` for a
  malformed UMO (``astrbot/core/star/context.py``), so ``PlatformHost`` must propagate
  the verdict instead of claiming success.
* ``Context.get_platform_inst`` matches ``Platform.meta().id``, so a UMO is deliverable
  only while its platform instance is registered.
* ``POST /api/v1/chat`` derives the conversation from ``username`` + ``session_id`` and
  the webchat adapter stores ``webchat!{username}!{cid}``, so the bridge must rebuild
  exactly that UMO to ask about its own sessions.

Everything runs offline against small doubles; no platform or OpenAPI server is used.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from bridge.host.openapi import OpenApiHost
from bridge.host.platform import PlatformHost

from astrbot.core.platform.message_session import MessageSesion
from astrbot.core.platform.message_type import MessageType

UMO = "webchat:FriendMessage:webchat!api_key:k1!sess-1"


class StubPlatform:
    """Platform instance double exposing only ``meta().id``."""

    def __init__(self, platform_id: str) -> None:
        """Create the double.

        Args:
            platform_id: Value returned by ``meta().id``.
        """
        self._platform_id = platform_id

    def meta(self) -> SimpleNamespace:
        """Return the platform metadata the host matches against.

        Returns:
            An object carrying the platform instance id.
        """
        return SimpleNamespace(id=self._platform_id)


class StubContext:
    """AstrBot ``Context`` double with an adjustable delivery verdict."""

    def __init__(
        self,
        *,
        verdict: bool = True,
        error: Exception | None = None,
        platforms: tuple[StubPlatform, ...] = (),
        lookup_error: Exception | None = None,
    ) -> None:
        """Create the double.

        Args:
            verdict: Value returned by ``send_message``.
            error: Exception raised by ``send_message`` instead of returning.
            platforms: Platform instances visible to ``get_platform_inst``.
            lookup_error: Exception raised by ``get_platform_inst``.
        """
        self.verdict = verdict
        self.error = error
        self.lookup_error = lookup_error
        self.platforms = {platform.meta().id: platform for platform in platforms}
        self.sent: list[tuple[str, object]] = []
        self.lookups: list[str] = []

    async def send_message(self, session: str, chain: object) -> bool:
        """Record one active-message attempt and return the configured verdict.

        Args:
            session: UMO passed by the host adapter.
            chain: Message chain passed by the host adapter.

        Returns:
            The configured verdict.

        Raises:
            Exception: The configured ``error``, when set.
        """
        self.sent.append((session, chain))
        if self.error is not None:
            raise self.error
        return self.verdict

    def get_platform_inst(self, platform_id: str) -> StubPlatform | None:
        """Resolve a platform double exactly like the real ``Context``.

        Args:
            platform_id: Platform instance id to look up.

        Returns:
            The matching platform double, or ``None``.

        Raises:
            Exception: The configured ``lookup_error``, when set.
        """
        self.lookups.append(platform_id)
        if self.lookup_error is not None:
            raise self.lookup_error
        return self.platforms.get(platform_id)


@pytest.mark.asyncio
async def test_send_text_returns_true_when_host_accepts() -> None:
    """A successful ``send_message`` is reported as ``True``."""
    context = StubContext(verdict=True)
    host = PlatformHost(context)

    assert await host.send_text(UMO, "hello") is True
    assert len(context.sent) == 1
    assert context.sent[0][0] == UMO


@pytest.mark.asyncio
async def test_send_text_returns_false_when_host_finds_no_platform() -> None:
    """``send_message`` returning ``False`` must not be reported as delivered."""
    context = StubContext(verdict=False)
    host = PlatformHost(context)

    assert await host.send_text(UMO, "hello") is False
    assert len(context.sent) == 1


@pytest.mark.asyncio
async def test_send_text_invalid_umo_is_false_not_an_exception() -> None:
    """A malformed UMO makes the host raise ``ValueError``; delivery is ``False``."""
    context = StubContext(error=ValueError("不合法的 session 字符串"))
    host = PlatformHost(context)

    assert await host.send_text("not-a-umo", "hello") is False


@pytest.mark.asyncio
async def test_send_text_empty_umo_never_reaches_the_host() -> None:
    """An empty UMO is skipped before any host call."""
    context = StubContext()
    host = PlatformHost(context)

    assert await host.send_text("", "hello") is False
    assert context.sent == []


@pytest.mark.asyncio
@pytest.mark.parametrize("verdict", [True, False])
async def test_send_chain_returns_the_host_verdict(verdict: bool) -> None:
    """``send_chain`` propagates the ``send_message`` verdict unchanged."""
    context = StubContext(verdict=verdict)
    host = PlatformHost(context)

    result = await host.send_chain(UMO, [{"type": "plain", "text": "hello"}])
    assert result is verdict
    assert len(context.sent) == 1


@pytest.mark.asyncio
async def test_send_chain_invalid_umo_is_false_not_an_exception() -> None:
    """A malformed UMO on the chain path is also reported as ``False``."""
    context = StubContext(error=ValueError("不合法的 session 字符串"))
    host = PlatformHost(context)

    assert await host.send_chain("not-a-umo", [{"type": "plain", "text": "x"}]) is False


@pytest.mark.asyncio
async def test_send_chain_empty_umo_never_reaches_the_host() -> None:
    """An empty UMO is skipped before any host call on the chain path."""
    context = StubContext()
    host = PlatformHost(context)

    assert await host.send_chain("", [{"type": "plain", "text": "x"}]) is False
    assert context.sent == []


def test_can_send_matches_registered_platform_id() -> None:
    """A UMO is sendable only while its platform id is registered."""
    context = StubContext(platforms=(StubPlatform("webchat"),))
    host = PlatformHost(context)

    assert host.can_send(UMO) is True
    assert context.lookups == ["webchat"]
    # Reachability is a pure lookup: nothing is ever sent.
    assert context.sent == []


def test_can_send_rejects_unregistered_platform_id() -> None:
    """A different registered platform must not satisfy the UMO's platform id."""
    context = StubContext(platforms=(StubPlatform("aiocqhttp"),))
    host = PlatformHost(context)

    assert host.can_send(UMO) is False
    assert context.lookups == ["webchat"]


def test_can_send_accepts_group_message_umo() -> None:
    """Group and friend UMOs are treated identically; only the platform id matters."""
    context = StubContext(platforms=(StubPlatform("webchat"),))
    host = PlatformHost(context)

    group_umo = "webchat:GroupMessage:webchat!api_key:k1!group-1"
    assert host.can_send(group_umo) is True


@pytest.mark.parametrize("umo", ["", "not-a-umo", ":FriendMessage:only-session"])
def test_can_send_rejects_malformed_umo_without_default_fallback(umo: str) -> None:
    """Malformed or platform-less UMOs are ``False``; no default fallback applies."""
    context = StubContext(platforms=(StubPlatform("webchat"),))
    host = PlatformHost(context, default_platform_id="webchat")

    assert host.can_send(umo) is False
    assert context.lookups == []


def test_can_send_false_when_platform_lookup_raises() -> None:
    """A failing platform lookup degrades to ``False`` instead of raising."""
    context = StubContext(platforms=(StubPlatform("webchat"),))
    context.lookup_error = RuntimeError("platform manager exploded")
    host = PlatformHost(context)

    assert host.can_send(UMO) is False


def make_openapi_host(key_id: str = "k1") -> OpenApiHost:
    """Build an adapter with test credentials (never real).

    Args:
        key_id: Non-secret key id used as ``username``.

    Returns:
        The adapter.
    """
    return OpenApiHost(
        base_url="http://127.0.0.1:6185", api_key="test-key", key_id=key_id
    )


def test_umo_for_session_uses_verified_identity() -> None:
    """The UMO carries ``api_key:<key_id>`` as its webchat username segment."""
    host = make_openapi_host("k1")

    assert (
        host.umo_for_session("sess-1")
        == "webchat:FriendMessage:webchat!api_key:k1!sess-1"
    )


def test_umo_for_session_round_trips_through_host_parser() -> None:
    """The UMO parses back into the webchat platform and keeps the username intact.

    ``MessageSession.from_str`` splits on the first two colons, so the ``api_key:<id>``
    username must survive inside the session segment and must not shift the platform id.
    """
    host = make_openapi_host("k1")
    session = MessageSesion.from_str(host.umo_for_session("sess-1"))

    assert session.platform_id == "webchat"
    assert session.message_type is MessageType.FRIEND_MESSAGE
    assert session.session_id == "webchat!api_key:k1!sess-1"


def test_umo_for_session_tracks_key_id_and_session() -> None:
    """Different key ids and session ids produce different UMOs."""
    host = make_openapi_host("k1")
    other_key = make_openapi_host("k2")

    assert host.umo_for_session("sess-1") != host.umo_for_session("sess-2")
    assert other_key.umo_for_session("sess-1") == (
        "webchat:FriendMessage:webchat!api_key:k2!sess-1"
    )
