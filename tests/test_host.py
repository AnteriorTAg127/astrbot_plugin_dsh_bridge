"""Host adapter tests: identity ownership, modalities, forbidden sources (§16.3).

These tests assert the governance rules that keep the bridge from escalating its own
privileges, using stubbed HTTP responses rather than a live AstrBot.
"""

from __future__ import annotations

import httpx
import pytest
from bridge.constants import OPENAPI_USERNAME_PREFIX
from bridge.errors import BridgeError
from bridge.host.capabilities import (
    HostCapabilities,
    provider_modalities,
    supports_image,
)
from bridge.host.openapi import (
    OpenApiHost,
    build_message_parts,
    is_loopback,
    is_private,
)


class StubProvider:
    """Provider double exposing ``provider_config['modalities']``."""

    def __init__(self, modalities) -> None:
        """Create the stub.

        Args:
            modalities: Modality list, or ``None`` for "unset".
        """
        self.provider_config = {"id": "p1"}
        if modalities is not None:
            self.provider_config["modalities"] = modalities


def make_host(
    *,
    base_url: str = "http://127.0.0.1:6185",
    key: str = "test-key",
    key_id: str = "k1",
    allow_private: bool = False,
) -> OpenApiHost:
    """Build an adapter with test credentials (never real).

    Args:
        base_url: OpenAPI base URL.
        key: API key value.
        key_id: API key id.
        allow_private: Whether private addresses are allowed.

    Returns:
        The adapter.
    """
    return OpenApiHost(
        base_url=base_url, api_key=key, key_id=key_id, allow_private_addr=allow_private
    )


def test_username_is_api_key_prefixed() -> None:
    """The only usable identity is ``api_key:<key_id>`` (§16.3)."""
    host = make_host(key_id="abc123")
    assert host.username == f"{OPENAPI_USERNAME_PREFIX}abc123"
    assert host.username.startswith("api_key:")


def test_endpoint_must_be_loopback_or_allowed_private() -> None:
    """A public OpenAPI address is refused outright (§16.3 rule 7)."""
    make_host(base_url="http://127.0.0.1:6185").check_endpoint()

    with pytest.raises(BridgeError) as excinfo:
        make_host(base_url="http://8.8.8.8:6185").check_endpoint()
    assert excinfo.value.code == "config_invalid"

    with pytest.raises(BridgeError):
        make_host(base_url="http://192.168.1.10:6185").check_endpoint()

    # Private is allowed only with an explicit opt-in.
    make_host(base_url="http://192.168.1.10:6185", allow_private=True).check_endpoint()


def test_is_loopback_and_is_private_helpers() -> None:
    """Address classifiers behave as the governance rules require."""
    assert is_loopback("127.0.0.1")
    assert is_loopback("localhost")
    assert is_loopback("::1")
    assert not is_loopback("192.168.0.2")
    assert is_private("192.168.0.2")
    assert is_private("10.1.2.3")
    assert not is_private("127.0.0.1")
    assert not is_private("8.8.8.8")


@pytest.mark.asyncio
async def test_ownership_check_rejects_foreign_creator(monkeypatch) -> None:
    """A response whose ``creator`` differs from our identity fails the self-check."""
    host = make_host(key_id="k1")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["username"] == "api_key:k1"
        return httpx.Response(
            200,
            json={
                "status": "ok",
                "data": {
                    "sessions": [
                        {"session_id": "s", "creator": "somebody-else"},
                    ]
                },
            },
        )

    transport = httpx.MockTransport(handler)
    host._client = httpx.AsyncClient(transport=transport)
    with pytest.raises(BridgeError) as excinfo:
        await host.verify_ownership()
    assert excinfo.value.code == "config_invalid"
    assert excinfo.value.details["reason"] == "openapi_identity_mismatch"
    await host.close()


@pytest.mark.asyncio
async def test_ownership_check_accepts_own_sessions(monkeypatch) -> None:
    """Sessions owned by our identity pass the self-check."""
    host = make_host(key_id="k1")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "status": "ok",
                "data": {
                    "sessions": [
                        {"session_id": "s1", "creator": "api_key:k1"},
                        {"session_id": "s2", "creator": "api_key:k1"},
                    ]
                },
            },
        )

    host._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    await host.verify_ownership()
    await host.close()


@pytest.mark.asyncio
async def test_ownership_check_reports_missing_chat_scope() -> None:
    """A 403 means the key lacks the ``chat`` scope, not that we may widen it."""
    host = make_host(key_id="k1")
    host._client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(403, json={}))
    )
    with pytest.raises(BridgeError) as excinfo:
        await host.verify_ownership()
    assert excinfo.value.details["reason"] == "missing_chat_scope"
    await host.close()


@pytest.mark.asyncio
async def test_unconfigured_host_refuses_to_run() -> None:
    """Without a key and key id, no agent run is attempted (§16.3 rule 6)."""
    host = OpenApiHost(base_url="http://127.0.0.1:6185", api_key="", key_id="")
    assert host.configured() is False
    with pytest.raises(BridgeError):
        await host.run_agent(parts=[{"type": "plain", "text": "hi"}])


class StubProviderWithConfig:
    """Provider double exposing an arbitrary ``provider_config`` value."""

    def __init__(self, config) -> None:
        """Create the stub.

        Args:
            config: Value exposed as ``provider_config``.
        """
        self.provider_config = config


@pytest.mark.parametrize(
    ("provider", "expected"),
    [
        pytest.param(None, False, id="provider_none"),
        pytest.param(
            StubProviderWithConfig(["text", "image"]), False, id="config_not_dict"
        ),
        pytest.param(
            StubProviderWithConfig({"modalities": "image"}),
            False,
            id="modalities_not_list",
        ),
        pytest.param(StubProvider(["text"]), False, id="text_only"),
        pytest.param(StubProvider(["text", "image"]), True, id="image_listed"),
        pytest.param(StubProvider(None), False, id="modalities_unset"),
        pytest.param(StubProvider([]), False, id="modalities_empty"),
    ],
)
def test_supports_image_fails_closed(provider, expected: bool) -> None:
    """Only an explicit ``image`` modality counts as vision support (§13.5).

    Unknown, unconfigured, and malformed configurations must never claim vision
    support; sending an image there would fail or be silently dropped.
    """
    assert supports_image(provider) is expected


def test_provider_modalities_normalises_and_fails_closed() -> None:
    """``provider_modalities`` returns ``None`` unless a real list is configured."""
    assert provider_modalities(StubProvider(["text"])) == ["text"]
    assert provider_modalities(StubProvider(None)) is None
    assert provider_modalities(StubProvider([])) == []
    assert provider_modalities(StubProviderWithConfig(["text"])) is None
    assert provider_modalities(StubProviderWithConfig({"modalities": None})) is None
    assert (
        provider_modalities(StubProviderWithConfig({"modalities": ("image",)})) is None
    )


def test_capabilities_require_vision_raises() -> None:
    """Sending an image to a text-only model raises ``model_without_vision``."""
    caps = HostCapabilities(
        version="0.1.0",
        transports=["longpoll", "webhook", "ws"],
        tls=False,
        provider_getter=lambda: StubProvider(["text"]),
    )
    assert caps.supports_vision() is False
    with pytest.raises(BridgeError) as excinfo:
        caps.require_vision()
    assert excinfo.value.code == "model_without_vision"
    caps_ok = HostCapabilities(
        version="0.1.0",
        transports=["ws"],
        tls=False,
        provider_getter=lambda: StubProvider(["text", "image"]),
    )
    caps_ok.require_vision()


def test_capabilities_shape_matches_protocol() -> None:
    """``caps()`` emits the §4.5 object with ``native_tool`` false for A."""
    caps = HostCapabilities(
        version="0.1.0",
        transports=["longpoll", "webhook", "ws"],
        tls=False,
        image_enabled=True,
        image_max_count=4,
        image_max_bytes=10_485_760,
        image_total_max_bytes=20_971_520,
    ).caps()
    assert caps["side"] == "A"
    assert caps["host"] == "astrbot"
    assert caps["approvals"]["native_tool"] is False
    assert caps["attachments"]["reference"] is False
    assert set(caps) == {
        "side",
        "host",
        "version",
        "pv",
        "transports",
        "tls",
        "roles",
        "approvals",
        "attachments",
        "limits",
        "features",
    }


def test_build_message_parts_orders_text_then_images() -> None:
    """Chat parts are plain text first, then image attachments (§6.8)."""
    parts = build_message_parts(["hello"], ["att-1", "att-2"])
    assert parts[0] == {"type": "plain", "text": "hello"}
    assert parts[1] == {"type": "image", "attachment_id": "att-1"}
    assert parts[2] == {"type": "image", "attachment_id": "att-2"}


def test_build_message_parts_never_empty() -> None:
    """An empty task input still produces a valid message array."""
    assert build_message_parts([]) == [{"type": "plain", "text": ""}]


@pytest.mark.asyncio
async def test_sse_parsing_ignores_heartbeats() -> None:
    """SSE heartbeats (``:``) are skipped and ``data:`` objects are decoded (§6.3.1)."""
    from bridge.host.openapi import _iter_sse

    body = (
        b": heartbeat\n\n"
        b'data: {"type": "session_id", "session_id": "sess-1"}\n\n'
        b": heartbeat\n\n"
        b'data: {"type": "plain", "data": "Hello "}\n\n'
        b'data: {"type": "plain", "data": "\xe4\xb8\xad\xe6\x96\x87"}\n\n'
        b'data: {"type": "end"}\n\n'
    )

    class FakeResponse:
        async def aiter_lines(self):
            for line in body.decode("utf-8").split("\n"):
                yield line

    events = [event async for event in _iter_sse(FakeResponse())]
    assert [event["type"] for event in events] == [
        "session_id",
        "plain",
        "plain",
        "end",
    ]
    assert events[2]["data"] == "中文"


@pytest.mark.asyncio
async def test_run_agent_collects_text_and_session(monkeypatch) -> None:
    """A chat run returns concatenated text plus the resolved session id."""
    host = make_host(key_id="k1")
    sse = (
        'data: {"type": "session_id", "session_id": "resolved"}\n\n'
        'data: {"type": "plain", "data": "part1 "}\n\n'
        'data: {"type": "plain", "data": "part2"}\n\n'
        'data: {"type": "end"}\n\n'
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/chat"
        return httpx.Response(200, content=sse.encode("utf-8"))

    host._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    result = await host.run_agent(parts=[{"type": "plain", "text": "hi"}])
    assert result["text"] == "part1 part2"
    assert result["session_id"] == "resolved"
    await host.close()


@pytest.mark.asyncio
async def test_run_agent_error_event_raises() -> None:
    """An SSE ``error`` event fails the run instead of returning partial text."""
    host = make_host(key_id="k1")
    sse = 'data: {"type": "error", "data": "boom"}\n\n'

    host._client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=sse.encode())
        )
    )
    with pytest.raises(BridgeError):
        await host.run_agent(parts=[{"type": "plain", "text": "x"}])
    await host.close()


@pytest.mark.asyncio
async def test_upload_image_returns_attachment_id() -> None:
    """Uploading an image returns the host ``attachment_id`` (§13.1)."""
    host = make_host(key_id="k1")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/file"
        return httpx.Response(
            200,
            json={
                "status": "ok",
                "data": {
                    "attachment_id": "att-9",
                    "filename": "a.png",
                    "type": "image",
                },
            },
        )

    host._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    attachment_id = await host.upload_image(b"\x89PNG", "image/png", "a.png")
    assert attachment_id == "att-9"
    await host.close()


def test_no_api_key_leak_in_diagnostics() -> None:
    """The adapter never exposes the API key through its public surface."""
    host = make_host(key="super-secret-key", key_id="k1")
    assert "super-secret-key" not in repr(host.__dict__.get("_base_url", ""))
    assert host.username == "api_key:k1"
