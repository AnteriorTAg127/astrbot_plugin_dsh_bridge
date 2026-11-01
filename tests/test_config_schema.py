"""Configuration contract tests (protocol §14, project rule: no ``null`` defaults)."""

from __future__ import annotations

import json
import re
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = PLUGIN_ROOT / "_conf_schema.json"
METADATA_PATH = PLUGIN_ROOT / "metadata.yaml"


def load_schema() -> dict:
    """Load the plugin configuration schema.

    Returns:
        Parsed schema dictionary.
    """
    with SCHEMA_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def iter_properties(schema: dict):
    """Yield every configuration property, including nested and template items.

    Args:
        schema: Root schema object.

    Yields:
        ``(dotted_path, property_meta)`` pairs.
    """

    def walk(node: dict, prefix: str):
        for key, meta in node.items():
            path = f"{prefix}.{key}" if prefix else key
            if not isinstance(meta, dict):
                continue
            yield path, meta
            yield from walk(meta.get("items", {}) or {}, path)
            templates = meta.get("templates") or {}
            for template_name, template in templates.items():
                items = (template or {}).get("items") or {}
                yield from walk(items, f"{path}.{template_name}")

    yield from walk(schema, "")


def test_schema_is_valid_json() -> None:
    """The configuration schema parses as JSON."""
    assert isinstance(load_schema(), dict)


def test_no_null_defaults() -> None:
    """No property may declare ``default: null`` (hard project rule)."""
    offenders = [
        path for path, meta in iter_properties(load_schema()) if "default" in meta and meta["default"] is None
    ]
    assert offenders == [], f"null defaults found: {offenders}"


def test_every_property_has_a_default() -> None:
    """Every scalar/list property carries an explicit default.

    ``template_list`` is exempt: AstrBot coerces it from ``DEFAULT_VALUE_MAP`` and the
    documented schema for it has no ``default`` field.
    """
    missing = [
        path
        for path, meta in iter_properties(load_schema())
        if "default" not in meta and meta.get("type") != "template_list"
    ]
    assert missing == [], f"properties without defaults: {missing}"


def test_every_property_has_description_and_type() -> None:
    """Every property documents itself and declares a supported type."""
    allowed = {
        "string",
        "text",
        "int",
        "float",
        "bool",
        "object",
        "list",
        "dict",
        "template_list",
        "file",
    }
    for path, meta in iter_properties(load_schema()):
        if "type" not in meta:
            # Template items inherit defaults from the parent template definition.
            continue
        assert meta["type"] in allowed, f"{path} uses unsupported type {meta['type']}"
        assert isinstance(meta.get("description"), str) and meta["description"], (
            f"{path} is missing a description"
        )


def test_secret_fields_are_masked_and_empty_by_default() -> None:
    """PSK and OpenAPI key fields are masked and start empty (§3.2, §16.3)."""
    schema = load_schema()
    connections = schema["connections"]
    items = connections["templates"]["dsh_bridge"]["items"]
    psk = items["conn_psk_secret"]
    assert psk["secret"] is True
    assert psk["default"] == ""
    assert schema["openapi_api_key"]["secret"] is True
    assert schema["openapi_api_key"]["default"] == ""
    # The non-secret identifiers are also empty, so no credential is pre-filled.
    assert items["conn_psk_id"]["default"] == ""
    assert schema["openapi_key_id"]["default"] == ""


def test_no_credential_shaped_defaults() -> None:
    """No default may look like a real key (defensive check for accidental commits)."""
    pattern = re.compile(r"abk_[A-Za-z0-9_-]{8,}")
    raw = SCHEMA_PATH.read_text(encoding="utf-8")
    assert not pattern.search(raw)
    for path, meta in iter_properties(load_schema()):
        default = meta.get("default")
        if isinstance(default, str):
            assert "abk_" not in default, f"{path} default looks like an API key"


def test_protocol_defaults_match_contract() -> None:
    """Defaults line up with the protocol §14 table."""
    schema = load_schema()
    items = schema["connections"]["templates"]["dsh_bridge"]["items"]
    assert items["conn_id"]["default"] == "default"
    assert items["conn_mode"]["default"] == "connect"
    assert items["conn_transport"]["default"] == "ws"
    assert items["conn_transport_fallback"]["default"] == ["longpoll"]
    assert items["conn_host"]["default"] == "127.0.0.1"
    assert items["conn_port"]["default"] == 8765
    assert items["conn_path"]["default"] == "/dsh-bridge"
    assert items["conn_tls_enabled"]["default"] is False
    assert items["conn_allow_agent_create"]["default"] is True
    assert items["conn_max_agent_sessions"]["default"] == 10
    assert schema["heartbeat_interval"]["default"] == 30
    assert schema["reconnect_max_backoff"]["default"] == 60
    assert schema["task_retention_days"]["default"] == 7
    assert schema["approval_timeout_seconds"]["default"] == 1800
    assert schema["approval_notify_channels"]["default"] == ["im", "web"]
    assert schema["wake_max_chain"]["default"] == 8
    assert schema["wake_rate_per_minute"]["default"] == 10
    assert schema["image_enabled"]["default"] is True
    assert schema["image_max_count"]["default"] == 4
    assert schema["image_max_bytes"]["default"] == 10485760
    assert schema["image_total_max_bytes"]["default"] == 20971520
    assert schema["image_allowed_mime"]["default"] == [
        "image/gif",
        "image/jpeg",
        "image/png",
        "image/webp",
    ]
    assert schema["openapi_base_url"]["default"] == "http://127.0.0.1:6185"


def test_image_defaults_stay_under_host_limits() -> None:
    """Image limits must not exceed the DSH host caps (§13.2)."""
    schema = load_schema()
    assert schema["image_max_bytes"]["default"] <= 20 * 1024 * 1024
    assert schema["image_total_max_bytes"]["default"] <= 200 * 1024 * 1024
    assert schema["image_max_count"]["default"] <= 20


def test_connection_is_a_template_list() -> None:
    """Connections use ``template_list`` so each connection carries its own PSK (§14)."""
    connections = load_schema()["connections"]
    assert connections["type"] == "template_list"
    assert "dsh_bridge" in connections["templates"]


def test_metadata_required_fields() -> None:
    """``metadata.yaml`` provides the host-required fields and a SemVer-ish version."""
    text = METADATA_PATH.read_text(encoding="utf-8")
    for field in ("name", "desc", "version", "author"):
        assert re.search(rf"^{field}:\s*\S", text, re.M), f"missing metadata field {field}"
    assert re.search(r"^version:\s*v?\d+\.\d+\.\d+", text, re.M)
    assert re.search(r"^name:\s*astrbot_plugin_", text, re.M)
    assert re.search(r'^astrbot_version:\s*">=', text, re.M)
