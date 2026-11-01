"""Schema contract tests for the bind address/port and approval notification UMO."""

from __future__ import annotations

import json
import re
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = PLUGIN_ROOT / "_conf_schema.json"
MAIN_PATH = PLUGIN_ROOT / "main.py"

CONNECTION_ITEMS = "connections.templates.dsh_bridge.items"


def load_schema() -> dict:
    """Load the plugin configuration schema.

    Returns:
        Parsed schema dictionary.
    """
    with SCHEMA_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def connection_items(schema: dict) -> dict:
    """Return the items of the standard DSH connection template.

    Args:
        schema: Root schema object.

    Returns:
        Template item mapping keyed by configuration name.
    """
    return schema["connections"]["templates"]["dsh_bridge"]["items"]


def main_default(pattern: str) -> str:
    """Extract a literal default from ``main.py``.

    Args:
        pattern: Regular expression with one capture group around the default.

    Returns:
        The captured default literal.

    Raises:
        AssertionError: If ``main.py`` does not read the property as expected.
    """
    source = MAIN_PATH.read_text(encoding="utf-8")
    match = re.search(pattern, source)
    assert match is not None, f"main.py does not read the property: {pattern}"
    return match.group(1)


def test_schema_is_valid_json() -> None:
    """The configuration schema parses as JSON and is an object."""
    assert isinstance(load_schema(), dict)


def test_connection_bind_addr_type_and_default_match_main() -> None:
    """``conn_bind_addr`` is a string defaulting to the value read by ``main.py``."""
    items = connection_items(load_schema())
    meta = items["conn_bind_addr"]
    expected = main_default(r'_str\(item\.get\("conn_bind_addr"\),\s*"([^"]*)"\)')
    assert meta["type"] == "string"
    assert meta["default"] == expected
    assert isinstance(meta["default"], str)


def test_connection_bind_port_type_and_default_match_main() -> None:
    """``conn_bind_port`` is an int defaulting to the value read by ``main.py``."""
    items = connection_items(load_schema())
    meta = items["conn_bind_port"]
    expected = int(main_default(r'_int\(\s*item\.get\("conn_bind_port"\),\s*(\d+)'))
    assert meta["type"] == "int"
    assert isinstance(meta["default"], int)
    assert not isinstance(meta["default"], bool)
    assert meta["default"] == expected
    assert 0 <= meta["default"] <= 65535


def test_bind_hints_distinguish_listen_from_peer() -> None:
    """The bind hints state the listen side explicitly and are not the peer side."""
    items = connection_items(load_schema())
    for key in ("conn_bind_addr", "conn_bind_port"):
        hint = items[key]["hint"]
        assert "监听" in hint, key
        assert "对端" in hint, key


def test_approval_notify_umo_type_and_default_match_main() -> None:
    """``approval_notify_umo`` is a string defaulting to what ``main.py`` reads."""
    meta = load_schema()["approval_notify_umo"]
    expected = main_default(
        r'_str\(\s*self\._cfg\("approval_notify_umo",\s*"([^"]*)"\),\s*""\s*\)'
    )
    assert meta["type"] == "string"
    assert meta["default"] == expected
    assert expected == ""


def test_approval_notify_umo_hint_is_web_only_when_empty() -> None:
    """The hint explains that an empty UMO keeps notifications web-only."""
    hint = load_schema()["approval_notify_umo"]["hint"]
    assert "留空" in hint
    assert "Web" in hint
    assert "IM" in hint


def test_new_properties_have_non_null_defaults() -> None:
    """Every touched property declares a concrete, non-null default."""
    items = connection_items(load_schema())
    candidates = [
        items["conn_bind_addr"],
        items["conn_bind_port"],
        load_schema()["approval_notify_umo"],
    ]
    for meta in candidates:
        assert "default" in meta
        assert meta["default"] is not None
