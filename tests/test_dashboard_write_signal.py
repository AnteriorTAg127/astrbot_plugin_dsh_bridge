"""Static contract checks for the Dashboard view write-capability signal.

These tests read ``views/bridge/index.html`` as text. They guard the fail-closed
contract that only a literal ``can_write === true`` in the ``GET status``
response may enable write controls, and that a failed status fetch clears the
flag instead of keeping a stale grant.

They are not a runtime UI acceptance test: browser behaviour (DOM state, bridge
calls, rendered buttons) still requires manual or browser-driven verification.
"""

from __future__ import annotations

import re
from pathlib import Path

INDEX_PATH = Path(__file__).resolve().parent.parent / "views" / "bridge" / "index.html"


def view_source() -> str:
    """Return the Dashboard view source.

    Returns:
        The HTML file content.
    """
    return INDEX_PATH.read_text(encoding="utf-8")


def function_body(source: str, signature: str) -> str:
    """Extract a JavaScript function body by brace matching.

    Args:
        source: Full HTML source.
        signature: Function prefix such as ``async function loadStatus()``.

    Returns:
        The text between the outermost braces of the function.

    Raises:
        AssertionError: When the signature or its braces are missing.
    """
    start = source.find(signature)
    assert start >= 0, f"missing function: {signature}"
    brace = source.find("{", start)
    assert brace >= 0, f"missing body: {signature}"
    depth = 0
    for index in range(brace, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1 : index]
    raise AssertionError(f"unbalanced braces: {signature}")


def can_write_assignments(source: str) -> list[str]:
    """Return the right-hand sides of ``state.canWrite`` assignments.

    Args:
        source: Full HTML source.

    Returns:
        Assignment expressions without the trailing semicolon.
    """
    return [
        expr.strip() for expr in re.findall(r"state\.canWrite\s*=\s*([^;]+);", source)
    ]


def test_can_write_starts_false() -> None:
    """The page starts fail-closed before any status response arrives."""
    state_literal = re.search(r"const state = \{[^}]*\};", view_source())
    assert state_literal is not None
    assert re.search(r"canWrite:\s*false", state_literal.group(0))


def test_only_strict_status_can_write_enables_writes() -> None:
    """Only ``data.can_write === true`` may turn the flag on."""
    assignments = can_write_assignments(view_source())
    assert assignments
    enabling = [expr for expr in assignments if expr != "false"]
    assert len(enabling) == 1
    assert re.fullmatch(r"data\??\.can_write\s*===\s*true", enabling[0])


def test_identity_locale_no_longer_grants_writes() -> None:
    """Dashboard context presence is not a write signal any more."""
    source = view_source()
    assert "detectIdentity" not in source
    for expr in can_write_assignments(source):
        assert "locale" not in expr
        assert "context" not in expr


def test_status_failure_clears_can_write() -> None:
    """A rejected status fetch must reset the flag and reapply the gate."""
    body = function_body(view_source(), "async function loadStatus()")
    catch_block = re.search(r"catch \(error\) \{(.*?)\} finally \{", body, re.S)
    assert catch_block is not None
    assert "state.canWrite = false;" in catch_block.group(1)
    assert re.search(r"\} finally \{\s*applyCanWrite\(\);\s*\}", body)


def test_apply_can_write_gates_every_write_control() -> None:
    """The gate toggles the notice, the hint and all marked controls."""
    body = function_body(view_source(), "function applyCanWrite()")
    assert 'document.getElementById("auth-notice").hidden = state.canWrite' in body
    assert 'document.querySelectorAll("[data-write]")' in body
    assert "button.disabled = !state.canWrite" in body


def test_write_buttons_carry_the_gate_marker() -> None:
    """Every rendered write button opts into the shared ``data-write`` gate."""
    source = view_source()
    buttons = re.findall(
        r"<button\b[^>]*data-(?:revoke|resolve|approve|reject)[^>]*>", source
    )
    assert buttons
    for tag in buttons:
        assert "data-write" in tag, tag


def test_startup_loads_status_before_rendering_actions() -> None:
    """Startup applies the gate, then resolves status before other loaders."""
    source = view_source()
    startup = source[source.index("// Fail closed before any network call") :]
    assert startup.index("applyCanWrite();") < startup.index("await bridge.ready()")
    assert startup.index("await bridge.ready()") < startup.index("await refreshAll()")
    refresh_body = function_body(source, "async function refreshAll()")
    assert refresh_body.index("await loadStatus()") < refresh_body.index(
        "loadSessions()"
    )
    assert "Promise.all([loadStatus()" not in source
    assert "setInterval(loadStatus" in source
