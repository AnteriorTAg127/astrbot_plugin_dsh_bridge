"""Layering and governance scans (protocol §1.1, §16.4, PRD §6.12).

These tests read the source tree as text: they are cheap, deterministic guards against
architectural drift and against re-introducing a privilege-escalation path.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
BRIDGE = PLUGIN_ROOT / "bridge"

#: Directories that are not shipped plugin code: process documents (``开发/``),
#: throwaway caches, and audit/integration artefacts produced by other agents.
_SKIP_DIRS = frozenset({"__pycache__", ".pytest_cache", "开发", "data", "integration"})


def _py_files(root: Path) -> list[Path]:
    """Return every Python file under ``root`` that is shipped plugin code.

    Args:
        root: Directory to scan.

    Returns:
        Sorted list of paths.
    """
    return sorted(
        path
        for path in root.rglob("*.py")
        if not _SKIP_DIRS & set(path.parts)
    )


def _imports(path: Path) -> set[str]:
    """Collect the module names imported by a file.

    Args:
        path: Python source file.

    Returns:
        Set of imported module strings (``from`` module + imported names).
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = "." * node.level + node.module
            found.add(base)
            for alias in node.names:
                found.add(f"{base}.{alias.name}")
    return found


def test_transport_never_imports_app_or_host() -> None:
    """``transport/*`` must not know about business or host semantics (§1.1)."""
    for path in _py_files(BRIDGE / "transport"):
        imports = _imports(path)
        for name in imports:
            assert not re.search(r"(^|\.)app(\.|$)", name.replace(".bridge", "")), (
                f"{path.name} must not import app layer: {name}"
            )
            assert "host" not in name, f"{path.name} must not import host layer: {name}"


def test_transport_does_not_reference_message_names() -> None:
    """The transport layer moves bytes only; it must not branch on ``m`` values."""
    forbidden = ("task.submit", "task.event", "approval.request", "session.authz")
    for path in _py_files(BRIDGE / "transport"):
        source = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in source, f"{path.name} must not know message name {token}"


def test_session_layer_does_not_import_app_or_host() -> None:
    """``session.py``/``router.py``/``store.py`` stay below the app layer (§1.1)."""
    for name in ("session.py", "router.py", "store.py", "crypto.py", "replay.py"):
        imports = _imports(BRIDGE / name)
        for module in imports:
            assert "app" not in module.split("."), f"{name} must not import app: {module}"
            assert "host" not in module, f"{name} must not import host: {module}"


def test_host_never_imports_session_or_transport() -> None:
    """``host/*`` exposes native actions only (§1.1)."""
    for path in _py_files(BRIDGE / "host"):
        imports = _imports(path)
        for module in imports:
            assert "transport" not in module, f"{path.name} must not import transport"
            assert not module.endswith(("session.session", "session.Session")), (
                f"{path.name} must not import the session layer: {module}"
            )


def test_app_never_touches_sockets() -> None:
    """``app/*`` must not open sockets or import aiohttp/httpx (§1.1)."""
    for path in _py_files(BRIDGE / "app"):
        source = path.read_text(encoding="utf-8")
        for token in ("import aiohttp", "import httpx", "import socket", "import ws"):
            assert token not in source, f"{path.name} must not import network stack"


def test_no_cron_privilege_escalation() -> None:
    """No source file may create cron jobs or fake an admin role (§16.4)."""
    patterns = (
        r'"origin"\s*:\s*"api"',
        r"'origin'\s*:\s*'api'",
        r"cron_payload",
        r"extras\[\s*[\"']cron_payload[\"']\s*\]",
        r"role\s*=\s*[\"']admin[\"']",
        r"set_approval_policy",
        r"setPolicy",
        r"set_approval",
    )
    for path in _py_files(PLUGIN_ROOT):
        if "tests" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        for pattern in patterns:
            assert not re.search(pattern, source), (
                f"{path.relative_to(PLUGIN_ROOT)} matches forbidden pattern {pattern}"
            )


def test_no_requests_library() -> None:
    """The project uses async HTTP only; ``requests`` is forbidden."""
    for path in _py_files(PLUGIN_ROOT):
        if "tests" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        assert not re.search(r"^\s*import requests\b", source, re.M), (
            f"{path.name} must not import requests"
        )
        assert "requests." not in source, f"{path.name} must not use requests"


def test_logging_uses_astrbot_logger() -> None:
    """Plugins log through ``astrbot.api.logger``, never the stdlib module."""
    for path in _py_files(PLUGIN_ROOT):
        if "tests" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        assert "import logging" not in source, f"{path.name} must not import logging"
        assert "logging.getLogger" not in source, f"{path.name} must not build loggers"


def test_persistent_data_uses_plugin_data_path() -> None:
    """Durable state lives under ``data/plugin_data``, never in the plugin directory."""
    main_source = (PLUGIN_ROOT / "main.py").read_text(encoding="utf-8")
    assert "get_astrbot_plugin_data_path" in main_source
    assert "PLUGIN_NAME" in main_source
    # ``store.py`` receives the path from its caller; it must not build one itself.
    store_tree = ast.parse(
        (BRIDGE / "store.py").read_text(encoding="utf-8"), filename="store.py"
    )
    code_only = "\n".join(
        ast.unparse(node) for node in store_tree.body if not isinstance(node, ast.Expr)
    )
    assert "plugin_data" not in code_only
    # Writable paths must come from the host, never from the plugin's own location.
    for path in _py_files(PLUGIN_ROOT):
        if "tests" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        assert "Path(__file__)" not in source, (
            f"{path.name} must not derive writable paths from __file__"
        )


def test_no_secret_is_logged() -> None:
    """No log call may interpolate a secret value into its format arguments."""
    secret_names = ("psk_secret", "api_key", "conn_psk_secret", "openapi_api_key")
    for path in _py_files(PLUGIN_ROOT):
        if "tests" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "logger"
            ):
                continue
            for arg in node.args:
                for inner in ast.walk(arg):
                    if isinstance(inner, ast.Name) and inner.id in secret_names:
                        raise AssertionError(
                            f"{path.name}:{node.lineno} logs secret variable {inner.id}"
                        )
                    if isinstance(inner, ast.Attribute) and inner.attr in secret_names:
                        raise AssertionError(
                            f"{path.name}:{node.lineno} logs secret attribute {inner.attr}"
                        )


def test_readme_and_changelog_exist() -> None:
    """User-facing documentation is present (stage 12)."""
    assert (PLUGIN_ROOT / "README.md").is_file()
    assert (PLUGIN_ROOT / "CHANGELOG.md").is_file()


def test_metadata_uses_repo_key_not_repo_url() -> None:
    """``metadata.yaml`` must use ``repo`` (the key the host actually reads)."""
    text = (PLUGIN_ROOT / "metadata.yaml").read_text(encoding="utf-8")
    assert "repo_url" not in text
    assert re.search(r"^repo:\s*https://github\.com/", text, re.M)
    assert re.search(r"^name:\s*astrbot_plugin_dsh_bridge", text, re.M)


def test_license_history_is_preserved() -> None:
    """The upstream template LICENSE stays in place (history must not be dropped)."""
    assert (PLUGIN_ROOT / "LICENSE").is_file()
    text = (PLUGIN_ROOT / "LICENSE").read_text(encoding="utf-8", errors="ignore")
    assert "GNU AFFERO GENERAL PUBLIC LICENSE" in text.upper()


def test_layer_packages_have_init_files() -> None:
    """Every layer is an importable package."""
    for name in ("bridge", "bridge/app", "bridge/host", "bridge/transport"):
        assert (PLUGIN_ROOT / name / "__init__.py").is_file()
