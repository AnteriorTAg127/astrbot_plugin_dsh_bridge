"""``event.ack`` must never block the serial inbound ``receive`` path (§11.1).

An ack is produced while the receive loop is handling a frame. The loop is serial:
awaiting a request/reply there stalls every later frame for up to the reply timeout,
which is what stalled the bridge for 60s. These tests pin the fix — the ack is
*queued* (the callback reports ``queued``, never a made-up ``delivered``), the task is
owned so ``terminate`` can cancel and reap it, and an unusable link still raises.
"""

from __future__ import annotations

import asyncio
import importlib
import sys
from pathlib import Path

import pytest
from bridge.app.notify import build_ack_params

PLUGIN_ROOT = Path(__file__).resolve().parent.parent


def _plugin_module():
    """Import the composition root the way AstrBot does.

    Returns:
        The ``astrbot_plugin_dsh_bridge.main`` module object.
    """
    package = PLUGIN_ROOT.name
    if package not in sys.path and PLUGIN_ROOT.parent.exists():
        sys.path.insert(0, str(PLUGIN_ROOT.parent))
    if str(PLUGIN_ROOT) not in sys.path:
        sys.path.insert(0, str(PLUGIN_ROOT))
    return importlib.import_module(f"{package}.main")


class BlockingSession:
    """A ready session whose ``call`` blocks until the test resolves its future."""

    def __init__(self, module) -> None:
        """Create the session double.

        Args:
            module: The plugin module, used for ``SessionState.READY``.
        """
        self.state = module.SessionState.READY
        self.calls: list[tuple[str, dict]] = []
        self.reply: asyncio.Future = asyncio.get_running_loop().create_future()

    async def call(self, message: str, params: dict, timeout_s=None) -> dict:
        """Record the request and wait for the test to resolve ``reply``.

        Args:
            message: Wire message name.
            params: Request parameters.
            timeout_s: Ignored by the double.

        Returns:
            Whatever the test resolved ``reply`` with.
        """
        self.calls.append((message, params))
        return await self.reply


def _plugin_with(module, session):
    """Build a plugin instance bypassing ``__init__`` wiring.

    Args:
        module: The plugin module.
        session: Session double to install.

    Returns:
        A plugin instance pointed at ``session``.
    """
    plugin = module.DshBridgePlugin.__new__(module.DshBridgePlugin)
    plugin._session = session
    plugin._ack_tasks = set()
    plugin._background = []
    plugin._started = False
    plugin._tasks = None
    plugin._manager = None
    plugin._notify = None
    plugin._blobs = None
    plugin._openapi = None
    plugin._store = None
    return plugin


@pytest.mark.asyncio
async def test_ack_request_returns_while_the_call_is_still_pending() -> None:
    """A blocking ``session.call`` must not block the caller (the receive loop)."""
    main_module = _plugin_module()
    session = BlockingSession(main_module)
    plugin = _plugin_with(main_module, session)
    params = build_ack_params("n-peer-1", "t-1", "t-1", "processed")

    reply = await asyncio.wait_for(plugin._send_ack_request(params), timeout=1.0)

    # Queued, not delivered: the peer has not answered yet.
    assert reply == {"notify_id": "n-peer-1", "queued": True}
    # Let the queued task start and block on the unresolved reply.
    await asyncio.sleep(0)
    assert session.calls == [("event.ack", params)]
    assert len(plugin._ack_tasks) == 1
    assert not plugin._ack_tasks.copy().pop().done()

    # The next frame resolves the reply; the background task then completes.
    session.reply.set_result({"notify_id": "n-peer-1", "ok": True})
    pending = list(plugin._ack_tasks)
    await asyncio.wait_for(asyncio.gather(*pending), timeout=1.0)


@pytest.mark.asyncio
async def test_ack_failure_is_logged_and_reaped() -> None:
    """A failed ack call is logged by the task, not raised into the caller."""
    main_module = _plugin_module()
    session = BlockingSession(main_module)
    plugin = _plugin_with(main_module, session)
    params = build_ack_params("n-peer-2", "t-2", "t-2", "processed")

    reply = await asyncio.wait_for(plugin._send_ack_request(params), timeout=1.0)
    assert reply["queued"] is True
    await asyncio.sleep(0)

    session.reply.set_exception(RuntimeError("session closed"))
    await asyncio.wait_for(asyncio.gather(*list(plugin._ack_tasks)), timeout=1.0)
    await asyncio.sleep(0)
    assert plugin._ack_tasks == set()


@pytest.mark.asyncio
async def test_ack_without_a_ready_session_raises() -> None:
    """An unusable link is a loud error, so the peer resend acks again later."""
    main_module = _plugin_module()
    plugin = _plugin_with(main_module, None)
    with pytest.raises(RuntimeError):
        await plugin._send_ack_request(build_ack_params("n-peer-3", "t", "t"))

    class NotReadySession:
        """A session that still exists but lost ``ready``."""

        state = main_module.SessionState.HANDSHAKING

        async def call(self, message: str, params: dict, timeout_s=None) -> dict:
            """Fail the test if a request is attempted while not ready."""
            raise AssertionError("must not call while not ready")

    plugin._session = NotReadySession()
    with pytest.raises(RuntimeError):
        await plugin._send_ack_request(build_ack_params("n-peer-3", "t", "t"))


@pytest.mark.asyncio
async def test_terminate_cancels_and_reaps_queued_acks() -> None:
    """Shutdown must not leave an ack task holding a captured session."""
    main_module = _plugin_module()
    session = BlockingSession(main_module)
    plugin = _plugin_with(main_module, session)

    for index in range(3):
        await plugin._send_ack_request(
            build_ack_params(f"n-peer-{index}", "t-4", "t-4", "processed")
        )
    await asyncio.sleep(0)
    assert len(plugin._ack_tasks) == 3
    assert len(session.calls) == 3

    await asyncio.wait_for(plugin.terminate(), timeout=1.0)

    assert plugin._ack_tasks == set()
    assert session.reply.cancelled() is True
