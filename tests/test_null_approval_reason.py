"""Regression: a legal ``native_tool`` request may carry ``reason: null`` (A receiver).

A genuine B-side native tool request can omit the human reason, i.e. send ``null``.
That null stays part of the wire identity: ``request_digest`` is computed over the
literal ``None`` and must verify unchanged. The SQLite ``approvals.reason`` column is
``TEXT NOT NULL``, so only the *stored/displayed* value may be coerced to ``""``.

Scope of the regression: the request lands as ``pending``, keeps the null-based
digest, and a human can still ``allowed-once`` / ``rejected`` it — trust anchoring
(peer side, human-only decisions) is unchanged.
"""

from __future__ import annotations

import pytest
from bridge.app.approvals import ApprovalService, request_digest_for
from bridge.app.notify import NotifyService
from bridge.constants import APPROVAL_NATIVE_TOOL, MSG_APPROVAL_DECISION

CONN = "default"
TOOL = "bash"
SESSION = "s-null"


class Recorder:
    """Capture outbound events instead of touching a socket."""

    def __init__(self) -> None:
        """Create an empty recorder."""
        self.events: list[dict] = []

    async def on_task_event(self, params: dict) -> None:
        """Ignore ``task.event`` payloads (not under test here)."""

    async def on_event(
        self, params: dict, row: dict, task_id: str, root_task_id: str
    ) -> None:
        """Record one generic event with its message name."""
        self.events.append({**params, "_message": row["message"]})


def null_reason_request(approval_id: str = "ap-null-1") -> dict:
    """Build a valid inbound ``native_tool`` request whose ``reason`` is ``null``.

    Args:
        approval_id: Approval identifier.

    Returns:
        Parameter dictionary whose digest is computed over the literal ``None``.
    """
    params = {
        "approval_id": approval_id,
        "approval_type": APPROVAL_NATIVE_TOOL,
        "task_id": None,
        "root_task_id": None,
        "session_id": SESSION,
        "tool": TOOL,
        "reason": None,
        "display_reason": {"en": "Run a shell command", "zh": "执行 shell 命令"},
        "call_id": None,
        "expires_at": None,
        "notify_id": "n-null-1",
        "origin_side": "B",
    }
    params["request_digest"] = request_digest_for(
        params["tool"],
        params["reason"],
        params["call_id"],
        params["session_id"],
        params["task_id"],
    )
    return params


def build_service(store) -> tuple[ApprovalService, Recorder]:
    """Wire a real :class:`ApprovalService` against the real store.

    Args:
        store: Initialised store fixture.

    Returns:
        ``(service, recorder)`` with a trusted B peer, as assembly would pass it.
    """
    recorder = Recorder()
    notify = NotifyService(
        store,
        conn=CONN,
        on_task_event=recorder.on_task_event,
        on_event=recorder.on_event,
    )
    service = ApprovalService(
        store,
        conn=CONN,
        side="A",
        approval_timeout_s=1800,
        notify_channels=["im", "web"],
        notify=notify,
        peer_side="B",
    )
    return service, recorder


def test_null_reason_digest_differs_from_empty_reason_digest() -> None:
    """The null-based digest is preserved: it is not the digest of ``""``."""
    assert request_digest_for(TOOL, None, None, SESSION, None) != request_digest_for(
        TOOL, "", None, SESSION, None
    )


@pytest.mark.parametrize(
    ("allowed", "outcome"), [(True, "allowed-once"), (False, "rejected")]
)
async def test_null_reason_request_is_stored_and_human_decides(
    store, allowed: bool, outcome: str
) -> None:
    """``reason: null`` is persisted as ``""`` but keeps the null digest and stays decidable."""
    service, recorder = build_service(store)
    params = null_reason_request()

    result = await service.handle_request(params)
    assert result["accepted"] is True

    stored = await store.get_approval("ap-null-1")
    assert stored is not None
    assert stored["state"] == "pending"
    # Storage/display coercion only: the wire digest still covers the literal null.
    assert stored["reason"] == ""
    assert stored["request_digest"] == params["request_digest"]
    assert stored["request_digest"] == request_digest_for(
        TOOL, None, None, SESSION, None
    )
    assert stored["origin_side"] == "B"

    applied, reason = await service.human_decide(
        "ap-null-1", allowed=allowed, actor="astrbot_admin:alice", channel="web"
    )
    assert applied is True and reason is None

    decided = await store.get_approval("ap-null-1")
    assert decided is not None
    assert decided["outcome"] == outcome
    assert decided["actor_kind"] == "human"

    events = [
        event for event in recorder.events if event["_message"] == MSG_APPROVAL_DECISION
    ]
    assert len(events) == 1
    assert events[0]["approval_id"] == "ap-null-1"
    assert events[0]["outcome"] == outcome
    assert events[0]["request_digest"] == stored["request_digest"]
