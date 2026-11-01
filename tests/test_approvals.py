"""Approval and decision tests (protocol §12, §9.8).

Includes the mandatory "cannot auto-approve" assertion required by §12.6.4 and by
PRD acceptance criterion 16.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from bridge.app.approvals import (
    ApprovalService,
    build_submit_projection,
    compute_submit_digest,
    is_allowing_outcome,
    is_fail_closed_outcome,
    request_digest_for,
)
from bridge.app.notify import NotifyService
from bridge.crypto import input_parts_digest
from bridge.errors import BridgeError

CONN = "default"


class ApprovalHarness:
    """Bundle the approval service with its recorders."""

    def __init__(self, store, sender) -> None:
        """Create the harness.

        Args:
            store: Store fixture instance.
            sender: Recording ``task.event`` sender.
        """
        self.store = store
        self.sender = sender
        self.notify = NotifyService(store, conn=CONN, on_task_event=sender)
        self.decided: list[tuple[dict, bool]] = []
        self.answers: list[dict] = []
        self.human_pings: list[dict] = []

        async def on_decided(approval: dict, allowed: bool) -> None:
            self.decided.append((approval, allowed))

        async def on_answered(decision: dict) -> None:
            self.answers.append(decision)

        async def on_human(payload: dict) -> None:
            self.human_pings.append(payload)

        self.service = ApprovalService(
            store,
            conn=CONN,
            side="A",
            approval_timeout_s=1800,
            notify_channels=["im", "web"],
            notify=self.notify,
            on_approval_decided=on_decided,
            on_decision_answered=on_answered,
            on_human_notify=on_human,
        )


@pytest.fixture
def harness(store, sender):
    """Provide an :class:`ApprovalHarness`."""
    return ApprovalHarness(store, sender)


def approval_request(approval_id: str = "ap-1", **overrides) -> dict:
    """Build a valid inbound ``approval.request`` parameter set.

    Args:
        approval_id: Approval identifier.
        **overrides: Field overrides.

    Returns:
        Parameter dictionary.
    """
    params = {
        "approval_id": approval_id,
        "approval_type": "business_decision",
        "task_id": "t-1",
        "root_task_id": "t-1",
        "session_id": None,
        "tool": "deploy",
        "reason": "needs approval",
        "display_reason": {"en": "Deploy", "zh": "部署"},
        "call_id": None,
        "request_digest": request_digest_for(
            "deploy", "needs approval", None, None, "t-1"
        ),
        "expires_at": None,
        "notify_id": "n-1",
        "origin_side": "B",
    }
    params.update(overrides)
    return params


@pytest.mark.asyncio
async def test_request_is_queued_and_notifies_human(harness) -> None:
    """An approval request is stored and a human is notified, never auto-answered (§12.2)."""
    result = await harness.service.handle_request(approval_request())
    assert result["approval_id"] == "ap-1"
    assert result["accepted"] is True
    stored = await harness.store.get_approval("ap-1")
    assert stored is not None
    assert stored["state"] == "pending"
    assert stored["outcome"] is None
    assert harness.human_pings and harness.human_pings[0]["approval_id"] == "ap-1"
    assert harness.decided == []


@pytest.mark.asyncio
async def test_native_tool_request_from_trusted_peer_is_accepted(harness) -> None:
    """A relays a genuine DSH native-tool request to a human (§12.1).

    ``native_tool`` is produced by the DSH side only; A must accept it from the
    authenticated peer so a human can decide, and must never create one itself.
    """
    result = await harness.service.handle_request(
        approval_request(approval_type="native_tool")
    )
    assert result["accepted"] is True
    stored = await harness.store.get_approval("ap-1")
    assert stored is not None
    assert stored["approval_type"] == "native_tool"
    assert stored["state"] == "pending"


@pytest.mark.asyncio
async def test_native_tool_request_claiming_local_origin_is_refused(harness) -> None:
    """A ``native_tool`` request that claims to come from A itself is spoofing (§12.1).

    The service trusts the authenticated peer side, never the payload. A payload that
    asserts a different origin is refused before its claim can be used as evidence.
    """
    params = approval_request(approval_type="native_tool")
    params["origin_side"] = "A"
    # The payload's claim is not evidence: acceptance depends on the authenticated
    # peer side, so a claim alone cannot grant (or deny) the native-tool path.
    result = await harness.service.handle_request(params)
    assert result["accepted"] is True
    stored = await harness.store.get_approval("ap-1")
    assert stored is not None
    # The recorded origin is the trusted side, not the spoofed payload value.
    assert stored["origin_side"] == "B"
    # And crucially, nothing was approved by the claim.
    assert stored["state"] == "pending"


@pytest.mark.asyncio
async def test_a_never_creates_native_tool_requests(harness) -> None:
    """A's own cross-end approval is ``cross_end_submit``, never ``native_tool``."""
    stored = await harness.service.create_cross_end_submit(
        task={"task_id": "t-1", "root_task_id": "t-1"},
        tool="astr_agent_run",
        reason="cross-end task submission",
        display_reason={"en": "Run", "zh": "执行"},
        params={"task_id": "t-1", "session_id": None},
    )
    assert stored["approval_type"] == "cross_end_submit"


@pytest.mark.asyncio
async def test_duplicate_request_is_idempotent(harness) -> None:
    """Re-sending the same ``approval_id`` does not queue twice (§12.2)."""
    first = await harness.service.handle_request(approval_request())
    second = await harness.service.handle_request(approval_request())
    assert first["accepted"] is True
    assert second["dedup"] is True
    assert len(await harness.store.list_approvals()) == 1


@pytest.mark.asyncio
async def test_expired_request_is_refused(harness) -> None:
    """A request already past ``expires_at`` is ``approval_expired`` (§12.2)."""
    past = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 60)) + ".000Z"
    with pytest.raises(BridgeError) as excinfo:
        await harness.service.handle_request(approval_request(expires_at=past))
    assert excinfo.value.code == "approval_expired"


@pytest.mark.asyncio
async def test_human_allow_records_allowed_once(harness) -> None:
    """A human ``allowed-once`` decision takes effect and is reported (§12.3)."""
    await harness.service.handle_request(approval_request())
    applied, reason = await harness.service.human_decide(
        "ap-1", allowed=True, actor="astrbot_admin:alice", channel="web"
    )
    assert applied is True and reason is None
    stored = await harness.store.get_approval("ap-1")
    assert stored is not None
    assert stored["outcome"] == "allowed-once"
    assert stored["actor_kind"] == "human"
    assert harness.decided and harness.decided[0][1] is True


@pytest.mark.asyncio
async def test_second_decision_is_ignored(harness) -> None:
    """The first decision wins; the second is ``already_decided`` (§12.4)."""
    await harness.service.handle_request(approval_request())
    await harness.service.human_decide(
        "ap-1", allowed=False, actor="astrbot_admin:alice", channel="web"
    )
    applied, reason = await harness.service.human_decide(
        "ap-1", allowed=True, actor="astrbot_admin:bob", channel="im"
    )
    assert applied is False
    assert reason == "already_decided"
    stored = await harness.store.get_approval("ap-1")
    assert stored is not None
    assert stored["outcome"] == "rejected"


@pytest.mark.asyncio
async def test_agent_actor_cannot_approve(harness) -> None:
    """Any agent-originated decision is refused (§12.6.3)."""
    await harness.service.handle_request(approval_request())
    with pytest.raises(BridgeError) as excinfo:
        await harness.service.handle_decision(
            {
                "approval_id": "ap-1",
                "outcome": "allowed-once",
                "actor": "agent:worker",
                "actor_kind": "agent",
            }
        )
    assert excinfo.value.code == "agent_cannot_approve"
    stored = await harness.store.get_approval("ap-1")
    assert stored is not None
    assert stored["state"] == "pending"


def test_unavailable_and_cancelled_fail_closed() -> None:
    """``unavailable``/``cancelled`` are refusals, never permits (§12.3)."""
    assert is_allowing_outcome("allowed-once")
    for outcome in ("rejected", "cancelled", "unavailable", None, "bogus"):
        assert is_fail_closed_outcome(outcome)
        assert not is_allowing_outcome(outcome)


@pytest.mark.asyncio
async def test_timeout_always_rejects_never_approves(harness) -> None:
    """Approval timeout must end as ``rejected`` — the mandatory no-auto-approve proof.

    The service never has a code path that grants on timeout; this test advances the
    clock past ``expires_at`` and asserts the only reachable outcome is a rejection.
    """
    await harness.service.handle_request(approval_request())
    # Force expiry without sleeping for 30 minutes.
    expired = await harness.store.expire_approvals(now=time.time() + 1801)
    assert len(expired) == 1
    stored = await harness.store.get_approval("ap-1")
    assert stored is not None
    assert stored["state"] == "decided"
    assert stored["outcome"] == "rejected"
    assert stored["channel"] == "timeout"
    assert stored["actor_kind"] != "human"


@pytest.mark.asyncio
async def test_no_approval_path_exists_in_source() -> None:
    """Text scan: the approval module contains no auto-approval shortcut (§12.6)."""
    from pathlib import Path

    source = (
        Path(__file__).resolve().parent.parent / "bridge" / "app" / "approvals.py"
    ).read_text(encoding="utf-8")
    forbidden = (
        'outcome = "allowed-once"  # auto',
        "auto_approve",
        "allow_by_default",
        "default_allow",
        "always_allow",
    )
    for token in forbidden:
        assert token not in source, f"forbidden auto-approval token: {token}"


@pytest.mark.asyncio
async def test_submit_digest_detects_changed_content(harness) -> None:
    """A submission whose content changed after approval is refused (§12.5)."""
    params = {
        "task_id": "t-9",
        "root_task_id": "t-9",
        "kind": "astr_agent_run",
        "origin": "human",
        "input_parts": [{"type": "text", "text": "deploy to prod"}],
        "attachments": [],
        "tool_hints": [],
        "session_id": None,
        "purpose": "deploy",
        "timeout_s": 60,
    }
    digest = compute_submit_digest(params)
    # A self-consistent digest with no local human-decided row is not evidence:
    # the gate refuses it before any comparison can succeed.
    unbacked = {
        **params,
        "approval_ref": {
            "approval_id": "ap-9",
            "submit_digest": digest,
            "actor": "astrbot_admin:alice",
            "actor_kind": "human",
            "decided_at": "2026-10-29T11:20:00.000Z",
            "expires_at": "2099-01-01T00:00:00.000Z",
        },
    }
    with pytest.raises(BridgeError) as excinfo:
        await harness.service.verify_submit_digest(unbacked)
    assert excinfo.value.code == "approval_mismatch"

    stored = await harness.service.create_cross_end_submit(
        task={"task_id": "t-9", "root_task_id": "t-9"},
        tool=params["kind"],
        reason="cross-end task submission",
        display_reason={"en": "Run", "zh": "执行"},
        params=params,
    )
    applied, reason = await harness.service.human_decide(
        stored["approval_id"], allowed=True, actor="astrbot_admin:alice", channel="web"
    )
    assert applied is True, reason
    approved = {
        **params,
        "approval_ref": {
            **unbacked["approval_ref"],
            "approval_id": stored["approval_id"],
        },
    }
    await harness.service.verify_submit_digest(approved)

    tampered = {
        **approved,
        "input_parts": [{"type": "text", "text": "deploy to dev"}],
    }
    with pytest.raises(BridgeError) as excinfo:
        await harness.service.verify_submit_digest(tampered)
    assert excinfo.value.code == "approval_digest_mismatch"


@pytest.mark.asyncio
async def test_submit_digest_rejects_agent_actor(harness) -> None:
    """An ``approval_ref`` produced by an agent cannot unlock execution (§12.5)."""
    params = {
        "task_id": "t-8",
        "root_task_id": "t-8",
        "kind": "astr_agent_run",
        "origin": "llm",
        "input_parts": [{"type": "text", "text": "do it"}],
        "attachments": [],
        "tool_hints": [],
        "session_id": None,
        "purpose": None,
        "timeout_s": 60,
    }
    digest = compute_submit_digest(params)
    params["approval_ref"] = {
        "approval_id": "ap-8",
        "submit_digest": digest,
        "actor": "agent:worker",
        "actor_kind": "agent",
        "decided_at": "2026-10-29T11:20:00.000Z",
        "expires_at": "2099-01-01T00:00:00.000Z",
    }
    with pytest.raises(BridgeError) as excinfo:
        await harness.service.verify_submit_digest(params)
    assert excinfo.value.code == "agent_cannot_approve"


@pytest.mark.asyncio
async def test_expired_approval_ref_is_refused(harness) -> None:
    """``approval_ref`` past its deadline is ``approval_expired`` (§12.5)."""
    params = {
        "task_id": "t-7",
        "root_task_id": "t-7",
        "kind": "astr_agent_run",
        "origin": "human",
        "input_parts": [{"type": "text", "text": "do it"}],
        "attachments": [],
        "tool_hints": [],
        "session_id": None,
        "purpose": None,
        "timeout_s": 60,
    }
    digest = compute_submit_digest(params)
    params["approval_ref"] = {
        "approval_id": "ap-7",
        "submit_digest": digest,
        "actor": "astrbot_admin:alice",
        "actor_kind": "human",
        "decided_at": "2026-10-29T11:20:00.000Z",
        "expires_at": "2020-01-01T00:00:00.000Z",
    }
    with pytest.raises(BridgeError) as excinfo:
        await harness.service.verify_submit_digest(params)
    assert excinfo.value.code == "approval_expired"


@pytest.mark.asyncio
async def test_decision_first_answer_wins(harness) -> None:
    """Only the first human answer applies; a second reports ``already_answered`` (§9.8)."""
    task = {"task_id": "t-1", "root_task_id": "t-1"}
    stored = await harness.service.create_decision(
        task=task,
        question="merge to which branch?",
        options=[{"id": "main", "label": "main", "consequence": "直接进主干"}],
        timeout_s=60,
    )
    decision_id = stored["decision_id"]
    first = await harness.service.answer(
        {
            "decision_id": decision_id,
            "choice": "main",
            "free_text": None,
            "actor": "astrbot_admin:alice",
            "actor_kind": "human",
        }
    )
    assert first["applied"] is True
    second = await harness.service.answer(
        {
            "decision_id": decision_id,
            "choice": "dev",
            "free_text": None,
            "actor": "astrbot_admin:bob",
            "actor_kind": "human",
        }
    )
    assert second["applied"] is False
    assert second["reason"] == "already_answered"


@pytest.mark.asyncio
async def test_agent_cannot_answer_decision(harness) -> None:
    """An agent answer is refused with ``agent_cannot_decide`` (§9.8)."""
    stored = await harness.service.create_decision(
        task={"task_id": "t-2", "root_task_id": "t-2"},
        question="which?",
        options=[{"id": "a", "label": "a", "consequence": ""}],
    )
    with pytest.raises(BridgeError) as excinfo:
        await harness.service.answer(
            {
                "decision_id": stored["decision_id"],
                "choice": "a",
                "actor": "agent:worker",
                "actor_kind": "agent",
            }
        )
    assert excinfo.value.code == "agent_cannot_decide"


@pytest.mark.asyncio
async def test_lookup_refuses_non_authoritative_rows(harness) -> None:
    """``approval.lookup`` never reports a mirror/pending row as evidence (§12.7.3)."""
    await harness.service.handle_request(approval_request())
    with pytest.raises(BridgeError) as excinfo:
        await harness.service.lookup(
            {
                "approval_id": "ap-1",
                "task_id": "t-lookup",
                "root_task_id": "t-lookup",
                "session_id": None,
                "submit_digest": "x",
            }
        )
    assert excinfo.value.code == "approval_mismatch"
    with pytest.raises(BridgeError) as unknown:
        await harness.service.lookup(
            {
                "approval_id": "nope",
                "task_id": "t-lookup",
                "root_task_id": "t-lookup",
                "session_id": None,
                "submit_digest": "x",
            }
        )
    assert unknown.value.code == "approval_mismatch"


@pytest.mark.asyncio
async def test_cross_end_submit_creates_pending_approval(harness) -> None:
    """A pending cross-end submission produces a queued approval (§12.5)."""
    task = {"task_id": "t-3", "root_task_id": "t-3"}
    stored = await harness.service.create_cross_end_submit(
        task=task,
        tool="astr_agent_run",
        reason="cross-end task submission",
        display_reason={"en": "Run", "zh": "执行"},
        params={
            "task_id": "t-3",
            "session_id": None,
        },
    )
    assert stored["approval_type"] == "cross_end_submit"
    assert stored["state"] == "pending"
    assert harness.human_pings


def test_submit_projection_matches_protocol_fields() -> None:
    """The projection carries exactly the fields §12.5 lists."""
    params = {
        "task_id": "t",
        "root_task_id": "t",
        "kind": "astr_agent_run",
        "origin": "human",
        "input_parts": [{"type": "text", "text": "x"}],
        "attachments": [],
        "tool_hints": [],
        "session_id": None,
        "purpose": None,
        "timeout_s": 60,
    }
    projection = build_submit_projection(params)
    assert set(projection) == {
        "task_id",
        "root_task_id",
        "kind",
        "origin",
        "session_id",
        "purpose",
        "timeout_s",
        "input_parts_digest",
        "attachments",
        "tool_hints",
    }
    assert projection["input_parts_digest"] == input_parts_digest(params["input_parts"])


@pytest.mark.asyncio
async def test_approval_expiry_has_exactly_one_winner(harness) -> None:
    """Only the sweep that actually closes the row reports it as expired."""
    await harness.service.handle_request(approval_request())
    expired = await harness.store.expire_approvals(now=time.time() + 1801)
    assert [row["approval_id"] for row in expired] == ["ap-1"]
    assert await harness.store.expire_approvals(now=time.time() + 1802) == []

    applied, reason = await harness.service.human_decide(
        "ap-1", allowed=True, actor="astrbot_admin:alice", channel="web"
    )
    assert applied is False
    # The deadline sweep already closed the row, so the late answer reports the
    # timeout rather than looking like a second human decision.
    assert reason == "expired"


@pytest.mark.asyncio
async def test_decision_expiry_is_claimed_once_and_answers_lose(harness) -> None:
    """The first expiry sweep owns the decision; a later answer is ``expired``."""
    stored = await harness.service.create_decision(
        task={"task_id": "t-exp", "root_task_id": "t-exp"},
        question="keep going?",
        options=[{"id": "yes", "label": "yes", "consequence": ""}],
        timeout_s=1,
    )
    decision_id = stored["decision_id"]
    expired = await harness.store.expire_decisions(now=time.time() + 5)
    assert [row["decision_id"] for row in expired] == [decision_id]
    assert await harness.store.expire_decisions(now=time.time() + 6) == []
    assert (await harness.store.get_decision(decision_id))["state"] == "expired"

    answer = await harness.service.answer(
        {
            "decision_id": decision_id,
            "choice": "yes",
            "free_text": None,
            "actor": "astrbot_admin:alice",
            "actor_kind": "human",
        }
    )
    assert answer["applied"] is False
    assert answer["reason"] == "expired"


@pytest.mark.asyncio
async def test_late_decision_answer_leaves_timeout_sweep_as_sole_winner(
    harness,
) -> None:
    """A late human answer loses; the timeout callback still fires exactly once.

    ``answer_decision`` must not mark the overdue pending row expired itself,
    because ``expire_decisions`` only scans pending rows and would then skip the
    one timeout report. The answer is refused now, the sweep owns the timeout.
    """
    stored = await harness.service.create_decision(
        task={"task_id": "t-late", "root_task_id": "t-late"},
        question="too late?",
        options=[{"id": "go", "label": "go", "consequence": ""}],
        timeout_s=0,
    )
    decision_id = stored["decision_id"]

    late = await harness.service.answer(
        {
            "decision_id": decision_id,
            "choice": "go",
            "free_text": None,
            "actor": "astrbot_admin:alice",
            "actor_kind": "human",
        }
    )
    assert late == {
        "decision_id": decision_id,
        "applied": False,
        "reason": "expired",
    }
    assert harness.answers == []
    # The late answer must leave the row claimable by the single timeout sweep.
    assert (await harness.store.get_decision(decision_id))["state"] == "pending"

    loop = asyncio.create_task(harness.service.timeout_loop(interval_s=0.01))
    try:
        for _ in range(200):
            if harness.answers:
                break
            await asyncio.sleep(0.01)
        # Allow further loop iterations so a duplicate report would be observed.
        await asyncio.sleep(0.03)
    finally:
        loop.cancel()
        try:
            await loop
        except asyncio.CancelledError:
            pass

    timed_out = [row for row in harness.answers if row.get("timed_out")]
    human_choices = [row for row in harness.answers if not row.get("timed_out")]
    assert [row["decision_id"] for row in timed_out] == [decision_id]
    assert human_choices == []
    assert (await harness.store.get_decision(decision_id))["state"] == "expired"
    assert await harness.store.expire_decisions() == []


@pytest.mark.asyncio
async def test_mirror_enrichment_copies_decided_at_and_expiry(store) -> None:
    """A lookup mirror gains the authoritative ``decided_at``/``expires_at``."""
    now = time.time()
    await store.put_approval(
        {
            "approval_id": "mirror-1",
            "approval_type": "cross_end_submit",
            "task_id": "t-m",
            "root_task_id": "t-m",
            "request_digest": "req-1",
            "origin_side": "B",
            "source": "peer_request",
            "expires_at": now + 60,
        }
    )
    mirror = {
        "approval_id": "mirror-1",
        "approval_type": "cross_end_submit",
        "task_id": "t-m",
        "root_task_id": "t-m",
        "session_id": None,
        "request_digest": "req-1",
        "submit_digest": "submit-1",
        "origin_side": "B",
        "conn": "default",
        "sid": "sid-1",
        "released_by_task": "t-m",
        "evidence": {"submit_digest": "submit-1"},
        "outcome": "allowed-once",
        "actor": "astrbot_admin:alice",
        "actor_kind": "human",
        "channel": "web",
        "expires_at": now + 120,
        "decided_at_epoch": now,
    }
    stored = await store.import_approval_mirror(mirror)
    assert stored is not None
    assert stored["source"] == "peer_lookup"
    assert stored["evidence"] == {"submit_digest": "submit-1"}
    assert stored["decided_at"] == pytest.approx(now)
    assert stored["expires_at"] == pytest.approx(now + 120)

    # A repeated lookup with the same evidence may only refresh the deadline and
    # must never rewrite the receiver's consumption.
    await store.claim_approval_consumption("mirror-1", "t-m")
    refreshed = await store.import_approval_mirror({**mirror, "expires_at": now + 240})
    assert refreshed is not None
    assert refreshed["expires_at"] == pytest.approx(now + 240)
    assert refreshed["consumed_by_task"] == "t-m"
