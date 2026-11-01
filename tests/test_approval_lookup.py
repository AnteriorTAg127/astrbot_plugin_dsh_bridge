"""``approval.lookup`` evidence contract (§12.7/§12.8), both roles.

The authority side is a real :class:`ApprovalService` with its own store; the
receiving side is a second instance whose ``peer_call`` is wired to the
authority's ``lookup`` exactly as the composition root wires a live session.
Nothing is hand-written into the approvals table: the tests drive the same
``create_outbound_submit_gate`` / ``human_decide`` / ``claim_approval_release``
path the production tool uses.
"""

from __future__ import annotations

import time

import pytest
from bridge.app.approvals import ApprovalService, compute_submit_digest
from bridge.app.notify import NotifyService
from bridge.constants import ACTOR_HUMAN
from bridge.errors import BridgeError
from bridge.store import Store

CONN = "default"
SID = "22222222-2222-4222-8222-222222222222"
TASK = "44444444-4444-4444-8444-444444444444"


def submit_params(task_id: str = TASK, **over) -> dict:
    """Build a valid outbound submission parameter set.

    Args:
        task_id: Task identifier.
        **over: Overrides.

    Returns:
        Complete parameter dictionary.
    """
    params = {
        "task_id": task_id,
        "root_task_id": task_id,
        "kind": "dsh_agent_run",
        "origin": "llm",
        "input_parts": [{"type": "text", "text": "请检查这个补丁"}],
        "attachments": [],
        "tool_hints": [],
        "session_id": None,
        "purpose": "review",
        "timeout_s": 300,
        "meta": {},
        "approval_ref": None,
    }
    params.update(over)
    return params


def ref_for(approval: dict, params: dict) -> dict:
    """Build the wire reference from an authoritative row.

    Args:
        approval: Authority approval row.
        params: Submission parameters.

    Returns:
        ``approval_ref`` dictionary.
    """
    return {
        "approval_id": approval["approval_id"],
        "submit_digest": compute_submit_digest(params),
        "actor": approval["actor"],
        "actor_kind": ACTOR_HUMAN,
        "decided_at": "2026-10-30T10:00:00.000Z",
        "expires_at": "2099-01-01T00:00:00.000Z",
    }


class Authority:
    """One authoritative endpoint holding a released outbound gate."""

    def __init__(self) -> None:
        """Prepare fields populated by :func:`build_authority`."""
        self.store: Store
        self.service: ApprovalService
        self.approval: dict | None = None

    async def open_gate(
        self, params: dict, *, decision: bool = True, release: bool = True
    ) -> dict:
        """Create, decide and release one outbound gate.

        Args:
            params: Submission parameters the gate approves.
            decision: Whether the human allows it.
            release: Whether the gate is released to this task.

        Returns:
            The stored approval row.
        """
        approval = await self.service.create_outbound_submit_gate(
            task={"task_id": params["task_id"], "root_task_id": params["root_task_id"]},
            params=params,
            tool=params["kind"],
            reason="cross-end task submission",
            display_reason={"en": "Run", "zh": "执行"},
        )
        applied, reason = await self.service.human_decide(
            approval["approval_id"],
            allowed=decision,
            actor="astrbot_admin:alice",
            channel="web",
        )
        assert applied is True, reason
        if release:
            claimed = await self.store.claim_approval_release(
                approval["approval_id"], params["task_id"]
            )
            assert claimed is True
        row = await self.store.get_approval(approval["approval_id"])
        assert row is not None
        self.approval = row
        return row


async def build_authority(tmp_path, name: str = "authority.db") -> Authority:
    """Build a real authority service bound to the live session.

    Args:
        tmp_path: pytest temporary directory.
        name: Database filename.

    Returns:
        The authority bundle.
    """
    authority = Authority()
    store = Store()
    await store.init(tmp_path / name)
    authority.store = store
    notify = NotifyService(store, conn=CONN, on_task_event=_noop)
    service = ApprovalService(
        store,
        conn=CONN,
        side="A",
        approval_timeout_s=1800,
        notify_channels=["web"],
        notify=notify,
    )
    service.bind_session(CONN, SID)
    service.bind_peer_side("B")
    authority.service = service
    return authority


class Receiver:
    """One receiving endpoint whose lookup goes to a real authority."""

    def __init__(self) -> None:
        """Prepare fields populated by :func:`build_receiver`."""
        self.store: Store
        self.service: ApprovalService
        self.calls = 0
        self.identity_at_call: tuple[str, str] | None = None
        self.before_return = None

    def wire(self, authority: Authority) -> None:
        """Wire ``peer_call`` to the authority's real ``lookup``.

        Args:
            authority: Authority bundle.
        """

        async def peer_call(message: str, params: dict, timeout_s: float) -> dict:
            assert message == "approval.lookup"
            self.calls += 1
            self.identity_at_call = self.service.session_identity()
            if self.before_return is not None:
                self.before_return()
            return await authority.service.lookup(params)

        self.service.set_peer_call(peer_call)


async def build_receiver(tmp_path) -> Receiver:
    """Build a real receiver service bound to the same session.

    Args:
        tmp_path: pytest temporary directory.

    Returns:
        The receiver bundle.
    """
    receiver = Receiver()
    store = Store()
    await store.init(tmp_path / "receiver.db")
    receiver.store = store
    notify = NotifyService(store, conn=CONN, on_task_event=_noop)
    service = ApprovalService(
        store,
        conn=CONN,
        side="B",
        approval_timeout_s=1800,
        notify_channels=["web"],
        notify=notify,
    )
    service.bind_session(CONN, SID)
    service.bind_peer_side("A")
    service.bind_peer_caps({"side": "A", "features": ["approval.lookup"]})
    receiver.service = service
    return receiver


async def _noop(params: dict) -> None:
    """Ignore one notification.

    Args:
        params: Notification payload.
    """


async def approved_pair(tmp_path):
    """Build an authority with a legal released gate and a wired receiver.

    Args:
        tmp_path: pytest temporary directory.

    Returns:
        ``(authority, receiver, params)``.
    """
    authority = await build_authority(tmp_path)
    receiver = await build_receiver(tmp_path)
    receiver.wire(authority)
    params = submit_params()
    await authority.open_gate(params)
    return authority, receiver, params


@pytest.mark.asyncio
async def test_lookup_round_trip_imports_trusted_mirror_and_consumes_once(
    tmp_path,
) -> None:
    """A legal ref is proven from the authority, mirrored, and consumed once."""
    authority, receiver, params = await approved_pair(tmp_path)
    try:
        params["approval_ref"] = ref_for(authority.approval, params)
        receiver.service.check_submit_ref(params)
        evidence = await receiver.service.resolve_submit_evidence(params)
        assert evidence["source"] == "peer_lookup"
        assert evidence["approval_id"] == authority.approval["approval_id"]
        assert evidence["submit_digest"] == compute_submit_digest(params)
        assert evidence["conn"] == CONN and evidence["sid"] == SID
        assert evidence["released_by_task"] == params["task_id"]
        assert evidence["consumed_by_task"] is None

        claimed = await receiver.store.claim_approval_consumption(
            evidence["approval_id"], params["task_id"]
        )
        assert claimed is True
        again = await receiver.store.claim_approval_consumption(
            evidence["approval_id"], params["task_id"]
        )
        assert again is False

        # A replay after the consume is refused by the receiver's own one-shot
        # consumption, even though the authority row still matches.
        with pytest.raises(BridgeError) as excinfo:
            row = await receiver.store.get_approval(evidence["approval_id"])
            assert row["consumed_by_task"] == params["task_id"]
            claimed = await receiver.store.claim_approval_consumption(
                evidence["approval_id"], params["task_id"]
            )
            if not claimed:
                raise BridgeError("approval_already_decided")
        assert excinfo.value.code == "approval_already_decided"
    finally:
        await receiver.store.close()
        await authority.store.close()


@pytest.mark.asyncio
async def test_receiver_without_lookup_support_fails_closed(tmp_path) -> None:
    """No live lookup hook is a refusal, never "treat the ref as absent"."""
    authority = await build_authority(tmp_path)
    receiver = await build_receiver(tmp_path)
    try:
        params = submit_params()
        await authority.open_gate(params)
        params["approval_ref"] = ref_for(authority.approval, params)
        receiver.service.set_peer_call(None)
        with pytest.raises(BridgeError) as excinfo:
            await receiver.service.resolve_submit_evidence(params)
        assert excinfo.value.code == "approval_lookup_failed"
    finally:
        await receiver.store.close()
        await authority.store.close()


@pytest.mark.asyncio
async def test_old_authority_row_without_session_evidence_is_refused(tmp_path) -> None:
    """A pre-amendment row (no conn/sid) can never become evidence (§12.8)."""
    authority, receiver, params = await approved_pair(tmp_path)
    try:
        await authority.store._conn().execute(
            "UPDATE approvals SET conn = NULL, sid = NULL WHERE approval_id = ?",
            (authority.approval["approval_id"],),
        )
        await authority.store._conn().commit()
        params["approval_ref"] = ref_for(authority.approval, params)
        with pytest.raises(BridgeError) as excinfo:
            await receiver.service.resolve_submit_evidence(params)
        assert excinfo.value.code == "approval_evidence_missing"
    finally:
        await receiver.store.close()
        await authority.store.close()


@pytest.mark.asyncio
async def test_authority_row_from_an_older_sid_cannot_answer(tmp_path) -> None:
    """A new authenticated sid makes the old decision unanswerable."""
    authority, receiver, params = await approved_pair(tmp_path)
    try:
        authority.service.bind_session(CONN, "33333333-3333-4333-8333-333333333333")
        params["approval_ref"] = ref_for(authority.approval, params)
        with pytest.raises(BridgeError) as excinfo:
            await receiver.service.resolve_submit_evidence(params)
        assert excinfo.value.code == "approval_evidence_missing"
    finally:
        await receiver.store.close()
        await authority.store.close()


@pytest.mark.asyncio
async def test_receiver_session_race_is_refused(tmp_path) -> None:
    """If the receiver's session changes during the call, the answer is discarded."""
    authority, receiver, params = await approved_pair(tmp_path)
    try:
        params["approval_ref"] = ref_for(authority.approval, params)

        def race() -> None:
            receiver.service.bind_session(CONN, "44444444-4444-4444-8444-444444444444")

        receiver.before_return = race
        with pytest.raises(BridgeError) as excinfo:
            await receiver.service.resolve_submit_evidence(params)
        assert excinfo.value.code == "approval_lookup_failed"
        assert (
            await receiver.store.get_approval(authority.approval["approval_id"]) is None
        )
    finally:
        await receiver.store.close()
        await authority.store.close()


@pytest.mark.asyncio
async def test_wrong_content_digest_is_refused(tmp_path) -> None:
    """The authoritative digest must equal the recomputed content digest."""
    authority, receiver, params = await approved_pair(tmp_path)
    try:
        tampered = dict(params, input_parts=[{"type": "text", "text": "另一件事"}])
        tampered["approval_ref"] = ref_for(authority.approval, tampered)
        # Self-consistent with the tampered content, but the authority approved
        # the original content: the lookup binding mismatch refuses it.
        receiver.service.check_submit_ref(tampered)
        with pytest.raises(BridgeError) as excinfo:
            await receiver.service.resolve_submit_evidence(tampered)
        # §12.7.5: the authority's refusal is an error answer, not its code.
        assert excinfo.value.code == "approval_lookup_failed"
    finally:
        await receiver.store.close()
        await authority.store.close()


@pytest.mark.asyncio
async def test_release_for_another_task_is_refused(tmp_path) -> None:
    """A gate released to T1 cannot authorize T2."""
    authority, receiver, params = await approved_pair(tmp_path)
    try:
        other = submit_params(task_id="99999999-9999-4999-8999-999999999999")
        other["approval_ref"] = ref_for(authority.approval, other)
        receiver.service.check_submit_ref(other)
        with pytest.raises(BridgeError) as excinfo:
            await receiver.service.resolve_submit_evidence(other)
        assert excinfo.value.code == "approval_lookup_failed"
    finally:
        await receiver.store.close()
        await authority.store.close()


@pytest.mark.asyncio
async def test_mirror_survives_store_reopen_and_stays_spent(tmp_path) -> None:
    """The imported mirror and its consumption are durable across a restart."""
    authority, receiver, params = await approved_pair(tmp_path)
    params["approval_ref"] = ref_for(authority.approval, params)
    evidence = await receiver.service.resolve_submit_evidence(params)
    assert await receiver.store.claim_approval_consumption(
        evidence["approval_id"], params["task_id"]
    )
    await receiver.store.close()
    try:
        reopened = Store()
        await reopened.init(tmp_path / "receiver.db")
        row = await reopened.get_approval(evidence["approval_id"])
        assert row is not None
        assert row["source"] == "peer_lookup"
        assert row["consumed_by_task"] == params["task_id"]
        assert row["evidence"]["submit_digest"] == compute_submit_digest(params)
        assert (
            await reopened.claim_approval_consumption(
                evidence["approval_id"], params["task_id"]
            )
            is False
        )
        await reopened.close()
    finally:
        await authority.store.close()


@pytest.mark.asyncio
async def test_receiver_without_negotiated_lookup_caps_fails_closed(tmp_path) -> None:
    """An unknown capability is a refusal, never an optimistic lookup call."""
    authority = await build_authority(tmp_path)
    receiver = await build_receiver(tmp_path)
    try:
        receiver.service.bind_peer_caps({"side": "A", "features": []})
        params = submit_params()
        await authority.open_gate(params)
        params["approval_ref"] = ref_for(authority.approval, params)
        with pytest.raises(BridgeError) as excinfo:
            await receiver.service.resolve_submit_evidence(params)
        assert excinfo.value.code == "approval_lookup_failed"
        assert receiver.calls == 0
    finally:
        await receiver.store.close()
        await authority.store.close()


@pytest.mark.asyncio
async def test_peer_side_change_during_lookup_discards_answer(tmp_path) -> None:
    """The captured authenticated side must still match when the answer returns."""
    authority, receiver, params = await approved_pair(tmp_path)
    try:
        params["approval_ref"] = ref_for(authority.approval, params)

        def race() -> None:
            receiver.service.bind_peer_side("INVALID")

        receiver.before_return = race
        with pytest.raises(BridgeError) as excinfo:
            await receiver.service.resolve_submit_evidence(params)
        assert excinfo.value.code == "approval_lookup_failed"
        assert (
            await receiver.store.get_approval(authority.approval["approval_id"]) is None
        )
    finally:
        await receiver.store.close()
        await authority.store.close()


@pytest.mark.asyncio
async def test_mirror_enrichment_keeps_consumption_and_refreshes_expiry(
    tmp_path,
) -> None:
    """A controlled re-import must not erase the receiver's one-shot consumption."""
    authority, receiver, params = await approved_pair(tmp_path)
    try:
        params["approval_ref"] = ref_for(authority.approval, params)
        evidence = await receiver.service.resolve_submit_evidence(params)
        assert await receiver.store.claim_approval_consumption(
            evidence["approval_id"], params["task_id"]
        )
        row = await receiver.store.get_approval(evidence["approval_id"])
        assert row is not None
        mirror = {
            "approval_id": row["approval_id"],
            "approval_type": row["approval_type"],
            "task_id": row["task_id"],
            "root_task_id": row["root_task_id"],
            "session_id": row["session_id"],
            "request_digest": row["request_digest"],
            "submit_digest": row["submit_digest"],
            "origin_side": row["origin_side"],
            "released_by_task": row["released_by_task"],
            "evidence": row["evidence"],
            "outcome": row["outcome"],
            "actor": row["actor"],
            "actor_kind": row["actor_kind"],
            "channel": row["channel"],
            "decided_reason": None,
            "decided_at_epoch": row["decided_at"],
            "expires_at": row["expires_at"] + 120,
        }
        refreshed = await receiver.store.import_approval_mirror(mirror)
        assert refreshed is not None
        assert refreshed["consumed_by_task"] == params["task_id"]
        assert refreshed["expires_at"] == pytest.approx(row["expires_at"] + 120)
        # A conflicting old row and an incomplete mirror are refused.
        conflict = dict(mirror, submit_digest="different")
        assert await receiver.store.import_approval_mirror(conflict) is None
        incomplete = dict(mirror, decided_at_epoch=float("nan"))
        assert await receiver.store.import_approval_mirror(incomplete) is None
    finally:
        await receiver.store.close()
        await authority.store.close()


@pytest.mark.asyncio
async def test_unknown_peer_caps_fail_closed_without_a_lookup_call(tmp_path) -> None:
    """Unbound (unknown) caps are unsupported: no optimistic remote call is made."""
    authority = await build_authority(tmp_path)
    receiver = await build_receiver(tmp_path)
    try:
        receiver.service.bind_peer_caps(None)
        params = submit_params()
        await authority.open_gate(params)
        params["approval_ref"] = ref_for(authority.approval, params)
        with pytest.raises(BridgeError) as excinfo:
            await receiver.service.resolve_submit_evidence(params)
        assert excinfo.value.code == "approval_lookup_failed"
        assert receiver.calls == 0
    finally:
        await receiver.store.close()
        await authority.store.close()


@pytest.mark.asyncio
async def test_returned_evidence_expiry_is_authoritative(tmp_path) -> None:
    """An expired authority row is refused even if the ref claims a future."""
    authority, receiver, params = await approved_pair(tmp_path)
    try:
        await authority.store._conn().execute(
            "UPDATE approvals SET expires_at = ? WHERE approval_id = ?",
            (time.time() - 10, authority.approval["approval_id"]),
        )
        await authority.store._conn().commit()
        params["approval_ref"] = ref_for(authority.approval, params)
        with pytest.raises(BridgeError) as excinfo:
            await receiver.service.resolve_submit_evidence(params)
        # §12.7.5: an authority error answer other than evidence_missing is a
        # failed lookup on the receiver, not a verbatim expiry.
        assert excinfo.value.code == "approval_lookup_failed"
    finally:
        await receiver.store.close()
        await authority.store.close()
