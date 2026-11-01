"""Fixtures and outcome accounting for the cross-transport acceptance suite.

Three outcomes are distinguished and never merged:

* **pass**  — the behaviour was observed over a real loopback socket.
* **fail**  — the behaviour was observed to be wrong (a defect).
* **blocked** — the behaviour could not be exercised because one side has not
  implemented the required piece yet. Reported with ``pytest.xfail`` and a
  reason starting with ``BLOCKED-IMPL``; never a silent skip, never a pass.

The module also reserves every port through ``bind(0)`` and refuses ``3080`` /
``6185`` by construction (see :mod:`harness`).
"""

from __future__ import annotations

import json  # noqa: F401  (used by pytest_sessionfinish payload)
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from tests.integration.cross_transport import harness as H

#: Where the run writes its machine-readable snapshot (git-ignored temp dir).
RESULTS_DIR = Path(__file__).resolve().parent / "_results"


def pytest_configure(config: pytest.Config) -> None:
    """Register the suite's marks without touching the shared ``pytest.ini``.

    Args:
        config: pytest configuration object.
    """
    config.addinivalue_line(
        "markers", "cross_transport: real-socket cross-language transport acceptance"
    )


@dataclass
class Addressing:
    """Port assignment for one A/B pair.

    Attributes:
        listen_port: Port the responder binds.
        reply_port: Inbound port of the connecting side (needed by HTTP carriers).
        a_peer_port: Port A dials.
        a_bind_port: Port A binds.
        b_peer_port: Port B dials.
        b_bind_port: Port B binds.
    """

    listen_port: int
    reply_port: int
    a_peer_port: int
    a_bind_port: int
    b_peer_port: int
    b_bind_port: int


def _await_ready_or_error(
    process: H.PeerProcess, timeout_s: float
) -> tuple[dict[str, Any] | None, str | None, str | None]:
    """Wait for a peer to become ``ready`` or to report ``start_error``.

    Args:
        process: Peer handle.
        timeout_s: Maximum wait in seconds.

    Returns:
        ``(ready_event, error_code, note)``; ``note`` explains a non-event.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for event in process.unsolicited:
            if event.get("event") == "start_error":
                process.unsolicited.remove(event)
                return None, str(event.get("code")), None
        try:
            return process.wait_event("ready", 0.5), None, None
        except H.HarnessError:
            pass
        if process.returncode is not None and not process.unsolicited:
            return None, "<process exited>", process.stdout_tail(600)
    return None, None, f"no ready/start_error within {timeout_s:.0f}s"


def _other_mode(mode: str) -> str:
    """Return the opposite carrier mode (§4.1: one listen, one connect).

    Args:
        mode: ``listen`` or ``connect``.

    Returns:
        The other mode.
    """
    return "connect" if mode == "listen" else "listen"


def assign_ports(a_mode: str) -> Addressing:
    """Reserve two loopback ports and map them onto both peers.

    Args:
        a_mode: ``listen`` when A is the responder, otherwise ``connect``.

    Returns:
        The port assignment.

    Raises:
        ValueError: For an unknown mode.
    """
    if a_mode not in {"listen", "connect"}:
        raise ValueError(f"unknown mode {a_mode}")
    listen_port = H.free_port()
    reply_port = H.free_port()
    if a_mode == "listen":
        return Addressing(
            listen_port, reply_port, reply_port, listen_port, listen_port, reply_port
        )
    return Addressing(
        listen_port, reply_port, listen_port, reply_port, reply_port, listen_port
    )


@dataclass
class Pair:
    """A running A/B peer pair plus the outcome it reached.

    Attributes:
        transport: Carrier name.
        a_mode: ``listen`` or ``connect`` for A.
        credentials: Synthetic credentials shared by both ends.
        addressing: Port assignment.
        a: A-side process.
        b: B-side process.
        ready: ``True`` when both sides reported ``ready``.
        a_ready: A's ``ready`` snapshot (if any).
        b_ready: B's ``ready`` snapshot (if any).
        a_error: ``start_error`` code A reported (if any).
        b_error: ``start_error`` code B reported (if any).
        notes: Free-form diagnostics gathered during startup.
    """

    transport: str
    a_mode: str
    credentials: H.Credentials
    addressing: Addressing
    a: H.PeerProcess
    b: H.PeerProcess
    ready: bool = False
    a_ready: dict[str, Any] | None = None
    b_ready: dict[str, Any] | None = None
    a_error: str | None = None
    b_error: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def b_mode(self) -> str:
        """The peer mode implied by ``a_mode``.

        Returns:
            ``connect`` when A listens, ``listen`` otherwise.
        """
        return "connect" if self.a_mode == "listen" else "listen"

    def require_ready(self, reason: str) -> None:
        """Fail loudly, or mark the test blocked when the handshake did not happen.

        Args:
            reason: Why the caller needs a ready pair.

        Raises:
            AssertionError: When the pair is not ready and the cause is a defect
                rather than a missing implementation.
        """
        if self.ready:
            return
        detail = (
            f"{reason}: A({self.a_mode}) ready={self.a_ready is not None} "
            f"B({self.b_mode}) ready={self.b_ready is not None}; "
            f"A start_error={[self.a_error] if self.a_error else []} "
            f"B start_error={[self.b_error] if self.b_error else []}"
        )
        if self.blocks_on_missing_impl():
            pytest.xfail(f"BLOCKED-IMPL: {detail}")
        raise AssertionError(detail)

    @staticmethod
    def _start_errors(process: H.PeerProcess) -> list[str]:
        """Return the ``start_error`` codes a peer reported.

        Args:
            process: Peer process handle.

        Returns:
            List of error codes.
        """
        return [
            str(event.get("code"))
            for event in process.unsolicited
            if event.get("event") == "start_error"
        ]

    def blocks_on_missing_impl(self) -> bool:
        """Whether the failure is explained by a carrier piece that is absent.

        The HTTP carriers only reach ``ready`` when the responder answers the
        ``POST /frames`` batch that carried ``auth`` with a 200 batch containing
        ``auth_ack`` (protocol §7.3 rule 2), and the initiator consumes that
        batch. Until both halves exist, an HTTP handshake cannot complete across
        implementations; that is "not implemented yet", not "observed wrong".

        Returns:
            ``True`` when the observed failure matches that condition.
        """
        if self.transport == "ws":
            return False
        return self._http_inline_auth_ack_absent()

    def _http_inline_auth_ack_absent(self) -> bool:
        """Check the concrete missing piece from the peers' own evidence.

        The signature is: the initiator timed out waiting for ``auth_ack`` while
        the responder's session never reached ``ready`` and recorded no security
        event -- i.e. no inline frame batch travelled back on the POST that
        carried ``auth`` (§7.3 rule 2). Any *other* failure (rejected handshake,
        bad MAC, wrong ``sid``, ``th_mismatch``) must not be excused.

        Returns:
            ``True`` when the observed failure matches that signature only.
        """
        initiator_error = self.b_error if self.a_mode == "listen" else self.a_error
        responder_error = self.a_error if self.a_mode == "listen" else self.b_error
        if initiator_error != "timeout":
            return False
        if responder_error not in (None, "timeout"):
            return False
        responder = self.a if self.a_mode == "listen" else self.b
        if self._security_events(responder):
            return False
        snapshot = self._snapshot(responder)
        # A responder that reached `ready` without ever answering inline is a
        # different, unexpected shape: report it as a defect, never as blocked.
        return snapshot is not None and snapshot.get("state") != "ready"

    @staticmethod
    def _snapshot(process: H.PeerProcess) -> dict[str, Any] | None:
        """Best-effort snapshot of a peer that may already be exiting.

        Args:
            process: Peer handle.

        Returns:
            The snapshot, or ``None`` when the peer is unavailable.
        """
        try:
            return process.request(3, op="snapshot")
        except H.HarnessError:
            return None

    @staticmethod
    def _security_events(process: H.PeerProcess) -> list[dict[str, Any]]:
        """Security events a peer recorded, when it can still be asked.

        Args:
            process: Peer handle.

        Returns:
            Recorded security events (empty when unavailable).
        """
        snapshot = Pair._snapshot(process)
        if snapshot is None:
            return []
        return list(snapshot.get("security_events") or [])

    def close(self) -> None:
        """Close both peers, always, even if they are already gone."""
        for process in (self.b, self.a):
            process.stop()


@pytest.fixture
def pair_factory(record_property):
    """Provide a factory that spawns a pair and guarantees teardown.

    Args:
        record_property: pytest hook used to tag the report with the carrier.

    Returns:
        A callable ``start(transport, a_mode) -> Pair``.
    """
    created: list[Pair] = []

    def start(transport: str, a_mode: str, *, startup_timeout_s: float = 40.0) -> Pair:
        credentials = H.Credentials.synthetic()
        addressing = assign_ports(a_mode)
        responder_mode = a_mode
        connector = "B" if a_mode == "listen" else "A"

        def spawn_side(side: str) -> H.PeerProcess:
            kwargs = {
                "transport": transport,
                "mode": responder_mode if side == "A" else _other_mode(responder_mode),
                "peer_port": addressing.a_peer_port
                if side == "A"
                else addressing.b_peer_port,
                "bind_port": addressing.a_bind_port
                if side == "A"
                else addressing.b_bind_port,
                "credentials": credentials,
            }
            return H.spawn_a(**kwargs) if side == "A" else H.spawn_b(**kwargs)

        # The responder must be bound before the initiator dials: spawn it first
        # and wait for the listening socket, never for a fixed sleep.
        first = spawn_side("A" if a_mode == "listen" else "B")
        bound = H.wait_port_open(addressing.listen_port, startup_timeout_s)
        second = spawn_side("B" if a_mode == "listen" else "A")
        pair = Pair(
            transport=transport,
            a_mode=a_mode,
            credentials=credentials,
            addressing=addressing,
            a=first if a_mode == "listen" else second,
            b=second if a_mode == "listen" else first,
        )
        created.append(pair)
        record_property("transport", transport)
        record_property("a_mode", a_mode)
        if not bound:
            pair.notes.append(f"responder never bound port {addressing.listen_port}")
            return pair

        for label, process in (("A", pair.a), ("B", pair.b)):
            event, error, note = _await_ready_or_error(process, startup_timeout_s)
            if note:
                pair.notes.append(f"{label}: {note}")
            if label == "A":
                pair.a_ready = event
                pair.a_error = error
            else:
                pair.b_ready = event
                pair.b_error = error
        pair.ready = pair.a_ready is not None and pair.b_ready is not None
        del connector
        return pair

    yield start
    for pair in created:
        pair.close()
    # Assert on the peers this process spawned, never on a global scan: a global
    # scan races with a concurrent run and would blame the wrong test.
    leftovers = H.assert_spawned_all_dead(timeout_s=12.0)
    assert not leftovers, f"harness left its own child processes behind: {leftovers}"
    # Same rule for file descriptors: only sockets opened through
    # ``harness.harness_socket`` are tracked, so a leak in the interpreter, in an
    # unrelated test or in a concurrent run can never be attributed here.
    leaked = H.assert_no_open_sockets()
    assert not leaked, f"harness leaked its own sockets: {leaked}"


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Persist the recorded assertions for the report generator.

    Args:
        session: pytest session object.
        exitstatus: Exit status of the run.
    """
    RESULTS_DIR.mkdir(exist_ok=True)
    payload = {"exitstatus": exitstatus, "records": _REPORTS.get("records", [])}
    (RESULTS_DIR / "last-run.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    """Record every test outcome, including ``xfail`` (blocked) ones.

    Args:
        report: pytest report for one phase.
    """
    if report.when != "call":
        return
    bucket = _REPORTS.setdefault("records", [])
    properties = dict(report.user_properties or ())
    bucket.append(
        {
            "nodeid": report.nodeid,
            "outcome": (
                "blocked"
                if report.outcome == "skipped" and report.wasxfail
                else report.outcome
            ),
            "wasxfail": getattr(report, "wasxfail", "") or "",
            "transport": properties.get("transport"),
            "a_mode": properties.get("a_mode"),
            "duration_s": round(report.duration, 3),
        }
    )


#: Run-scoped accumulator shared with :func:`pytest_sessionfinish`.
_REPORTS: dict[str, list[dict[str, Any]]] = {}
