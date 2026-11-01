"""Fixtures and outcome vocabulary for the business round-trip acceptance suite.

Three outcomes are kept strictly apart and never merged:

* **pass** — the business behaviour was observed end to end over a real socket.
* **fail** — the behaviour was observed to be wrong (a product defect).
* **blocked** — the behaviour could not be exercised because one side has not
  implemented the required piece. Raised as ``pytest.xfail`` with a reason that
  starts with ``BLOCKED-IMPL`` and names the exact file and function; a block is
  never a silent skip and never a pass.

Everything else in this suite is real: two processes, one real loopback
WebSocket between them, both real plugin assemblies and both real durable stores.
Only the host boundaries are stubbed (``M`` in the report): A's AstrBot agent run
and IM wake sink, B's model-facing agent registry.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from tests.integration.business_roundtrip import harness as H

#: Where the run writes its machine-readable snapshot.
RESULTS_DIR = Path(__file__).resolve().parent / "_results"

#: Statuses a task can reach, used by the wait helpers.
TERMINAL = ("succeeded", "failed", "rejected", "canceled", "needs_human")


def pytest_configure(config: pytest.Config) -> None:
    """Register this suite's mark without editing the shared ``pytest.ini``.

    Args:
        config: pytest configuration object.
    """
    config.addinivalue_line(
        "markers", "business_roundtrip: real-socket business acceptance, both sides"
    )
    config.addinivalue_line(
        "markers", "approval_timeout(seconds): approval deadline both peers run with"
    )
    config.addinivalue_line(
        "markers",
        "delivery_delay(ms): test-only B-side delay before a delivery is counted",
    )


def pytest_report_header(config: pytest.Config) -> list[str]:
    """Report the environment this suite will run against.

    Args:
        config: pytest configuration object.

    Returns:
        Header lines.
    """
    ok, reason = H.b_available()
    return [
        f"business-roundtrip: A={H.A_ROOT}",
        f"business-roundtrip: B={H.B_ROOT} ({'ready' if ok else reason})",
        f"business-roundtrip: python={H.PYTHON} node={H.NODE}",
    ]


@dataclass
class Outcome:
    """One case's recorded outcome, for the run snapshot.

    Attributes:
        name: Test name.
        verdict: ``pass`` / ``fail`` / ``blocked``.
        detail: One-line explanation.
        data: Structured evidence captured by the case.
    """

    name: str
    verdict: str
    detail: str
    data: dict[str, Any] = field(default_factory=dict)


#: Every outcome recorded in this run, in execution order.
OUTCOMES: list[Outcome] = []


@pytest.fixture(scope="session")
def b_ready() -> None:
    """Skip the whole module only when B cannot physically run here.

    Returns:
        None.

    Raises:
        pytest.skip: When the B checkout or its dependencies are unusable.
    """
    ok, reason = H.b_available()
    if not ok:
        pytest.skip(f"BLOCKED-ENV: {reason}")


@pytest.fixture
def pair(request: pytest.FixtureRequest, b_ready: None) -> Any:
    """Start one real A listener and one real B connector, then tear both down.

    Args:
        request: pytest request, used to read a case's approval deadline marker.
        b_ready: Ensures the environment check ran first.

    Yields:
        A live :class:`harness.PeerPair` with both sessions ready.
    """
    timeout = (
        int(request.node.get_closest_marker("approval_timeout").args[0])
        if request.node.get_closest_marker("approval_timeout")
        else 600
    )
    delay = (
        int(request.node.get_closest_marker("delivery_delay").args[0])
        if request.node.get_closest_marker("delivery_delay")
        else 0
    )
    instance = H.PeerPair(approval_timeout_s=timeout, delivery_delay_ms=delay)
    try:
        instance.start_a()
        instance.start_b()
        # A owns the authorization table, so every case starts from the one state a
        # human would have set up: the peer's session is granted. Cases that test
        # revocation archive/revoke it themselves.
        instance.a_grant(instance.sid, purpose="acceptance")
        # A's push is what makes a claim possible, so the fixture waits for it once
        # instead of every case racing it with a sleep.
        assert instance.wait_b_authz(instance.sid), "A never pushed the grant to B"
        yield instance
    finally:
        instance.close()


@pytest.fixture(autouse=True)
def record_outcome(request: pytest.FixtureRequest) -> Any:
    """Record each case's verdict so the report can be generated from the run.

    Args:
        request: pytest request object.

    Yields:
        A mutable dict the case may fill with evidence.
    """
    evidence: dict[str, Any] = {}
    started = time.time()
    yield evidence
    report = getattr(request.node, "rep_call", None)
    verdict = "pass"
    detail = f"{time.time() - started:.1f}s"
    if report is not None and report.failed:
        verdict = "fail"
        tail = (report.longreprtext or "").strip().splitlines()
        detail = tail[-1][:200] if tail else detail
    elif report is not None and report.skipped:
        verdict = "blocked"
        detail = str(report.longrepr[2] if isinstance(report.longrepr, tuple) else "")[
            :200
        ]
    OUTCOMES.append(Outcome(request.node.name, verdict, detail, evidence))


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo) -> Any:
    """Expose each phase report on the item so the fixture can read it.

    Args:
        item: Test item.
        call: Phase call info.

    Yields:
        Control to pytest, then attaches the report.
    """
    outcome = yield
    report = outcome.get_result()
    setattr(item, f"rep_{report.when}", report)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Write the run snapshot next to the suite.

    Args:
        session: pytest session.
        exitstatus: pytest exit code.
    """
    # A collect-only run (`--co`) or a run that could not start records nothing;
    # writing an empty snapshot there would destroy the previous real one.
    if not OUTCOMES:
        return
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "exitstatus": exitstatus,
        "a_root": str(H.A_ROOT),
        "b_root": str(H.B_ROOT),
        "outcomes": [
            {
                "name": item.name,
                "verdict": item.verdict,
                "detail": item.detail,
                "data": item.data,
            }
            for item in OUTCOMES
        ],
    }
    (RESULTS_DIR / "last-run.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
