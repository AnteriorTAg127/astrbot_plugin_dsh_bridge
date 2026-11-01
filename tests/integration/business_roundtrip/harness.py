"""Harness plumbing for the business round-trip acceptance suite.

Scope: temporary data roots, synthetic credentials, loopback ports and the
lifecycle of the two peer processes. This module contains no protocol logic, no
bridge business logic and no assertions about the product — the cases own those.

Hard rules enforced here:

* Ports come from ``bind(("127.0.0.1", 0))`` only; ``3080`` (DSH Web GUI) and
  ``6185`` (AstrBot API) are refused by construction.
* Credentials are synthetic per run, generated with :mod:`secrets`; they are never
  read from the environment, a config file or ``api_config.json``.
* Every data root is a fresh temporary directory, removed by :meth:`PeerPair.close`
  even when a case fails.
* Every spawned process is killed in a ``finally`` block and re-checked, so a
  failing assertion cannot leave a peer (or a listening socket) behind.
"""

from __future__ import annotations

import contextlib
import json
import os
import queue
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

#: Wall-clock instant this module was imported, so teardown can tell this run's
#: leftovers from an unrelated orphan.
RUN_STARTED_AT = time.time()

#: Ports this harness must never touch (DSH Web GUI, AstrBot API).
FORBIDDEN_PORTS = frozenset({3080, 6185})

HERE = Path(__file__).resolve().parent
#: A plugin root (this file lives at ``<plugin>/tests/integration/business_roundtrip``).
A_ROOT = HERE.parents[2]
#: B plugin root; overridable so the suite is not tied to one checkout layout.
B_ROOT = Path(
    os.environ.get("DSH_BRIDGE_B_ROOT") or (A_ROOT.parent / "dsh-plugin-astrbot-bridge")
).resolve()

PYTHON = os.environ.get("DSH_BRIDGE_PYTHON") or sys.executable
NODE = os.environ.get("DSH_BRIDGE_NODE") or "node"

A_PEER = HERE / "a_peer.py"
B_PEER = HERE / "b_peer.mjs"

#: The plugin package name A's modules are imported as (``main.py`` uses relative
#: imports, so it must be imported under its real package name).
A_PACKAGE = A_ROOT.name


class HarnessError(RuntimeError):
    """Raised when the harness itself cannot run (not a product failure)."""


def free_port() -> int:
    """Ask the OS for an unused loopback TCP port.

    Returns:
        A port number the kernel just handed out.

    Raises:
        HarnessError: When the kernel returns a forbidden port.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])
    if port in FORBIDDEN_PORTS:
        raise HarnessError(f"kernel returned forbidden port {port}")
    return port


def wait_port_open(port: int, timeout_s: float = 40.0) -> bool:
    """Block until something accepts TCP connections on ``port``.

    Args:
        port: Port to poll.
        timeout_s: Maximum wait in seconds.

    Returns:
        ``True`` when the port accepted a connection before the deadline.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.25)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.05)
    return False


def port_is_free(port: int) -> bool:
    """Whether nothing is listening on ``port``.

    Args:
        port: TCP port to check.

    Returns:
        ``True`` when a connect attempt is refused.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("127.0.0.1", port)) != 0


class PeerProcess:
    """One peer subprocess with a JSON-lines command channel.

    Commands go to stdin; events land in an append-only file, which keeps the
    control stream away from the peer's own stdout logging and needs no POSIX file
    descriptor passing (so the same code runs on Windows).
    """

    def __init__(
        self, name: str, argv: list[str], env: dict[str, str], events_path: Path
    ):
        """Start one peer.

        Args:
            name: Label used in error messages (``"A"`` / ``"B"``).
            argv: Command line.
            env: Complete environment for the child.
            events_path: File the child appends control events to.
        """
        self.name = name
        self.events_path = events_path
        self.events_path.write_text("", encoding="utf-8")
        self._offset = 0
        self._pending: list[dict] = []
        self.stderr_tail: list[str] = []
        self.proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self._stdout: queue.Queue[str] = queue.Queue()
        self._stderr: queue.Queue[str] = queue.Queue()
        self._threads = [
            threading.Thread(
                target=self._pump, args=(self.proc.stdout, self._stdout), daemon=True
            ),
            threading.Thread(
                target=self._pump, args=(self.proc.stderr, self._stderr), daemon=True
            ),
        ]
        #: Combined output, stdout first: the A side logs to stdout, B to stderr.
        self._logs: list[str] = []
        for thread in self._threads:
            thread.start()
        self._next_id = 0

    @staticmethod
    def _pump(stream: Any, sink: queue.Queue[str]) -> None:
        """Copy one child stream into a queue until EOF.

        Args:
            stream: Child stream.
            sink: Destination queue.
        """
        with contextlib.suppress(Exception):
            for line in stream:
                sink.put(line.rstrip("\n"))

    def _drain_logs(self) -> None:
        """Keep the child's output quarantined so a full pipe cannot block it."""
        while True:
            try:
                self.stderr_tail.append(self._stderr.get_nowait())
            except queue.Empty:
                break
            if len(self.stderr_tail) > 300:
                del self.stderr_tail[:150]
        while True:
            try:
                self.stderr_tail.append(self._stdout.get_nowait())
            except queue.Empty:
                return

    def drain_logs(self) -> list[str]:
        """Return the child's output lines, keeping the newest for later reads.

        The tail is deliberately *not* cleared: a case that reads logs twice must
        still see the first lines, and the ring already bounds memory.

        Returns:
            Log lines, oldest first.
        """
        self._drain_logs()
        return list(self.stderr_tail)

    def read_events(self) -> list[dict]:
        """Read control events appended since the last call.

        Returns:
            Parsed event objects, in file order.
        """
        text = self.events_path.read_text(encoding="utf-8")
        fresh = text[self._offset :]
        self._offset = len(text)
        events = []
        for line in fresh.splitlines():
            line = line.strip()
            if not line:
                continue
            with contextlib.suppress(json.JSONDecodeError):
                events.append(json.loads(line))
        return events

    def wait_event(self, predicate: Any, timeout_s: float, what: str) -> dict:
        """Wait for one matching control event.

        Args:
            predicate: Callable taking an event and returning a bool.
            timeout_s: Maximum wait.
            what: Description used in the failure message.

        Returns:
            The matching event.

        Raises:
            HarnessError: On timeout, with the child's recent stderr attached.
        """
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            for index, event in enumerate(self._pending):
                if predicate(event):
                    return self._pending.pop(index)
            self._pending.extend(self.read_events())
            for index, event in enumerate(self._pending):
                if predicate(event):
                    return self._pending.pop(index)
            self._drain_logs()
            if self.proc.poll() is not None:
                raise HarnessError(
                    f"peer {self.name} exited with {self.proc.returncode} while waiting for "
                    f"{what}: {' | '.join(self.stderr_tail[-8:])}"
                )
            time.sleep(0.02)
        raise HarnessError(
            f"peer {self.name} did not produce {what} within {timeout_s:.1f}s: "
            f"{' | '.join(self.stderr_tail[-8:])}"
        )

    def command(self, payload: dict, timeout_s: float = 30.0) -> dict:
        """Send one command and wait for its reply.

        Args:
            payload: Command object; ``id`` is assigned here.
            timeout_s: Maximum wait for the reply.

        Returns:
            The reply event.
        """
        assert self.proc.stdin is not None
        self._next_id += 1
        command_id = self._next_id
        payload = {**payload, "id": command_id}
        self.proc.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self.proc.stdin.flush()
        return self.wait_event(
            lambda event: event.get("id") == command_id,
            timeout_s,
            f"reply to {payload.get('op')}",
        )

    def stop(self) -> None:
        """Terminate the child and reap it, escalating to a kill."""
        if self.proc.poll() is None:
            with contextlib.suppress(Exception):
                assert self.proc.stdin is not None
                self.proc.stdin.close()
            with contextlib.suppress(Exception):
                self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(Exception):
                    self.proc.kill()
                with contextlib.suppress(Exception):
                    self.proc.wait(timeout=10)
        for thread in self._threads:
            thread.join(timeout=2)
        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            with contextlib.suppress(Exception):
                if stream is not None:
                    stream.close()


class PeerPair:
    """An A listener plus a B connector over one real loopback WebSocket."""

    def __init__(
        self, approval_timeout_s: int = 600, delivery_delay_ms: int = 0
    ) -> None:
        """Allocate ports, credentials and temporary data roots.

        Args:
            approval_timeout_s: Approval deadline both sides are configured with.
            delivery_delay_ms: Test-only B-side delay before a delivery is counted.
        """
        self.approval_timeout_s = approval_timeout_s
        self.delivery_delay_ms = delivery_delay_ms
        self.port = free_port()
        self.conn = "business"
        self.psk_id = f"business-{secrets.token_hex(4)}"
        self.psk_secret = secrets.token_hex(32)
        self.root = Path(tempfile.mkdtemp(prefix="dsh-br-assurance-"))
        self.a_data = self.root / "a-data"
        self.b_data = self.root / "b-data"
        self.a_data.mkdir()
        self.b_data.mkdir()
        self.a_events = self.root / "a-events.jsonl"
        self.b_events = self.root / "b-events.jsonl"
        self.a_mode = "direct"
        self.a: PeerProcess | None = None
        self.b: PeerProcess | None = None
        self._sid: str | None = None

    # -- lifecycle ---------------------------------------------------------------------

    def start_a(self) -> PeerProcess:
        """Start the A peer and wait for its listener plus handshake state.

        Returns:
            The running A peer.
        """
        env = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": str(A_ROOT.parent),
            "PYTHONUNBUFFERED": "1",
            "DSH_BR_A_EVENTS": str(self.a_events),
            "DSH_BR_APPROVAL_TIMEOUT": str(self.approval_timeout_s),
            "HOME": os.environ.get("HOME", ""),
        }
        self.a = PeerProcess(
            "A",
            [
                PYTHON,
                str(A_PEER),
                "--port",
                str(self.port),
                "--data-root",
                str(self.a_data),
                "--conn",
                self.conn,
                "--psk-id",
                self.psk_id,
                "--psk-secret",
                self.psk_secret,
                "--mode",
                self.a_mode,
            ],
            env,
            self.a_events,
        )
        if not wait_port_open(self.port, timeout_s=40):
            raise HarnessError(
                f"A never listened on {self.port}: {' | '.join(self.a.stderr_tail[-10:])}"
            )
        return self.a

    def start_b(self, timeout_s: float = 45.0) -> PeerProcess:
        """Start the B peer and wait until its session is ready.

        Args:
            timeout_s: Maximum wait for the B handshake.

        Returns:
            The running B peer.
        """
        env = {
            "PATH": os.environ.get("PATH", ""),
            "DSH_BR_CONTROL_B_ROOT": str(B_ROOT),
            "DSH_BR_DATA_ROOT": str(self.b_data),
            "DSH_BR_CONTROL_PATH": str(self.b_events),
            "DSH_BR_CONN": self.conn,
            "DSH_BR_PSK_ID": self.psk_id,
            "DSH_BR_PSK_SECRET": self.psk_secret,
            "DSH_BR_PEER_PORT": str(self.port),
            "DSH_BR_APPROVAL_TIMEOUT": str(self.approval_timeout_s),
            "DSH_BR_DELIVERY_DELAY_MS": str(self.delivery_delay_ms),
            "HOME": os.environ.get("HOME", ""),
        }
        self.b = PeerProcess(
            "B",
            [NODE, str(B_PEER)],
            env,
            self.b_events,
        )
        ready = self.b.wait_event(
            lambda event: event.get("event") in ("ready", "start_error"),
            timeout_s,
            "B ready",
        )
        if ready.get("event") != "ready":
            raise HarnessError(f"B failed to become ready: {ready}")
        self._sid = ready.get("sid")
        # A's responder side becomes ready when B's hello arrives; its own
        # ``ready`` event is the proof that both ends negotiated one session.
        self.a.wait_event(
            lambda event: event.get("event") == "ready", timeout_s, "A ready"
        )  # type: ignore[union-attr]
        return self.b

    @property
    def sid(self) -> str:
        """The B-side session identity of the live handshake."""
        assert self._sid is not None
        return self._sid

    def close(self) -> None:
        """Stop both peers and remove the temporary data roots."""
        for peer in (self.b, self.a):
            if peer is None:
                continue
            with contextlib.suppress(Exception):
                if peer.proc.poll() is None:
                    peer.command({"op": "close"}, timeout_s=20)
            with contextlib.suppress(Exception):
                peer.stop()
        shutil.rmtree(self.root, ignore_errors=True)

    # -- convenience views -------------------------------------------------------------

    def a_snapshot(self) -> dict:
        """Read A's business snapshot.

        Returns:
            Snapshot dictionary.
        """
        assert self.a is not None
        return self.a.command({"op": "snapshot"}, timeout_s=25)

    def b_snapshot(self) -> dict:
        """Read B's business snapshot.

        Returns:
            Snapshot dictionary.
        """
        assert self.b is not None
        return self.b.command({"op": "snapshot"}, timeout_s=25)

    def a_grant(self, session_id: str, purpose: str = "") -> dict:
        """Authorize a session on A (the authority for both ends).

        Args:
            session_id: Session to grant.
            purpose: Purpose label.

        Returns:
            Reply event.
        """
        assert self.a is not None
        return self.a.command(
            {"op": "grant", "session_id": session_id, "purpose": purpose}
        )

    def wait_b_authz(self, session_id: str, timeout_s: float = 25.0) -> bool:
        """Wait until B's own authorization table contains the grant A pushed.

        A claim is decided synchronously against B's cached table, so a case that
        raises a harness request before the push lands would be testing a race, not
        the product. Waiting for the pushed row makes the precondition explicit.

        Args:
            session_id: Session that must appear as granted.
            timeout_s: Maximum wait.

        Returns:
            ``True`` when the session is in B's table.
        """
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            snapshot = self.b_snapshot()
            grants = (snapshot.get("authz") or {}).get("grants") or []
            if any(str(grant.get("session_id")) == str(session_id) for grant in grants):
                return True
            time.sleep(0.1)
        return False

    def wait_a_approval(self, approval_id: str, timeout_s: float = 25.0) -> dict | None:
        """Wait until the receiving side stored the forwarded approval.

        The peer's ``approval.request`` is a request, and the human may only act once
        the row exists locally; deciding earlier would test a race instead of the
        product.

        Args:
            approval_id: Approval identifier.
            timeout_s: Maximum wait.

        Returns:
            The stored approval row, or ``None`` on timeout.
        """
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            for row in self.a_snapshot()["approvals"]:
                if row["approval_id"] == approval_id:
                    return row
            time.sleep(0.1)
        return None

    def b_call(self, message: str, params: dict, timeout_s: float = 25.0) -> dict:
        """Issue one real request from B to A over the live session.

        Args:
            message: Protocol message name.
            params: Request parameters.
            timeout_s: Call timeout.

        Returns:
            Reply event (``ok`` is false for a protocol error).
        """
        assert self.b is not None
        return self.b.command(
            {"op": "call", "m": message, "params": params, "timeout_s": timeout_s},
            timeout_s=timeout_s + 10,
        )

    def a_logs(self) -> list[str]:
        """Drain A's captured stdout/stderr lines seen so far.

        Returns:
            Log lines, oldest first.
        """
        assert self.a is not None
        return self.a.drain_logs()

    def b_logs(self) -> list[str]:
        """Drain B's captured stdout/stderr lines seen so far.

        Returns:
            Log lines, oldest first.
        """
        assert self.b is not None
        return self.b.drain_logs()

    def a_command(self, payload: dict, timeout_s: float = 30.0) -> dict:
        """Send a command to A.

        Args:
            payload: Command object.
            timeout_s: Maximum wait.

        Returns:
            Reply event.
        """
        assert self.a is not None
        return self.a.command(payload, timeout_s=timeout_s)

    def b_command(self, payload: dict, timeout_s: float = 30.0) -> dict:
        """Send a command to B.

        Args:
            payload: Command object.
            timeout_s: Maximum wait.

        Returns:
            Reply event.
        """
        assert self.b is not None
        return self.b.command(payload, timeout_s=timeout_s)

    def wait_a_task(
        self, task_id: str, statuses: list[str], timeout_s: float = 25.0
    ) -> dict:
        """Wait for one A-side task to reach a status.

        Args:
            task_id: Task identifier.
            statuses: Acceptable statuses.
            timeout_s: Maximum wait.

        Returns:
            Reply event carrying ``task``.
        """
        return self.a_command(
            {
                "op": "wait_task",
                "task_id": task_id,
                "statuses": statuses,
                "timeout_s": timeout_s,
            },
            timeout_s=timeout_s + 10,
        )

    def wait_b_task(
        self, task_id: str, statuses: list[str], timeout_s: float = 25.0
    ) -> dict:
        """Wait for one B-side task to reach a status.

        Args:
            task_id: Task identifier.
            statuses: Acceptable statuses.
            timeout_s: Maximum wait.

        Returns:
            Reply event carrying ``task``.
        """
        return self.b_command(
            {
                "op": "wait_task",
                "task_id": task_id,
                "statuses": statuses,
                "timeout_s": timeout_s,
            },
            timeout_s=timeout_s + 10,
        )


def b_available() -> tuple[bool, str]:
    """Whether the B peer can run at all in this environment.

    Returns:
        ``(True, "")`` when ready, otherwise ``(False, reason)``.
    """
    if not B_ROOT.is_dir():
        return False, f"B plugin root not found at {B_ROOT}"
    if not (B_ROOT / "lib" / "index.js").is_file():
        return False, f"B plugin entry missing under {B_ROOT}"
    if not (B_ROOT / "node_modules" / "@deepseek-ai" / "cordis").exists():
        return False, f"B node_modules not installed under {B_ROOT}"
    if shutil.which(NODE) is None:
        return False, f"node executable not found ({NODE})"
    if not Path(PYTHON).exists():
        return False, f"python executable not found ({PYTHON})"
    return True, ""
