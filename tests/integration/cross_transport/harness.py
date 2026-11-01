"""Harness plumbing for the cross-language transport tests.

Scope: ports, synthetic credentials, peer process lifecycle and the capture of
wire bytes. This module contains no protocol logic and no bridge business code.

Hard rules enforced here (they are asserted, not documented promises):

* Ports come from ``bind(("127.0.0.1", 0))`` only; ``3080`` (DSH Web GUI) and
  ``6185`` (AstrBot API) are refused by construction.
* Credentials are synthetic per run; they are generated from ``secrets`` and are
  never read from the environment, a config file or ``api_config.json``.
* Every spawned process is killed in a ``finally`` block by
  :class:`PeerProcess`, and :func:`assert_no_stray_children` re-checks.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import queue
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Wall-clock instant this module was imported. Used to distinguish peers this
#: run left behind from orphans of an earlier, killed run (which must not fail
#: the current assertion but are still reported by the caller's cleanup).
RUN_STARTED_AT = time.time()

#: Every peer this process spawned, in creation order. Teardown asserts on this
#: registry rather than on a global process scan: a scan races with a concurrent
#: run and can attribute somebody else's peer to this test.
SPAWNED: list[PeerProcess] = []

#: Ports this harness must never touch (§9.3 of the integration plan).
FORBIDDEN_PORTS = frozenset({3080, 6185})

#: Repo roots, derived from this file's location so the same harness runs from
#: any checkout without editing constants.
HERE = Path(__file__).resolve().parent
A_ROOT = HERE.parents[2]
B_ROOT = Path(
    os.environ.get("DSH_BRIDGE_B_ROOT") or (A_ROOT.parent / "dsh-plugin-astrbot-bridge")
).resolve()

PYTHON = os.environ.get("DSH_BRIDGE_PYTHON") or sys.executable
NODE = os.environ.get("DSH_BRIDGE_NODE") or "node"

A_PEER = HERE / "a_peer.py"
B_PEER = HERE / "b_peer.mjs"


class HarnessError(RuntimeError):
    """Raised when the harness itself cannot run (not a bridge failure)."""


#: Sockets this test process opened through :func:`harness_socket` and has not
#: closed yet. Only sockets the harness itself opened are tracked, so the
#: teardown assertion can never blame the interpreter, an unrelated test or a
#: concurrent run for a descriptor this harness does not own.
OPEN_SOCKETS: set[socket.socket] = set()


@contextlib.contextmanager
def harness_socket(*, timeout_s: float | None = None) -> Iterator[socket.socket]:
    """Yield a TCP socket and always close it, tracking it while open.

    Args:
        timeout_s: Optional connect/read timeout.

    Yields:
        A fresh ``AF_INET``/``SOCK_STREAM`` socket.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if timeout_s is not None:
        sock.settimeout(timeout_s)
    OPEN_SOCKETS.add(sock)
    try:
        yield sock
    finally:
        OPEN_SOCKETS.discard(sock)
        with contextlib.suppress(OSError):
            sock.close()


def assert_no_open_sockets() -> list[str]:
    """Report (and force-close) sockets this harness opened and leaked.

    Returns:
        Descriptions of the sockets that were still open; empty when clean.
    """
    leaked = [repr(sock) for sock in OPEN_SOCKETS]
    for sock in list(OPEN_SOCKETS):
        OPEN_SOCKETS.discard(sock)
        with contextlib.suppress(OSError):
            sock.close()
    return leaked


def free_port() -> int:
    """Ask the OS for an unused loopback TCP port.

    Returns:
        A port number the kernel just handed out; nothing is listening on it
        after this function returns.

    Raises:
        HarnessError: When the kernel returns a forbidden port (should not
            happen, but the check makes the rule impossible to violate).
    """
    with harness_socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])
    if port in FORBIDDEN_PORTS:
        raise HarnessError(f"kernel returned forbidden port {port}")
    return port


def port_is_free(port: int) -> bool:
    """Whether nothing is listening on ``port``.

    Args:
        port: TCP port to check.

    Returns:
        ``True`` when a connect attempt is refused.
    """
    with harness_socket(timeout_s=0.5) as sock:
        return sock.connect_ex(("127.0.0.1", port)) != 0


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
        with harness_socket(timeout_s=0.25) as sock:
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.05)
    return False


@dataclass(frozen=True)
class Credentials:
    """Synthetic, per-run connection credentials.

    Attributes:
        conn: Connection identifier shared by both ends.
        psk_id: Non-secret PSK identifier.
        psk_secret: Synthetically generated secret; never logged or persisted.
    """

    conn: str
    psk_id: str
    psk_secret: str = field(repr=False)

    @classmethod
    def synthetic(cls, conn: str = "default") -> Credentials:
        """Generate a fresh synthetic credential triple.

        Args:
            conn: Connection identifier.

        Returns:
            Credentials with a 32-byte random secret.
        """
        return cls(conn=conn, psk_id="test-conn", psk_secret=secrets.token_hex(32))


@dataclass
class PeerReply:
    """One reply event received from a peer process.

    Attributes:
        event: Event name (``ready``, ``snapshot``, ``result``, …).
        data: Full JSON object.
    """

    event: str
    data: dict[str, Any]


class PeerProcess:
    """A child peer process with a JSON-line control channel.

    Events arrive on an inherited pipe (fd 3) so the peer's own stdout logging
    cannot corrupt the control stream. A reader thread drains it into a queue;
    :meth:`request` correlates replies by ``id``.
    """

    def __init__(
        self,
        *,
        name: str,
        argv: list[str],
        cwd: Path,
        env: dict[str, str] | None = None,
    ) -> None:
        """Spawn the peer process.

        Args:
            name: Human-readable label used in error messages.
            argv: Command line (absolute executable first).
            cwd: Working directory for the child.
            env: Extra environment variables.
        """
        self.name = name
        self.argv = argv
        self.cwd = cwd
        self._events: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._unsolicited: list[dict[str, Any]] = []
        self._next_id = 0
        self._stderr_lines: list[str] = []
        self._stdout_lines: list[str] = []
        read_fd, write_fd = os.pipe()
        child_env = {
            **os.environ,
            "DSH_BRIDGE_B_ROOT": str(B_ROOT),
            "PYTHONPATH": str(A_ROOT),
            "PYTHONUNBUFFERED": "1",
            "DSH_BRIDGE_CONTROL_FD": str(write_fd),
            **(env or {}),
        }
        try:
            self.proc = subprocess.Popen(  # noqa: S603 - argv is built locally
                argv,
                cwd=str(cwd),
                env=child_env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                preexec_fn=_child_preexec,
                pass_fds=(write_fd,),
            )
        finally:
            os.close(write_fd)
        self._control_fd = read_fd
        SPAWNED.append(self)
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        self._log_reader = threading.Thread(target=self._log_loop, daemon=True)
        self._log_reader.start()

    # -- plumbing ----------------------------------------------------------------------

    def _read_loop(self) -> None:
        """Decode control lines until EOF and publish them to the queue."""
        with os.fdopen(self._control_fd, "rb", buffering=0) as stream:
            for raw in stream:
                text = raw.decode("utf-8", "replace").strip()
                if not text:
                    continue
                try:
                    self._events.put(json.loads(text))
                except json.JSONDecodeError:
                    self._events.put({"event": "_unparsable", "line": text})
        self._events.put(None)

    def _log_loop(self) -> None:
        """Drain stdout/stderr so a chatty peer can never block on a full pipe."""
        _drain(self.proc.stdout, self._stdout_lines)
        _drain(self.proc.stderr, self._stderr_lines)

    def send(self, **payload: Any) -> int:
        """Send one command object.

        Args:
            **payload: Command fields; ``id`` is assigned here.

        Returns:
            The assigned command id.
        """
        self._next_id += 1
        command = {"id": self._next_id, **payload}
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(command) + "\n")
        self.proc.stdin.flush()
        return self._next_id

    def request(self, wait_s: float, **payload: Any) -> dict[str, Any]:
        """Send a command and wait for its reply.

        Args:
            wait_s: Maximum wait in seconds for the reply. Named ``wait_s`` so a
                command field called ``timeout_s`` can be passed through verbatim.
            **payload: Command fields.

        Returns:
            The matching reply object.

        Raises:
            HarnessError: On timeout, EOF, or a reply id mismatch.
        """
        command_id = self.send(**payload)
        deadline = time.monotonic() + wait_s
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HarnessError(
                    f"{self.name}: timeout waiting for reply to {payload.get('op')}"
                )
            try:
                event = self._events.get(timeout=remaining)
            except queue.Empty as exc:
                raise HarnessError(
                    f"{self.name}: timeout waiting for reply to {payload.get('op')}"
                ) from exc
            if event is None:
                raise HarnessError(
                    f"{self.name}: process ended before replying to {payload.get('op')}; "
                    f"stderr tail={self.stderr_tail(800)}"
                )
            if event.get("id") != command_id:
                # Unsolicited events (e.g. `ready`) are kept for later assertions.
                self.unsolicited.append(event)
                continue
            return event

    @property
    def unsolicited(self) -> list[dict[str, Any]]:
        """Events received that were not replies to a :meth:`request`.

        Returns:
            Accumulated list.
        """
        return self._unsolicited

    def wait_event(self, event_name: str, timeout_s: float) -> dict[str, Any]:
        """Wait for one unsolicited event with the given name.

        Args:
            event_name: ``event`` field to match.
            timeout_s: Maximum wait.

        Returns:
            The event object.

        Raises:
            HarnessError: On timeout or EOF.
        """
        for existing in self.unsolicited:
            if existing.get("event") == event_name:
                self.unsolicited.remove(existing)
                return existing
        deadline = time.monotonic() + timeout_s
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HarnessError(
                    f"{self.name}: timeout waiting for event {event_name}"
                )
            try:
                event = self._events.get(timeout=remaining)
            except queue.Empty as exc:
                raise HarnessError(
                    f"{self.name}: timeout waiting for event {event_name}"
                ) from exc
            if event is None:
                raise HarnessError(
                    f"{self.name}: ended while waiting for {event_name}; "
                    f"stderr tail={self.stderr_tail(800)}"
                )
            if event.get("event") == event_name:
                return event
            self.unsolicited.append(event)

    def drain_events(self) -> list[dict[str, Any]]:
        """Return every event that is currently queued, without blocking.

        Returns:
            List of events (including a trailing ``None`` sentinel dropped).
        """
        out: list[dict[str, Any]] = []
        while True:
            try:
                event = self._events.get_nowait()
            except queue.Empty:
                break
            if event is None:
                continue
            out.append(event)
        return out

    def stdout_tail(self, limit: int = 4000) -> str:
        """Return the tail of captured stdout.

        Args:
            limit: Characters to keep.

        Returns:
            Tail text.
        """
        return "".join(self._stdout_lines)[-limit:]

    def stderr_tail(self, limit: int = 4000) -> str:
        """Return the tail of captured stderr.

        Args:
            limit: Characters to keep.

        Returns:
            Tail text.
        """
        return "".join(self._stderr_lines)[-limit:]

    @property
    def returncode(self) -> int | None:
        """Process exit status, or ``None`` while running.

        Returns:
            Exit code or ``None``.
        """
        return self.proc.poll()

    def stop(self, timeout_s: float = 5.0) -> None:
        """Terminate the peer and its process group, escalating to ``SIGKILL``.

        The child runs in its own session (``setsid``), so the whole group is
        signalled: a peer that spawned helpers cannot leave them behind.

        Args:
            timeout_s: Grace period before the hard kill.
        """
        if self.proc.poll() is not None:
            self._kill_group()
            self._reap()
            return
        # Closing stdin makes a cooperative peer exit through its normal path.
        with contextlib.suppress(Exception):
            if self.proc.stdin is not None:
                self.proc.stdin.close()
        with contextlib.suppress(Exception):
            self.proc.terminate()
        try:
            self.proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            pass
        self._kill_group()
        with contextlib.suppress(Exception):
            self.proc.wait(timeout=timeout_s)
        self._reap()
        for stream in (self.proc.stdout, self.proc.stderr):
            with contextlib.suppress(Exception):
                if stream is not None:
                    stream.close()

    @property
    def alive(self) -> bool:
        """Whether the child process still exists (zombies count as gone).

        Returns:
            ``True`` while the process is running.
        """
        if self.proc.poll() is not None:
            return False
        return not _is_zombie(self.proc.pid)

    def _reap(self) -> None:
        """Wait for the child to be reaped so its pid cannot linger as a zombie.

        A zombie keeps ``/proc/<pid>/cmdline`` populated on some kernels, which
        would make the leftover check report a process that no longer exists.
        """
        with contextlib.suppress(Exception):
            self.proc.wait(timeout=5)

    def _kill_group(self) -> None:
        """Kill the child's process group, ignoring an already-dead group."""
        with contextlib.suppress(Exception):
            os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)

    def __enter__(self) -> PeerProcess:
        """Enter the context manager.

        Returns:
            This process.
        """
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Always terminate the child.

        Args:
            *exc_info: Exception information (ignored).
        """
        self.stop()


def _child_preexec() -> None:
    """Put each child in its own process group so a kill takes the whole tree."""
    with contextlib.suppress(Exception):
        os.setsid()


def _drain(stream: Any, sink: list[str]) -> None:
    """Read a text stream line by line into ``sink`` until EOF.

    Args:
        stream: Text stream or ``None``.
        sink: Accumulating list.
    """
    if stream is None:
        return
    with contextlib.suppress(Exception):
        for line in stream:
            sink.append(line)


def a_peer_argv(
    *,
    transport: str,
    mode: str,
    peer_port: int,
    bind_port: int,
    credentials: Credentials,
    path: str = "/dsh-bridge",
    poll_wait_s: int = 2,
    heartbeat_s: int = 30,
    probe_interval_s: int = 30,
) -> list[str]:
    """Build the A-side peer command line.

    Args:
        transport: ``ws`` / ``webhook`` / ``longpoll``.
        mode: ``listen`` or ``connect``.
        peer_port: Port of the peer endpoint.
        bind_port: Port this side binds for inbound delivery (0 = ephemeral).
        credentials: Synthetic credentials.
        path: Connection path prefix.
        poll_wait_s: Long-poll wait.
        heartbeat_s: Session heartbeat period in seconds.
        probe_interval_s: Webhook probe period; shortened only when a scenario
            has to observe consecutive probe failures inside the test budget.

    Returns:
        Argument vector.
    """
    return [
        PYTHON,
        "-u",
        str(A_PEER),
        "--transport",
        transport,
        "--mode",
        mode,
        "--peer-port",
        str(peer_port),
        "--bind-port",
        str(bind_port),
        "--path",
        path,
        "--conn",
        credentials.conn,
        "--psk-id",
        credentials.psk_id,
        "--psk-secret",
        credentials.psk_secret,
        "--poll-wait-s",
        str(poll_wait_s),
        "--heartbeat-s",
        str(heartbeat_s),
        "--probe-interval-s",
        str(probe_interval_s),
    ]


def b_peer_argv(
    *,
    transport: str,
    mode: str,
    peer_port: int,
    bind_port: int,
    credentials: Credentials,
    path: str = "/dsh-bridge",
    poll_wait_s: int = 2,
    heartbeat_s: int = 30,
    probe_interval_s: int = 30,
) -> list[str]:
    """Build the B-side peer command line.

    Args:
        transport: ``ws`` / ``webhook`` / ``longpoll``.
        mode: ``listen`` or ``connect``.
        peer_port: Port of the peer endpoint.
        bind_port: Port this side binds for inbound delivery.
        credentials: Synthetic credentials.
        path: Connection path prefix.
        poll_wait_s: Long-poll wait.
        heartbeat_s: Session heartbeat period in seconds.
        probe_interval_s: Webhook probe period (see :func:`a_peer_argv`).

    Returns:
        Argument vector.
    """
    return [
        NODE,
        str(B_PEER),
        "--transport",
        transport,
        "--mode",
        mode,
        "--peer-port",
        str(peer_port),
        "--bind-port",
        str(bind_port),
        "--path",
        path,
        "--conn",
        credentials.conn,
        "--psk-id",
        credentials.psk_id,
        "--psk-secret",
        credentials.psk_secret,
        "--poll-wait-s",
        str(poll_wait_s),
        "--heartbeat-s",
        str(heartbeat_s),
        "--probe-interval-s",
        str(probe_interval_s),
    ]


def normalize_peer_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Normalise spawn keyword arguments.

    Args:
        kwargs: Caller keyword arguments.

    Returns:
        A copy where ``port`` (when given without ``peer_port``) means the
        peer's port and ``bind_port`` defaults to ``0`` (kernel-assigned).
    """
    out = dict(kwargs)
    if "port" in out:
        out.setdefault("peer_port", out.pop("port"))
    out.setdefault("bind_port", 0)
    return out


def spawn_a(**kwargs: Any) -> PeerProcess:
    """Spawn the A-side peer.

    Args:
        **kwargs: Arguments forwarded to :func:`a_peer_argv`; ``port`` is an
            alias for ``peer_port`` so call sites read naturally.

    Returns:
        The running process handle.
    """
    argv = a_peer_argv(**normalize_peer_kwargs(kwargs))
    return PeerProcess(name="A", argv=argv, cwd=A_ROOT)


def spawn_b(**kwargs: Any) -> PeerProcess:
    """Spawn the B-side peer.

    Args:
        **kwargs: Arguments forwarded to :func:`b_peer_argv`; ``port`` is an
            alias for ``peer_port``.

    Returns:
        The running process handle.
    """
    argv = b_peer_argv(**normalize_peer_kwargs(kwargs))
    return PeerProcess(name="B", argv=argv, cwd=B_ROOT)


def public_env_keys() -> set[str]:
    """Names of environment variables the harness is allowed to read.

    Returns:
        A set containing only harness-owned overrides; never a credential.
    """
    return {
        "DSH_BRIDGE_B_ROOT",
        "DSH_BRIDGE_PYTHON",
        "DSH_BRIDGE_NODE",
        "DSH_BRIDGE_CONTROL_FD",
    }


def kill_process_group(process: subprocess.Popen[Any]) -> None:
    """Kill one process group, used as a last-resort cleanup.

    Args:
        process: Child process whose group must die.
    """
    with contextlib.suppress(Exception):
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)


def assert_spawned_all_dead(*, timeout_s: float = 10.0) -> list[str]:
    """Wait for every peer this process spawned to be gone.

    This is the exact check used by the fixture teardown: it looks only at peers
    this run started, so a concurrent or earlier run can never be blamed.

    Args:
        timeout_s: How long to keep polling before declaring leftovers.

    Returns:
        ``pid name`` strings that are still alive (empty when clean).
    """
    deadline = time.monotonic() + timeout_s
    while True:
        alive = [f"{peer.proc.pid} {peer.name}" for peer in SPAWNED if peer.alive]
        if not alive or time.monotonic() >= deadline:
            return alive
        for peer in SPAWNED:
            if peer.alive:
                peer.stop(timeout_s=2.0)
        time.sleep(0.1)


def assert_no_stray_children(
    markers: list[str] | None = None, *, timeout_s: float = 8.0
) -> list[str]:
    """Return peers this run left behind after teardown.

    Only processes started after this module was imported are considered: an
    orphan from an earlier, forcibly killed run must not be attributed to the
    current one, but it also must not be silently ignored forever, so callers
    can print :func:`all_harness_peers` for the full picture.

    Args:
        markers: Extra literal markers (defaults to this file's two peers).
        timeout_s: How long to keep polling before declaring leftovers.

    Returns:
        Matching ``pid cmdline`` strings (empty when this run cleaned up).
    """
    deadline = time.monotonic() + timeout_s
    while True:
        leftovers = [
            entry
            for entry in all_harness_peers(markers)
            if _started_after_run(entry.split(" ", 1)[0])
        ]
        if not leftovers or time.monotonic() >= deadline:
            return leftovers
        time.sleep(0.1)


def all_harness_peers(markers: list[str] | None = None) -> list[str]:
    """List every live harness peer, regardless of when it started.

    Args:
        markers: Extra literal markers (defaults to this file's two peers).

    Returns:
        ``pid cmdline`` strings, secrets redacted.
    """
    needles = [str(A_PEER), str(B_PEER), *(markers or [])]
    own = {os.getpid(), os.getppid()}
    found: list[str] = []
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return found
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid in own:
            continue
        with contextlib.suppress(OSError):
            raw = (entry / "cmdline").read_bytes()
            argv = raw.split(b"\x00")
            cmdline = " ".join(
                part.decode("utf-8", "ignore") for part in argv if part
            ).strip()
            if not cmdline:
                continue
            # A peer is recognised by its interpreter plus the script path, so a
            # shell wrapper that merely mentions the script is never matched.
            head = cmdline.split()[:4]
            if not any(needle in head for needle in needles[:2]):
                continue
            if _is_zombie(pid):
                continue
            found.append(f"{pid} {_redact(cmdline)}")
    return found


def _is_zombie(pid: int) -> bool:
    """Whether a pid is a zombie awaiting reaping.

    Args:
        pid: Process id.

    Returns:
        ``True`` when the process state is ``Z``.
    """
    with contextlib.suppress(OSError, ValueError, IndexError):
        stat = Path(f"/proc/{pid}/stat").read_text()
        fields = stat[stat.rindex(")") + 2 :].split()
        return bool(fields) and fields[0] == "Z"
    return False


def _redact(cmdline: str) -> str:
    """Remove the synthetic PSK from a command line before reporting it.

    Args:
        cmdline: Raw command line.

    Returns:
        Command line with the secret replaced.
    """
    parts = cmdline.split()
    out: list[str] = []
    for index, part in enumerate(parts):
        if index > 0 and parts[index - 1] == "--psk-secret":
            out.append("<redacted>")
            continue
        out.append(part)
    return " ".join(out)


def _started_after_run(pid_text: str) -> bool:
    """Whether a process started after this harness imported.

    Args:
        pid_text: Process id as text.

    Returns:
        ``True`` when the process began at or after :data:`RUN_STARTED_AT`.
    """
    with contextlib.suppress(OSError, ValueError):
        stat = Path(f"/proc/{int(pid_text)}/stat").read_text()
        # Field 22 is starttime in clock ticks since boot; the command name in
        # field 2 may contain spaces, so parse from the closing parenthesis.
        fields = stat[stat.rindex(")") + 2 :].split()
        start_ticks = int(fields[19])
        boot_time = time.time() - time.clock_gettime(time.CLOCK_BOOTTIME)
        return (
            boot_time + start_ticks / os.sysconf("SC_CLK_TCK") >= RUN_STARTED_AT - 1.0
        )
    return True


def run_async(coro: Any, *, timeout_s: float = 90.0) -> Any:
    """Run one coroutine to completion from a synchronous test or fixture.

    The ``pytest.ini`` runs the rest of the plugin in asyncio mode, so a test that
    needs an async object (a real ``TransportManager`` in this suite) calls this
    instead of taking an event loop argument: it always drives a fresh loop and
    closes it, which keeps the peer processes and the loop lifetime independent.

    Args:
        coro: Coroutine to await.
        timeout_s: Maximum runtime before the coroutine is cancelled.

    Returns:
        The coroutine's result.

    Raises:
        TimeoutError: When the coroutine does not finish in time.
    """

    async def _bounded() -> Any:
        return await asyncio.wait_for(coro, timeout=timeout_s)

    return asyncio.run(_bounded())
