"""Transport selection, fallback and diagnostics (§7.5, §7.6).

Policy:

1. Prefer ``conn_transport``; on failure walk ``conn_transport_fallback`` in order.
2. Every switch records ``transport_switched{from,to,reason}`` for the status page.
3. A carrier that reports itself degraded **at runtime** (webhook reverse probes
   failing, §7.3 rule 6) is dropped and the configured fallbacks are tried in
   order; the preferred carrier is retried every five minutes afterwards
   (§7.5 rule 3) so a temporary outage does not degrade the link forever.
4. When nothing is reachable, report a readable diagnosis and stay ``disconnected``
   rather than retrying in a tight loop (§7.5 rule 4); retries back off
   exponentially up to ``reconnect_max_backoff``.

Failure classes drive the retry discipline (§7.6): network/server errors back off,
security and protocol errors do not silently downgrade, and configuration errors
stop at ``config_error``.

Carrier identity and wiring contract:
    The carrier's own state is read from the production objects — ``alive()`` and,
    when the carrier has one, ``degraded()`` — never inferred from a state string.
    Every ``start()`` gets a per-activation hook set whose ``on_state`` is tagged
    with the transport instance, so a late event from an already replaced carrier
    can never move the manager.

    ``on_transport(transport)`` is called once per **activation**, before that
    carrier is started, and the composition root is expected to bind a *fresh*
    session (new nonce/``sid``, new keys) to it there: the protocol requires the
    re-handshake after a switch to use a new session (§4, §7.5). ``on_release``
    is called with the outgoing transport immediately before it is stopped, which
    is where the composition root closes the old session. See
    ``开发/v0.1/test/fallback-runtime-fix.md`` for the remaining ``main.py``
    wiring that is *not* done here.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Awaitable, Callable
from dataclasses import replace
from typing import Any

from astrbot.api import logger

from ..constants import (
    TRANSPORT_WEBHOOK,
    TRANSPORT_WS,
    TRANSPORT_LONGPOLl,
)
from ..errors import (
    ERR_CONFIG_INVALID,
    ERR_NOT_READY,
    ERR_PSK_NOT_CONFIGURED,
    BridgeError,
)
from .base import Transport, TransportHooks
from .longpoll import LongPollTransport
from .webhook import WebhookTransport
from .ws import WsTransport

#: Security-class codes: never downgraded, always surfaced (§7.6).
SECURITY_CODES = frozenset(
    {
        "psk_mismatch",
        "th_mismatch",
        "aead_failed",
        "replay_detected",
        "replay_out_of_window",
        "stale_session",
        "auth_required",
        "subprotocol_mismatch",
        "bad_handshake_encoding",
        "hello_replay",
        "handshake_reuse",
        "dual_writer",
    }
)

#: Configuration-class codes: stop instead of retrying (§7.6).
CONFIG_CODES = frozenset(
    {"psk_not_configured", "config_invalid", "unknown_conn", "bad_side"}
)

#: How often an otherwise healthy link is re-examined (cheap, no timers kept).
IDLE_POLL_S = 5.0

#: Failed (re-)handshakes on one carrier before it is torn down and rebuilt.
HANDSHAKE_REBUILD_AFTER = 3


def build_transport(name: str, cfg: Any) -> Transport:
    """Instantiate one carrier from configuration.

    Args:
        name: ``ws`` / ``webhook`` / ``longpoll``.
        cfg: Session configuration.

    Returns:
        The transport instance.

    Raises:
        BridgeError: ``config_invalid`` for an unknown carrier name.
    """
    role = "listen" if getattr(cfg, "mode", "connect") == "listen" else "connect"
    if name == TRANSPORT_WS:
        return WsTransport(
            role=role,
            conn=cfg.conn,
            max_frame_bytes=int(getattr(cfg, "max_frame_bytes", 2_097_152)),
            handshake_timeout_s=float(getattr(cfg, "handshake_timeout_s", 10.0)),
            tls_cert_path=getattr(cfg, "tls_cert_path", ""),
            tls_key_path=getattr(cfg, "tls_key_path", ""),
            tls_fingerprint=getattr(cfg, "tls_fingerprint", ""),
        )
    if name == TRANSPORT_WEBHOOK:
        return WebhookTransport(
            role=role,
            conn=cfg.conn,
            side=cfg.side,
            psk_id=cfg.psk_id,
            psk_secret=cfg.psk_secret,
            heartbeat_s=int(getattr(cfg, "heartbeat_s", 30)),
        )
    if name == TRANSPORT_LONGPOLl:
        return LongPollTransport(
            role=role,
            conn=cfg.conn,
            side=cfg.side,
            psk_id=cfg.psk_id,
            psk_secret=cfg.psk_secret,
            wait_s=int(getattr(cfg, "poll_wait_s", 25)),
        )
    raise BridgeError(ERR_CONFIG_INVALID, details={"transport": name})


class TransportManager:
    """Own the carrier lifecycle and the fallback ladder."""

    def __init__(
        self,
        cfg: Any,
        hooks: TransportHooks,
        *,
        preferred: str = TRANSPORT_WS,
        fallbacks: list[str] | None = None,
        attempt_preferred_after_s: float = 300.0,
        idle_poll_s: float = IDLE_POLL_S,
        on_transport: Callable[[Any], Awaitable[None]] | None = None,
        on_release: Callable[[Any], Awaitable[None]] | None = None,
        on_state: Callable[[str, str], None] | None = None,
    ) -> None:
        """Create the manager.

        Args:
            cfg: Session configuration (``mode``/``conn``/``side``/PSK/... ).
            hooks: Inbound callbacks shared by every carrier.
            preferred: ``conn_transport``.
            fallbacks: ``conn_transport_fallback`` order.
            attempt_preferred_after_s: Retry interval for the preferred carrier
                after a fallback switch (§7.5 rule 3, five minutes in production).
            idle_poll_s: How often a healthy link is re-examined for carrier state.
            on_transport: Coroutine invoked with each newly built transport so the
                composition root can bind a fresh session to it before it starts.
            on_release: Coroutine invoked with the outgoing transport right before
                it is stopped, so the composition root can close its session.
            on_state: State observer for the status page.
        """
        self._cfg = cfg
        self._hooks = hooks
        self._preferred = preferred
        self._fallbacks = list(fallbacks or [])
        self._retry_preferred_after = float(attempt_preferred_after_s)
        self._idle_poll = float(idle_poll_s)
        self._on_transport = on_transport
        self._on_release = on_release
        self._on_state = on_state

        self._current: Transport | None = None
        self._current_name: str = ""
        self._history: list[dict] = []
        self._last_error: str = ""
        self._tried: list[str] = []
        self._degraded = False
        self._failures = 0
        self._attempts = 0
        self._connected = False
        self._handshake_failures = 0
        self._preferred_due = 0.0
        self._closing = False
        self._wake = asyncio.Event()

    # -- accessors ---------------------------------------------------------------------

    def current(self) -> str:
        """Return the active carrier name (empty when none)."""
        return self._current_name

    def transport(self) -> Transport | None:
        """Return the active transport instance."""
        return self._current

    def history(self) -> list[dict]:
        """Return the switch history for the status page (§7.5 rule 2)."""
        return list(self._history)

    def carrier_degraded(self) -> bool:
        """Return whether the *production* carrier reports itself degraded.

        The answer comes from the carrier's own ``degraded()`` method (webhook
        reverse-probe state, §7.3 rule 6). Carriers without that method are never
        considered degraded — the manager does not guess from state strings.

        Returns:
            ``True`` when the active carrier says it is degraded.
        """
        transport = self._current
        if transport is None:
            return False
        probe = getattr(transport, "degraded", None)
        if not callable(probe):
            return False
        with contextlib.suppress(Exception):
            return bool(probe())
        return False

    def diagnostics(self) -> dict:
        """Return a readable diagnosis of the link (§7.5 rule 4).

        Returns:
            ``{"preferred", "current", "fallbacks", "history", "last_error",
            "tried", "degraded", "reachable", "carrier", "attempts", "stopped",
            "retry_preferred_after_s", "carrier_degraded"}``.
        """
        return {
            "preferred": self._preferred,
            "current": self._current_name,
            "fallbacks": self._fallbacks,
            "history": list(self._history),
            "last_error": self._last_error,
            "tried": list(self._tried),
            "degraded": self._degraded,
            "reachable": bool(self._current and self._current.alive()),
            "carrier": self._current.diagnostics() if self._current else {},
            "carrier_degraded": self.carrier_degraded(),
            "attempts": self._attempts,
            "stopped": self._closing,
            "retry_preferred_after_s": self._retry_preferred_after,
        }

    # -- lifecycle ---------------------------------------------------------------------

    def _record_switch(self, source: str, target: str, reason: str) -> None:
        """Record one transport switch in history and the log (§7.5 rule 2).

        Args:
            source: Previous carrier.
            target: New carrier.
            reason: Short English reason.
        """
        entry = {
            "from": source,
            "to": target,
            "reason": reason,
            "at": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
            + f".{int(time.time() * 1000) % 1000:03d}Z",
        }
        self._history.append(entry)
        logger.warning(
            "bridge transport_switched conn=%s from=%s to=%s reason=%s",
            self._cfg.conn,
            source or "-",
            target,
            reason,
        )

    def _hooks_for(self, transport: Transport) -> TransportHooks:
        """Return the shared hooks with a carrier-tagged state observer.

        Args:
            transport: The carrier that will receive these hooks.

        Returns:
            A :class:`TransportHooks` copy whose ``on_state`` attributes events to
            ``transport``, so a late event from a replaced carrier cannot move the
            manager.
        """

        def on_state(state: str, reason: str) -> None:
            self._observe_carrier_state(transport, state, reason)

        return replace(self._hooks, on_state=on_state)

    def _observe_carrier_state(
        self, transport: Transport, state: str, reason: str
    ) -> None:
        """React to a carrier state event and forward it to the observers.

        Args:
            transport: Carrier that emitted the event.
            state: Carrier state (``ready`` / ``degraded`` / ``disconnected``).
            reason: Short English reason.
        """
        if transport is self._current:
            if state == "degraded":
                self._degraded = True
                self._wake.set()
            elif state == "ready" and not self.carrier_degraded():
                # Recovery is only ours to record; the carrier stays authoritative.
                self._degraded = self._current_name != self._preferred
                self._wake.set()
        for observer in (self._hooks.on_state, self._on_state):
            if observer is None:
                continue
            with contextlib.suppress(Exception):
                observer(state, reason)

    async def _activate(self, name: str) -> Transport:
        """Build and start one carrier, binding it to the session layer.

        The step is failure-atomic: a carrier that fails to start is stopped again
        before the error propagates, so a half-initialised carrier cannot keep a
        socket, a poll loop or a probe task alive.

        Args:
            name: Carrier name.

        Returns:
            The started transport.

        Raises:
            BridgeError: Any start failure.
        """
        self._attempts += 1
        transport = build_transport(name, self._cfg)
        if self._on_transport is not None:
            await self._on_transport(transport)
        try:
            await transport.start(self._cfg, self._hooks_for(transport))
        except BaseException:
            with contextlib.suppress(Exception):
                await transport.stop()
            raise
        return transport

    def _adopt(self, transport: Transport, name: str) -> None:
        """Make ``transport`` the active carrier.

        Args:
            transport: Started transport.
            name: Carrier name.
        """
        self._current = transport
        self._current_name = name
        self._connected = False
        self._handshake_failures = 0

    async def _release_current(self) -> bool:
        """Release the active transport, then stop it.

        ``on_release`` runs first so the composition root can close the session
        that used this carrier while the carrier is still the one the session
        holds. Stopping afterwards guarantees the sockets, poll loops, probe and
        flush tasks are gone before a new carrier binds the same port.

        Returns:
            ``True`` when a transport was released.
        """
        transport = self._current
        self._current = None
        self._current_name = ""
        self._connected = False
        self._handshake_failures = 0
        if transport is None:
            return False
        if self._on_release is not None:
            with contextlib.suppress(Exception):
                await self._on_release(transport)
        with contextlib.suppress(Exception):
            await transport.stop()
        return True

    def _ladder(self, *, include_preferred: bool, exclude: str = "") -> list[str]:
        """Return the carriers to try, in configuration order.

        Args:
            include_preferred: Append ``preferred`` after the fallbacks.
            exclude: Carrier to skip (the one that just failed, or the current).

        Returns:
            Deduplicated carrier names.
        """
        skip = {exclude, self._current_name}
        names: list[str] = []
        for name in self._fallbacks:
            if not name or name in skip or name == self._preferred or name in names:
                continue
            names.append(name)
        if include_preferred and self._preferred and self._preferred not in skip:
            if self._preferred not in names:
                names.append(self._preferred)
        return names

    async def bring_up(self) -> Transport:
        """Try the preferred carrier then the fallbacks in order (§7.5).

        The previous carrier is released *before* the ladder is walked: a listening
        carrier holds its port, so leaving it bound would make the replacement fail
        with ``address already in use`` and leave the session attached to a dead
        carrier.

        Returns:
            The first carrier that started.

        Raises:
            BridgeError: When every carrier failed; the error is the last failure.
        """
        if self._closing:
            raise BridgeError(ERR_NOT_READY, details={"reason": "stopped"})
        previous = self._current_name
        await self._release_current()
        # While a fallback switch is still inside its retry window, the preferred
        # carrier is known-bad: rebuilding must go straight to the fallbacks, or a
        # torn-down link would flap back onto the carrier that just failed.
        throttle = self._degraded and time.monotonic() < self._preferred_due
        if throttle and self._fallbacks:
            order = self._ladder(include_preferred=False)
        else:
            order = [
                self._preferred,
                *self._ladder(include_preferred=False, exclude=self._preferred),
            ]
        last_error: Exception | None = None
        self._tried = []
        for index, name in enumerate(order):
            self._tried.append(name)
            try:
                transport = await self._activate(name)
            except BridgeError as exc:
                last_error = exc
                self._last_error = exc.code
                if exc.code in CONFIG_CODES:
                    logger.error(
                        "bridge transport config error conn=%s carrier=%s code=%s",
                        self._cfg.conn,
                        name,
                        exc.code,
                    )
                    if self._on_state is not None:
                        self._on_state("config_error", exc.code)
                    raise
                logger.warning(
                    "bridge transport unavailable conn=%s carrier=%s code=%s",
                    self._cfg.conn,
                    name,
                    exc.code,
                )
                continue
            except Exception as exc:
                last_error = exc
                self._last_error = "internal_error"
                logger.warning(
                    "bridge transport start failed conn=%s carrier=%s error=%s",
                    self._cfg.conn,
                    name,
                    exc,
                )
                continue
            self._adopt(transport, name)
            on_fallback = name != self._preferred
            self._degraded = on_fallback
            self._preferred_due = (
                time.monotonic() + self._retry_preferred_after if on_fallback else 0.0
            )
            if previous != name:
                self._record_switch(previous, name, "bring_up")
            return transport
        if last_error is not None:
            raise (
                last_error
                if isinstance(last_error, BridgeError)
                else BridgeError(ERR_NOT_READY, details={"reason": "no_transport"})
            )
        raise BridgeError(
            ERR_CONFIG_INVALID, details={"reason": "no_transport_configured"}
        )

    async def _switch_to_fallback(self, reason: str) -> Transport | None:
        """Drop the degraded carrier and start the next configured fallback.

        Args:
            reason: Why the switch happened (``transport_degraded``).

        Returns:
            The newly active transport, or ``None`` when no fallback started.

        Raises:
            BridgeError: ``config_error`` class failures from a fallback.
        """
        failed = self._current_name
        await self._release_current()
        self._tried = []
        for name in self._ladder(include_preferred=False, exclude=failed):
            self._tried.append(name)
            try:
                transport = await self._activate(name)
            except BridgeError as exc:
                self._last_error = exc.code
                if exc.code in CONFIG_CODES:
                    logger.error(
                        "bridge fallback config error conn=%s carrier=%s code=%s",
                        self._cfg.conn,
                        name,
                        exc.code,
                    )
                    if self._on_state is not None:
                        self._on_state("config_error", exc.code)
                    raise
                logger.warning(
                    "bridge fallback unavailable conn=%s carrier=%s code=%s",
                    self._cfg.conn,
                    name,
                    exc.code,
                )
                continue
            except Exception as exc:
                self._last_error = "internal_error"
                logger.warning(
                    "bridge fallback start failed conn=%s carrier=%s error=%s",
                    self._cfg.conn,
                    name,
                    exc,
                )
                continue
            self._adopt(transport, name)
            self._degraded = True
            self._preferred_due = time.monotonic() + self._retry_preferred_after
            self._record_switch(failed, name, reason)
            return transport
        self._degraded = True
        self._preferred_due = time.monotonic() + self._retry_preferred_after
        return None

    async def fallback(self, reason: str) -> Transport:
        """Drop the active carrier and switch to the next working one (§7.3 rule 6).

        Args:
            reason: Why the switch happened (``transport_degraded`` / network error).

        Returns:
            The newly active transport.

        Raises:
            BridgeError: When no fallback carrier can start.
        """
        failed = self._current_name
        await self._release_current()
        self._tried = []
        last_error: Exception | None = None
        for name in self._ladder(include_preferred=True, exclude=failed):
            self._tried.append(name)
            try:
                transport = await self._activate(name)
            except BridgeError as exc:
                last_error = exc
                self._last_error = exc.code
                if exc.code in CONFIG_CODES:
                    if self._on_state is not None:
                        self._on_state("config_error", exc.code)
                    raise
                continue
            except Exception as exc:
                last_error = exc
                self._last_error = "internal_error"
                continue
            self._adopt(transport, name)
            self._degraded = True
            self._preferred_due = time.monotonic() + self._retry_preferred_after
            self._record_switch(failed, name, reason)
            return transport
        raise BridgeError(
            ERR_NOT_READY, details={"reason": "no_fallback"}
        ) from last_error

    async def try_restore_preferred(self) -> bool:
        """Attempt to return to the preferred carrier (§7.5 rule 3).

        The fallback keeps serving while the preferred carrier starts: only after
        the preferred carrier is up is the fallback released. A failed attempt
        re-binds the still-running fallback to the session so the live link is
        never left pointing at a dead carrier. The ``on_transport`` re-bind is
        skipped when the composition root holds one session for the whole
        connection (the temporary carrier only shadowed it, it was never stopped).

        Returns:
            ``True`` when the preferred carrier is now active.
        """
        if self._current_name == self._preferred:
            return True
        old_name = self._current_name
        try:
            transport = await self._activate(self._preferred)
        except Exception as exc:
            self._last_error = getattr(exc, "code", "internal_error")
            logger.info(
                "bridge preferred transport still unavailable conn=%s error=%s",
                self._cfg.conn,
                exc,
            )
            if self._current is not None and self._on_transport is not None:
                with contextlib.suppress(Exception):
                    await self._on_transport(self._current)
            self._preferred_due = time.monotonic() + self._retry_preferred_after
            return False
        await self._release_current()
        self._adopt(transport, self._preferred)
        self._degraded = False
        self._preferred_due = 0.0
        self._record_switch(old_name, self._preferred, "restored")
        return True

    async def _wait(self, delay: float) -> None:
        """Wait for ``delay`` seconds, waking early on a carrier event or stop.

        Args:
            delay: Maximum wait in seconds.
        """
        if self._closing:
            return
        try:
            await asyncio.wait_for(self._wake.wait(), timeout=max(0.0, delay))
            self._wake.clear()
        except TimeoutError:
            return

    async def run_forever(
        self, *, connect: Callable[[], Awaitable[None]] | None = None
    ) -> None:
        """Keep a carrier up, switch on degradation and restore the preferred one.

        The loop is event-driven: it wakes on a carrier state event and otherwise
        polls once per ``idle_poll_s``. Every wait is bounded and cancellable, so a
        degraded link that has no working fallback backs off instead of spinning,
        and ``stop()`` ends the loop without leaving a timer behind.

        Args:
            connect: Coroutine that performs the handshake over the active carrier.
                Called again after every switch, on a freshly activated carrier.
        """
        if self._closing:
            return
        # Production calls ``bring_up()`` + ``connect()`` before starting this loop
        # (``main.py::_run_connection``), so a carrier that is up *and not degraded*
        # at entry has already completed its handshake; connecting again would
        # restart the handshake on a live session. Everything the loop adopts itself
        # starts with ``_connected = False`` and is handshaken by the branch below.
        self._connected = (
            bool(self._current is not None and self._current.alive())
            and not self.carrier_degraded()
        )
        self._handshake_failures = 0
        backoff = 1.0
        max_backoff = float(getattr(self._cfg, "reconnect_max_backoff", 60))
        while not self._closing:
            try:
                # Degradation is checked first: a degraded carrier is not alive(),
                # so testing "needs a handshake" before this would keep reconnecting
                # onto the very carrier that was reported unusable.
                if self.carrier_degraded():
                    switched = await self._switch_to_fallback("transport_degraded")
                    if switched is not None:
                        backoff = 1.0
                        await self._wait(0)
                        continue
                    self._failures += 1
                    level = logger.warning if self._failures <= 10 else logger.debug
                    level(
                        "bridge no fallback carrier conn=%s tried=%s backoff=%.1f",
                        self._cfg.conn,
                        self._tried,
                        backoff,
                    )
                    await self._release_current()
                    await self._wait(backoff)
                    backoff = min(backoff * 2, max_backoff)
                    continue
                if self._current is None or not self._connected:
                    if self._current is None:
                        await self.bring_up()
                    if connect is not None:
                        await connect()
                    self._connected = True
                    self._handshake_failures = 0
                    backoff = 1.0
                    await self._wait(self._idle_poll)
                    continue
                if not self._current.alive() and self._cfg.mode != "listen":
                    # A connect-side link that died is relinked through the ladder
                    # after a backoff. A *listener* whose carrier is up but has no
                    # peer yet is not "down": re-binding it would drop the accepted
                    # socket and replay the old EADDRINUSE thrash.
                    self._failures += 1
                    level = logger.warning if self._failures <= 10 else logger.debug
                    level(
                        "bridge carrier down conn=%s carrier=%s failures=%s backoff=%.1f",
                        self._cfg.conn,
                        self._current_name,
                        self._failures,
                        backoff,
                    )
                    await self._release_current()
                    await self._wait(backoff)
                    backoff = min(backoff * 2, max_backoff)
                    continue
                if (
                    self._current_name != self._preferred
                    and time.monotonic() >= self._preferred_due
                ):
                    if await self.try_restore_preferred():
                        backoff = 1.0
                        await self._wait(0)
                        continue
                await self._wait(self._idle_poll)
            except asyncio.CancelledError:
                raise
            except BridgeError as exc:
                self._failures += 1
                self._last_error = exc.code
                if exc.code in CONFIG_CODES:
                    if self._on_state is not None:
                        self._on_state("config_error", exc.code)
                    logger.error(
                        "bridge staying in config_error conn=%s code=%s",
                        self._cfg.conn,
                        exc.code,
                    )
                    return
                level = logger.warning if self._failures <= 10 else logger.debug
                level(
                    "bridge reconnect scheduled conn=%s code=%s failures=%s backoff=%.1f",
                    self._cfg.conn,
                    exc.code,
                    self._failures,
                    backoff,
                )
                await self._mark_handshake_failed()
                await self._wait(backoff)
                backoff = min(backoff * 2, max_backoff)
            except Exception:
                logger.exception("bridge transport loop error conn=%s", self._cfg.conn)
                await self._mark_handshake_failed()
                await self._wait(backoff)
                backoff = min(backoff * 2, max_backoff)

    async def _mark_handshake_failed(self) -> None:
        """Record a failed (re-)handshake and decide how to recover.

        A handshake failure on a carrier that is still ``alive()`` (a listener, or a
        connect-side socket that stayed open) would otherwise never be retried: the
        loop would see a healthy carrier and idle with no session on it. The carrier
        is released after a few failed attempts so the ladder rebuilds it — and the
        session attached to it — from scratch.
        """
        self._connected = False
        self._handshake_failures += 1
        if self._handshake_failures < HANDSHAKE_REBUILD_AFTER:
            return
        logger.warning(
            "bridge carrier rebuilt after failed handshakes conn=%s carrier=%s attempts=%s",
            self._cfg.conn,
            self._current_name or "-",
            self._handshake_failures,
        )
        await self._release_current()

    async def stop(self) -> None:
        """Stop the loop and the active carrier.

        Safe to call more than once. After it returns, ``run_forever`` does not
        restart the link and no carrier task or timer remains.
        """
        self._closing = True
        self._wake.set()
        await self._release_current()
        self._degraded = False
        self._preferred_due = 0.0


def classify_failure(code: str) -> str:
    """Classify an error code for the retry discipline (§7.6).

    Args:
        code: §15 error code.

    Returns:
        ``security`` / ``config`` / ``protocol`` / ``server`` / ``network``.
    """
    if code in SECURITY_CODES:
        return "security"
    if code in CONFIG_CODES:
        return "config"
    if code in ("bad_version", "subprotocol_mismatch", "bad_caps"):
        return "protocol"
    if code in ("rate_limited", "server_busy", "draining", "not_ready"):
        return "server"
    return "network"


def should_retry(code: str) -> bool:
    """Whether a retry is allowed for this error class (§7.6).

    Args:
        code: §15 error code.

    Returns:
        ``False`` for configuration and protocol incompatibility errors.
    """
    return classify_failure(code) not in ("config", "protocol")


__all__ = [
    "CONFIG_CODES",
    "SECURITY_CODES",
    "TransportManager",
    "build_transport",
    "classify_failure",
    "should_retry",
    "ERR_PSK_NOT_CONFIGURED",
]
