"""64-bit sliding replay window for inbound frame sequence numbers (§5.4).

Semantics (normative):
    * ``seq == expected`` — accept and advance.
    * ``expected < seq < expected + 64`` and bit clear — accept out of order
      (the HTTP batch path can deliver concurrently).
    * bit already set — ``replay_detected`` (fatal).
    * ``seq < expected`` and slid out of the window — ``replay_out_of_window``
      (fatal).
    * ``seq >= expected + 64`` — ``replay_out_of_window`` (fatal).

The window never tolerates duplicates; it only tolerates reordering.
"""

from __future__ import annotations

from .errors import ERR_REPLAY_DETECTED, ERR_REPLAY_OUT_OF_WINDOW, BridgeError

WINDOW_SIZE = 64


class ReplayWindow:
    """Track the highest accepted sequence plus a 64-bit presence bitmap."""

    __slots__ = ("_expected", "_bits")

    def __init__(self, start: int = 0) -> None:
        """Initialise the window.

        Args:
            start: First sequence number expected from the peer (``0`` for a fresh
                session, because ``auth``/``auth_ack`` occupy ``seq=0``).
        """
        self._expected = start
        self._bits = 0

    @property
    def expected(self) -> int:
        """The next in-order sequence number."""
        return self._expected

    def _shift(self, distance: int) -> None:
        """Advance the window by ``distance`` slots.

        Args:
            distance: Number of new slots to consume, at least 1.
        """
        if distance >= WINDOW_SIZE:
            self._bits = 0
        else:
            self._bits = (self._bits << distance) & ((1 << WINDOW_SIZE) - 1)
        self._expected += distance

    def accept(self, seq: int) -> None:
        """Validate and record an inbound ``seq``.

        Args:
            seq: Sequence number taken from the (plaintext) envelope.

        Raises:
            BridgeError: ``replay_detected`` for a duplicate inside the window,
                ``replay_out_of_window`` when the value is before or beyond it.
        """
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            raise BridgeError(ERR_REPLAY_OUT_OF_WINDOW)
        if seq < self._expected:
            offset = self._expected - seq
            if offset > WINDOW_SIZE:
                raise BridgeError(ERR_REPLAY_OUT_OF_WINDOW)
            bit = 1 << (offset - 1)
            if self._bits & bit:
                raise BridgeError(ERR_REPLAY_DETECTED)
            self._bits |= bit
            return
        distance = seq - self._expected
        if distance >= WINDOW_SIZE:
            raise BridgeError(ERR_REPLAY_OUT_OF_WINDOW)
        self._shift(distance + 1)
        # The just-accepted slot is the newest one; older slots stay recorded.
        self._bits |= 1

    def would_accept(self, seq: int) -> bool:
        """Check acceptance without mutating state (used by tests and diagnostics).

        Args:
            seq: Candidate sequence number.

        Returns:
            ``True`` when :meth:`accept` would succeed.
        """
        snapshot = (self._expected, self._bits)
        try:
            self.accept(seq)
        except BridgeError:
            return False
        finally:
            self._expected, self._bits = snapshot
        return True
