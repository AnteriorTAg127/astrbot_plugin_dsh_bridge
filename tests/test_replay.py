"""Unit tests for the 64-bit replay window (protocol §5.4)."""

from __future__ import annotations

import pytest

from bridge.errors import ERR_REPLAY_DETECTED, ERR_REPLAY_OUT_OF_WINDOW, BridgeError
from bridge.replay import WINDOW_SIZE, ReplayWindow


def test_in_order_acceptance_advances_expected() -> None:
    """Sequential frames advance ``expected`` one slot at a time."""
    window = ReplayWindow()
    for seq in range(10):
        window.accept(seq)
        assert window.expected == seq + 1


def test_duplicate_is_fatal_replay() -> None:
    """Re-sending an already accepted seq is ``replay_detected``."""
    window = ReplayWindow()
    window.accept(0)
    window.accept(1)
    with pytest.raises(BridgeError) as excinfo:
        window.accept(0)
    assert excinfo.value.code == ERR_REPLAY_DETECTED
    assert excinfo.value.fatal


def test_reordering_inside_window_is_accepted_once() -> None:
    """Out-of-order frames inside the window are accepted exactly once."""
    window = ReplayWindow()
    window.accept(2)
    assert window.expected == 3
    window.accept(1)
    window.accept(0)
    assert window.expected == 3
    for seq in (0, 1, 2):
        with pytest.raises(BridgeError) as excinfo:
            window.accept(seq)
        assert excinfo.value.code == ERR_REPLAY_DETECTED


def test_far_future_seq_is_out_of_window() -> None:
    """``seq >= expected + WINDOW_SIZE`` is rejected, never silently skipped."""
    window = ReplayWindow()
    window.accept(0)
    expected = window.expected
    # The last slot that still fits in the window is accepted.
    window.accept(expected + WINDOW_SIZE - 1)
    assert window.expected == expected + WINDOW_SIZE

    fresh = ReplayWindow()
    fresh.accept(0)
    with pytest.raises(BridgeError) as excinfo:
        fresh.accept(fresh.expected + WINDOW_SIZE)
    assert excinfo.value.code == ERR_REPLAY_OUT_OF_WINDOW
    assert fresh.expected == 1


def test_slid_out_past_seq_is_out_of_window() -> None:
    """A seq that already fell out of the bitmap is out of window, not replay."""
    window = ReplayWindow()
    for seq in range(WINDOW_SIZE + 5):
        window.accept(seq)
    with pytest.raises(BridgeError) as excinfo:
        window.accept(0)
    assert excinfo.value.code == ERR_REPLAY_OUT_OF_WINDOW


def test_window_boundary_slots_are_accepted() -> None:
    """The last slot inside the window is accepted; the next one is not."""
    window = ReplayWindow()
    window.accept(0)
    window.accept(WINDOW_SIZE - 1)
    assert window.expected == WINDOW_SIZE
    with pytest.raises(BridgeError):
        window.accept(WINDOW_SIZE - 1)


def test_invalid_seq_types_are_rejected() -> None:
    """Negative, boolean and non-integer seqs never enter the window."""
    window = ReplayWindow()
    for bad in (-1, True, "1", None):
        with pytest.raises(BridgeError):
            window.accept(bad)


def test_would_accept_does_not_mutate() -> None:
    """The dry-run helper leaves the window untouched."""
    window = ReplayWindow()
    window.accept(0)
    assert window.would_accept(1)
    assert window.would_accept(0) is False
    assert window.expected == 1
    window.accept(1)
    assert window.expected == 2


def test_start_offset_is_honoured() -> None:
    """A window started at N only rejects seqs that are already outside the window."""
    window = ReplayWindow(start=5)
    # 4 is one slot behind the start, so it is still inside the window.
    window.accept(4)
    assert window.expected == 5
    with pytest.raises(BridgeError) as excinfo:
        window.accept(4)
    assert excinfo.value.code == ERR_REPLAY_DETECTED
    window.accept(5)
    assert window.expected == 6
