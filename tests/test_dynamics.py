"""Tests for keystroke dynamics."""
from keytrace.analytics.dynamics import DynamicsExtractor


def _event(kind: str, key: str, ts_ns: int) -> dict:
    return {
        "kind": kind,
        "key": key,
        "ts_ns": ts_ns,
        "wall_iso": "",
        "window_title": "",
        "window_process": "",
    }


def test_dwell_is_release_minus_press():
    ex = DynamicsExtractor(window=10)
    ex.feed(_event("press", "a", 0))
    ex.feed(_event("release", "a", 50_000_000))   # 50ms
    snap = ex.snapshot()
    assert abs(snap.mean_dwell_ms - 50.0) < 0.1


def test_flight_is_press_minus_previous_release():
    ex = DynamicsExtractor(window=10)
    ex.feed(_event("press", "a", 0))
    ex.feed(_event("release", "a", 50_000_000))
    ex.feed(_event("press", "b", 100_000_000))     # 50ms after release
    ex.feed(_event("release", "b", 130_000_000))
    snap = ex.snapshot()
    assert abs(snap.mean_flight_ms - 50.0) < 0.1


def test_n_keys_counts_presses():
    ex = DynamicsExtractor(window=10)
    for i, k in enumerate("hello"):
        ex.feed(_event("press", k, i * 100_000_000))
        ex.feed(_event("release", k, i * 100_000_000 + 40_000_000))
    snap = ex.snapshot()
    assert snap.n_keys == 5


def test_window_caps_buffer():
    ex = DynamicsExtractor(window=3)
    for i in range(10):
        ex.feed(_event("press", "x", i * 1_000_000))
        ex.feed(_event("release", "x", i * 1_000_000 + 100_000))
    snap = ex.snapshot()
    # Only last 3 presses tracked
    assert snap.n_keys == 3
