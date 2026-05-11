"""Keystroke dynamics.

This is the small slice of cybersecurity that crosses into biometrics:
how a user types (rhythm, hold duration, gap between keys) is surprisingly
unique. Continuous-authentication products use it to detect when an attacker
with valid credentials starts using a session.

We extract two primary features from a stream of press/release events:

    dwell_time  = release_ts - press_ts        (how long a key is held)
    flight_time = press_ts(n+1) - release_ts(n) (gap between successive keys)

And derive:
    rhythm_sigma = stdev of inter-press intervals  (typing consistency)

These are the same features Coron-style continuous-auth papers use.
"""
from __future__ import annotations

import statistics
from collections import deque
from dataclasses import dataclass
from typing import Iterable

NS_PER_MS = 1_000_000


@dataclass
class DynamicsSnapshot:
    n_keys: int
    mean_dwell_ms: float
    mean_flight_ms: float
    rhythm_sigma_ms: float

    def to_dict(self) -> dict:
        return {
            "n_keys": self.n_keys,
            "mean_dwell_ms": round(self.mean_dwell_ms, 2),
            "mean_flight_ms": round(self.mean_flight_ms, 2),
            "rhythm_sigma_ms": round(self.rhythm_sigma_ms, 2),
        }


class DynamicsExtractor:
    """Rolling-window extractor. Feed it KeyEvent dicts in order."""

    def __init__(self, window: int = 50) -> None:
        self._window = window
        # Buffers hold (key, ts_ns)
        self._pending_press: dict[str, int] = {}
        self._dwells: deque[float] = deque(maxlen=window)
        self._flights: deque[float] = deque(maxlen=window)
        self._press_times: deque[int] = deque(maxlen=window)
        self._last_release_ns: int | None = None

    def feed(self, event: dict) -> None:
        key = event["key"]
        ts = event["ts_ns"]
        kind = event["kind"]

        if kind == "press":
            self._pending_press[key] = ts
            if self._last_release_ns is not None:
                self._flights.append((ts - self._last_release_ns) / NS_PER_MS)
            self._press_times.append(ts)
        elif kind == "release":
            if (press_ts := self._pending_press.pop(key, None)) is not None:
                self._dwells.append((ts - press_ts) / NS_PER_MS)
            self._last_release_ns = ts

    def snapshot(self) -> DynamicsSnapshot:
        # stdev() needs >=2 samples
        intervals = []
        prev = None
        for t in self._press_times:
            if prev is not None:
                intervals.append((t - prev) / NS_PER_MS)
            prev = t

        return DynamicsSnapshot(
            n_keys=len(self._press_times),
            mean_dwell_ms=statistics.fmean(self._dwells) if self._dwells else 0.0,
            mean_flight_ms=statistics.fmean(self._flights) if self._flights else 0.0,
            rhythm_sigma_ms=statistics.stdev(intervals) if len(intervals) >= 2 else 0.0,
        )

    # Convenience for offline analysis of a full log
    @classmethod
    def from_events(cls, events: Iterable[dict], window: int = 10_000) -> DynamicsSnapshot:
        ex = cls(window=window)
        for e in events:
            ex.feed(e)
        return ex.snapshot()
