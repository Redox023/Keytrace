"""Statistical anomaly detection over keystroke dynamics.

The idea: train a baseline (mean + stdev) on the user's first N keystrokes
or a separately provided baseline file. Then for each rolling snapshot,
compute z-scores on (mean_dwell, mean_flight, rhythm_sigma). If any |z|
exceeds the threshold, flag the window as anomalous.

This is a deliberately simple model — a one-week project should not pretend
to be a research-grade UEBA engine. The honest framing is: "demonstrates I
understand the baseline-and-deviation paradigm that real UEBA products use,
and can wire it into a live pipeline."
"""
from __future__ import annotations

import json
import math
import statistics
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable


@dataclass
class Baseline:
    n_samples: int
    dwell_mean: float
    dwell_sd: float
    flight_mean: float
    flight_sd: float
    rhythm_mean: float
    rhythm_sd: float

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Baseline":
        return cls(**d)

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path: Path) -> "Baseline":
        return cls.from_dict(json.loads(path.read_text()))


@dataclass
class AnomalyReport:
    is_anomalous: bool
    z_dwell: float
    z_flight: float
    z_rhythm: float
    reasons: list[str]


def train_baseline(snapshots: Iterable[dict]) -> Baseline:
    """Build a baseline from a sequence of DynamicsSnapshot.to_dict()s."""
    dwells, flights, rhythms = [], [], []
    n = 0
    for s in snapshots:
        # Skip degenerate snapshots
        if s.get("n_keys", 0) < 5:
            continue
        dwells.append(s["mean_dwell_ms"])
        flights.append(s["mean_flight_ms"])
        rhythms.append(s["rhythm_sigma_ms"])
        n += 1
    if n < 5:
        raise ValueError("baseline needs >= 5 valid snapshots")
    return Baseline(
        n_samples=n,
        dwell_mean=statistics.fmean(dwells),
        dwell_sd=statistics.stdev(dwells) if n >= 2 else 0.0,
        flight_mean=statistics.fmean(flights),
        flight_sd=statistics.stdev(flights) if n >= 2 else 0.0,
        rhythm_mean=statistics.fmean(rhythms),
        rhythm_sd=statistics.stdev(rhythms) if n >= 2 else 0.0,
    )


def _z(x: float, mu: float, sd: float) -> float:
    if sd <= 1e-9:
        return 0.0
    return (x - mu) / sd


def score(snapshot: dict, baseline: Baseline, *, z_threshold: float = 3.0) -> AnomalyReport:
    zd = _z(snapshot["mean_dwell_ms"], baseline.dwell_mean, baseline.dwell_sd)
    zf = _z(snapshot["mean_flight_ms"], baseline.flight_mean, baseline.flight_sd)
    zr = _z(snapshot["rhythm_sigma_ms"], baseline.rhythm_mean, baseline.rhythm_sd)
    reasons = []
    if abs(zd) > z_threshold:
        reasons.append(f"dwell z={zd:.2f}")
    if abs(zf) > z_threshold:
        reasons.append(f"flight z={zf:.2f}")
    if abs(zr) > z_threshold:
        reasons.append(f"rhythm z={zr:.2f}")
    return AnomalyReport(
        is_anomalous=bool(reasons),
        z_dwell=zd, z_flight=zf, z_rhythm=zr,
        reasons=reasons,
    )
