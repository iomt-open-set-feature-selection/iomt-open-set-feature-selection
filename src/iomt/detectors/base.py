"""Shared detector interface.

Every detector works on a sequence of block scores in two steps:

  inputs = det.prepare(scores, rng)      threshold-free preprocessing
  alarms = det.alarms(inputs, h, starts) alarm indices for threshold h

``alarms`` restarts the statistic after every alarm (renewal), and at every
index in ``starts`` (a new capture segment) without counting an alarm. That
lets calibration and the run-length audit try many thresholds on one
preprocessing pass.
"""
from __future__ import annotations

import numpy as np


class Detector:
    name = "base"

    def fit_reference(self, ref_scores: np.ndarray) -> "Detector":
        raise NotImplementedError

    def prepare(self, scores: np.ndarray, rng: np.random.Generator):
        raise NotImplementedError

    def alarms(self, inputs, h: float, starts=()) -> np.ndarray:
        raise NotImplementedError

    # A theoretical threshold for nominal ARL gamma, if the method has one.
    def theory_threshold(self, gamma: float):
        return None


def run_lengths(alarm_idx: np.ndarray, n: int, starts=()) -> dict:
    """Renewal ARL estimate: observed blocks / alarms (censored runs count as exposure)."""
    a = int(len(alarm_idx))
    return {"blocks": int(n), "alarms": a, "arl": (n / a) if a else float("inf")}
