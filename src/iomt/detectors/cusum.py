"""CUSUM on the standardised block score (classical baseline).

z_t = (s_t - mu) / sigma with mu, sigma from the benign reference blocks.
C_t = max(0, C_{t-1} + z_t - k); alarm when C_t >= h.
"""
from __future__ import annotations

import numpy as np

from iomt.detectors.base import Detector


class Cusum(Detector):
    name = "cusum"

    def __init__(self, drift_k: float = 0.5):
        self.k = float(drift_k)

    def fit_reference(self, ref_scores):
        r = np.asarray(ref_scores, float)
        self.mu = float(r.mean())
        self.sigma = float(r.std()) or 1.0
        return self

    def prepare(self, scores, rng):
        return (np.asarray(scores, float) - self.mu) / self.sigma - self.k

    def alarms(self, inc, h, starts=()):
        starts = set(int(s) for s in starts)
        C = 0.0
        out = []
        for i, x in enumerate(inc.tolist()):
            if i in starts:
                C = 0.0
            C = max(0.0, C + x)
            if C >= h:
                out.append(i)
                C = 0.0
        return np.asarray(out, dtype=np.int64)
