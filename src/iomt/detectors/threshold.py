"""Fixed threshold on the standardised block score (per-block baseline)."""
from __future__ import annotations

import numpy as np

from iomt.detectors.base import Detector


class Threshold(Detector):
    name = "threshold"

    def fit_reference(self, ref_scores):
        r = np.asarray(ref_scores, float)
        self.mu = float(r.mean())
        self.sigma = float(r.std()) or 1.0
        return self

    def prepare(self, scores, rng):
        return (np.asarray(scores, float) - self.mu) / self.sigma

    def alarms(self, z, h, starts=()):
        return np.flatnonzero(np.asarray(z) >= h).astype(np.int64)
