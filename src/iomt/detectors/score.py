"""Benign-only anomaly score (protocol score.model), fitted per device.

The score never sees attack traffic. Input is the window feature matrix on any
feature subset; output is one number per window, higher = less like benign.
Detectors work on block scores: the mean window score over each block.
"""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest

from iomt.streams.load import block_means, transform


class BenignScore:
    def __init__(self, model: str = "isolation_forest", seed: int = 0, n_estimators: int = 200):
        if model != "isolation_forest":
            raise ValueError(f"score model '{model}' not implemented")
        self.model, self.seed, self.n_estimators = model, seed, n_estimators

    def fit(self, X: np.ndarray) -> "BenignScore":
        Z = transform(np.asarray(X, float))
        self.med = np.median(Z, axis=0)
        q75, q25 = np.percentile(Z, [75, 25], axis=0)
        iqr = q75 - q25
        sd = Z.std(axis=0)
        self.scale = np.where(iqr > 0, iqr, np.where(sd > 0, sd, 1.0))
        self.clf = IsolationForest(n_estimators=self.n_estimators, random_state=self.seed,
                                   n_jobs=-1).fit((Z - self.med) / self.scale)
        return self

    def window_scores(self, X: np.ndarray) -> np.ndarray:
        Z = (transform(np.asarray(X, float)) - self.med) / self.scale
        return -self.clf.score_samples(Z)

    def block_scores(self, X: np.ndarray, block_windows: int) -> np.ndarray:
        return block_means(self.window_scores(X), block_windows)
