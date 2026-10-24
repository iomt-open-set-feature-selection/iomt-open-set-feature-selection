"""Online conformal e-detector (Bhattacharyya & Ramdas, arXiv 2609.27179, 2026).

Conformal p-values. The reference bag starts with held-out benign block
scores and grows with every observed block (it is never reset). For a new
score s_t with bag B (including s_t):
    p_t = ( #{b in B : b > s_t} + U * #{b in B : b = s_t} ) / |B|,  U ~ Uniform(0,1)
Under exchangeability (no change), p_1, p_2, ... are i.i.d. Uniform(0,1).
High anomaly score -> small p.

Betting. f_theta(p) = theta * p^(theta - 1), theta in the protocol grid,
uniform prior over the grid. Each f_theta integrates to 1 on [0,1], so f_theta(p_t)
is an e-value under the null.

Statistic. The paper's ARL-optimal detector sums mixture martingales started
at every candidate change time k, shifted by rho:
    S_t = sum_{k<=t} [ rho + (1 - rho) * mean_theta prod_{j=k..t} f_theta(p_j) ]
Per theta the inner sum is a Shiryaev-Roberts recursion
    A_t(theta) = f_theta(p_t) * (A_{t-1}(theta) + 1),
so S_t = rho * t + (1 - rho) * mean_theta A_t(theta), O(|theta grid|) per block.
Alarm when S_t >= gamma. Under exchangeability, gamma <= ARL <= gamma / rho.

Restarting the martingales at every candidate time (instead of one martingale
started at time 1, as in Vovk's CUSUM/SR conformal martingales) is what
removes the sqrt(ARL) delay of the older constructions.

Under real (dependent) traffic the guarantee does not hold exactly. That is
why windows are blocked and why the run length is audited (gate item 5).
"""
from __future__ import annotations

import bisect

import numpy as np

from iomt.detectors.base import Detector


class ConformalE(Detector):
    name = "conformal_e"

    def __init__(self, thetas=(0.15, 0.30, 0.50, 0.75, 1.0), rho: float = 0.5):
        self.thetas = np.asarray(thetas, float)
        if not (0 < rho < 1):
            raise ValueError("rho must be in (0, 1)")
        self.rho = float(rho)
        self.ref: list[float] = []

    def fit_reference(self, ref_scores):
        self.ref = sorted(float(x) for x in ref_scores)
        return self

    def pvalues(self, scores, rng) -> np.ndarray:
        bag = list(self.ref)
        out = np.empty(len(scores))
        for i, s in enumerate(scores):
            s = float(s)
            lo = bisect.bisect_left(bag, s)
            hi = bisect.bisect_right(bag, s)
            n = len(bag) + 1
            greater = len(bag) - hi
            equal = hi - lo + 1
            out[i] = max((greater + rng.random() * equal) / n, 1e-300)
            bag.insert(hi, s)
        return out

    def prepare(self, scores, rng):
        p = self.pvalues(scores, rng)
        # f_theta(p_t) per block (rows) and theta (columns).
        return self.thetas[None, :] * p[:, None] ** (self.thetas[None, :] - 1.0)

    def statistic_path(self, F: np.ndarray, starts=()) -> np.ndarray:
        """S_t without renewal (restarting only at segment starts)."""
        starts = set(int(s) for s in starts)
        A = np.zeros(F.shape[1])
        t = 0
        S = np.empty(len(F))
        for i in range(len(F)):
            if i in starts:
                A[:] = 0.0
                t = 0
            A = F[i] * (A + 1.0)
            t += 1
            S[i] = self.rho * t + (1.0 - self.rho) * A.mean()
        return S

    def alarms(self, F, h, starts=()):
        starts = set(int(s) for s in starts)
        rho, one_m = self.rho, 1.0 - self.rho
        m = F.shape[1]
        rows = F.tolist()
        A = [0.0] * m
        t = 0
        out = []
        for i, f in enumerate(rows):
            if i in starts:
                A = [0.0] * m
                t = 0
            A = [fi * (ai + 1.0) for fi, ai in zip(f, A)]
            t += 1
            if rho * t + one_m * (sum(A) / m) >= h:
                out.append(i)
                A = [0.0] * m
                t = 0
        return np.asarray(out, dtype=np.int64)

    def theory_threshold(self, gamma):
        return float(gamma)
