"""Threshold calibration to a nominal average run length on held-out benign blocks.

The tuning split is usually too short to observe many false alarms at the
nominal ARL, so it is lengthened with a moving-block bootstrap (blocks of
``mbb_len`` consecutive block scores, drawn within one capture segment, which
keeps short-range dependence). The threshold is the smallest h whose renewal
ARL on that long sequence reaches the target, found by bisection.

A second method, ``contiguous``, skips the bootstrap: it runs the detector on
the tuning blocks in their real order (restarting at each capture segment) and
takes the smallest h whose observed ARL reaches the target. It keeps all of the
dependence in the data but sees fewer alarms. ``calibrate_with`` dispatches on
the method named in protocol ``detectors.calibration``.

All three detectors go through this same routine, so they are matched on
false-alarm rate. The run-length audit (validity/run_length.py) then checks
the calibrated threshold on a separate audit split it never saw.
"""
from __future__ import annotations

import numpy as np

from iomt.detectors.base import Detector

BRACKETS = {"conformal_e": (1.0, 1e9, True), "cusum": (0.0, 200.0, False),
            "threshold": (-5.0, 60.0, False)}


def moving_block_bootstrap(segments: list[np.ndarray], length: int, mbb_len: int,
                           rng: np.random.Generator) -> np.ndarray:
    segs = [np.asarray(s, float) for s in segments if len(s) >= mbb_len]
    if not segs:
        raise ValueError("no tuning segment is as long as one bootstrap block")
    sizes = np.array([len(s) - mbb_len + 1 for s in segs], float)
    probs = sizes / sizes.sum()
    out, n = [], 0
    while n < length:
        k = rng.choice(len(segs), p=probs)
        i = rng.integers(0, len(segs[k]) - mbb_len + 1)
        out.append(segs[k][i:i + mbb_len])
        n += mbb_len
    return np.concatenate(out)[:length]


def arl_at(det: Detector, inputs, h, n, starts=()):
    a = len(det.alarms(inputs, h, starts))
    return n / a if a else float("inf")


def calibrate(det: Detector, tune_segments: list[np.ndarray], target_arl: float,
              rng: np.random.Generator, *, mbb_len: int = 10, min_len: int = 5000,
              factor: float = 50.0, max_len: int = 400_000, iters: int = 40) -> dict:
    length = int(min(max_len, max(min_len, factor * target_arl)))
    seq = moving_block_bootstrap(tune_segments, length, mbb_len, rng)
    inputs = det.prepare(seq, rng)
    lo, hi, logscale = BRACKETS[det.name]
    arl_hi = arl_at(det, inputs, hi, length)
    if arl_hi < target_arl:
        return {"h": hi, "arl_tune": arl_hi, "bootstrap_len": length, "reached": False}
    for _ in range(iters):
        mid = np.sqrt(lo * hi) if logscale else 0.5 * (lo + hi)
        if arl_at(det, inputs, mid, length) >= target_arl:
            hi = mid
        else:
            lo = mid
        if (logscale and hi / lo < 1.001) or (not logscale and hi - lo < 1e-3):
            break
    return {"h": float(hi), "arl_tune": arl_at(det, inputs, hi, length),
            "bootstrap_len": length, "reached": True}


def _bisect(det: Detector, inputs, n: int, target_arl: float, starts, iters: int):
    lo, hi, logscale = BRACKETS[det.name]
    arl_hi = arl_at(det, inputs, hi, n, starts)
    if arl_hi < target_arl:
        return hi, arl_hi, False
    for _ in range(iters):
        mid = np.sqrt(lo * hi) if logscale else 0.5 * (lo + hi)
        if arl_at(det, inputs, mid, n, starts) >= target_arl:
            hi = mid
        else:
            lo = mid
        if (logscale and hi / lo < 1.001) or (not logscale and hi - lo < 1e-3):
            break
    return float(hi), arl_at(det, inputs, hi, n, starts), True


def calibrate_contiguous(det: Detector, tune_segments: list[np.ndarray], target_arl: float,
                         rng: np.random.Generator, *, iters: int = 40) -> dict:
    """Calibrate on the tuning blocks in real order, one segment after another."""
    segs = [np.asarray(s, float) for s in tune_segments if len(s)]
    if not segs:
        raise ValueError("no tuning blocks")
    seq = np.concatenate(segs)
    starts = np.cumsum([0] + [len(s) for s in segs])[:-1]
    inputs = det.prepare(seq, rng)
    h, arl, reached = _bisect(det, inputs, len(seq), target_arl, starts, iters)
    n_al = len(det.alarms(inputs, h, starts))
    return {"h": h, "arl_tune": arl, "tune_blocks": int(len(seq)), "tune_alarms": int(n_al),
            "reached": reached}


def calibrate_with(det: Detector, tune_segments: list[np.ndarray], target_arl: float,
                   rng: np.random.Generator, method: str = "mbb", mbb_len_blocks: int = 10) -> dict:
    """Calibrate with a method from protocol detectors.calibration.candidates."""
    if method == "mbb":
        out = calibrate(det, tune_segments, target_arl, rng, mbb_len=int(mbb_len_blocks))
    elif method == "contiguous":
        out = calibrate_contiguous(det, tune_segments, target_arl, rng)
    else:
        raise ValueError(f"unknown calibration method {method!r}")
    out["method"] = method
    out["mbb_len_blocks"] = int(mbb_len_blocks) if method == "mbb" else None
    return out


def candidate_label(c: dict) -> str:
    return f"mbb{int(c['mbb_len_blocks'])}" if c["method"] == "mbb" else c["method"]
