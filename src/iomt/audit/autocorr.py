"""Gate item 4: within-stream autocorrelation and the block size.

For each usable device, on its benign streams (one per capture), group the
windows into non-overlapping blocks of b windows and average the features in
each block. For every b on protocol validity.block_grid_windows, compute the
lag-1 autocorrelation of the block means for each non-constant feature and
take the mean absolute value across features (pooled over captures, weighted
by block count). A device's block size is the smallest b with mean |ACF| below
validity.acf_threshold. The study uses one block size: the largest of the
per-device choices, so every device is below threshold at it.

Detection delay grows by about one block, so the smallest b that works is
chosen. Per-device curves are kept for review.

Owner note: ARCHITECTURE.md lists audit/ as B's, but the 21 Oct split gives
gate items 1-5 to A. Fix CODEOWNERS at the freeze.

Output: results/audit/block_size.json (ARCHITECTURE.md 4.3: the only place
detectors read the block size from).
"""
from __future__ import annotations

import argparse
import json

import numpy as np

from iomt import protocol as P
from iomt.contracts import features_for
from iomt.paths import AUDIT, ensure
from iomt.streams.load import benign_segments, block_means, transform

MIN_BLOCKS = 20


def acf1(x: np.ndarray) -> np.ndarray:
    """Lag-1 autocorrelation per column; NaN for constant columns."""
    x = x - x.mean(axis=0)
    den = (x * x).sum(axis=0)
    num = (x[1:] * x[:-1]).sum(axis=0)
    with np.errstate(invalid="ignore", divide="ignore"):
        r = np.where(den > 0, num / np.where(den > 0, den, 1), np.nan)
    return r


def device_curve(segments, features, grid):
    curve = {}
    for b in grid:
        vals, weights = [], []
        for df in segments:
            X = transform(df[features].to_numpy(dtype=float))
            B = block_means(X, b)
            if len(B) < MIN_BLOCKS:
                continue
            r = acf1(B)
            r = r[np.isfinite(r)]
            if len(r) == 0:
                continue
            vals.append(float(np.mean(np.abs(r))))
            weights.append(len(B))
        curve[b] = (float(np.average(vals, weights=weights)), int(sum(weights))) if vals else (None, 0)
    return curve


def run(cfg):
    features = features_for(cfg)
    thr = float(P.require(cfg, "validity.acf_threshold"))
    grid = [int(b) for b in P.require(cfg, "validity.block_grid_windows")]
    W = float(P.require(cfg, "streams.window_seconds"))
    segs = benign_segments()
    per_device, failing = {}, []
    for dev, s in sorted(segs.items()):
        curve = device_curve(s, features, grid)
        ok = [b for b in grid if curve[b][0] is not None and curve[b][0] < thr]
        chosen = min(ok) if ok else None
        per_device[dev] = {
            "chosen_block_windows": chosen,
            "mean_abs_acf_lag1": {str(b): curve[b][0] for b in grid},
            "n_blocks": {str(b): curve[b][1] for b in grid},
        }
        if chosen is None:
            failing.append(dev)
    chosen_all = [v["chosen_block_windows"] for v in per_device.values() if v["chosen_block_windows"]]
    block = max(chosen_all) if chosen_all else None
    at_block = {d: (v["mean_abs_acf_lag1"].get(str(block)) if block else None) for d, v in per_device.items()}
    above = [d for d, a in at_block.items() if a is None or a >= thr]
    return {
        "protocol_sha256": P.sha256(),
        "feature_set": P.get(cfg, "feature_set", "ciciomt39"),
        "window_seconds": W,
        "acf_threshold": thr,
        "lag": "1 block (lag-1 ACF of block means)",
        "block_windows": block,
        "block_seconds": block * W if block else None,
        "mean_abs_acf_at_block": at_block,
        "devices_above_threshold_at_block": above,
        "devices_without_any_block": failing,
        "per_device": per_device,
    }


def main(argv=None):
    argparse.ArgumentParser(description="Autocorrelation and block size (gate 4)").parse_args(argv)
    cfg = P.load()
    rep = run(cfg)
    ensure(AUDIT)
    with open(AUDIT / "block_size.json", "w", encoding="utf-8") as f:
        json.dump(rep, f, indent=1)
    for d, v in rep["per_device"].items():
        print(f"{d:28s} chosen b={v['chosen_block_windows']}  "
              + " ".join(f"{b}:{a:.2f}" if a is not None else f"{b}:-" for b, a in v["mean_abs_acf_lag1"].items()))
    print(f"\nblock size: {rep['block_windows']} windows ({rep['block_seconds']} s); "
          f"devices above threshold at it: {rep['devices_above_threshold_at_block']}; "
          f"devices with no block in the grid: {rep['devices_without_any_block']}")


if __name__ == "__main__":
    main()
