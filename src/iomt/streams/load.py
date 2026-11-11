"""Read window streams back from the manifest."""
from __future__ import annotations

import json
from collections import defaultdict

import numpy as np
import pandas as pd

from iomt import protocol as P
from iomt.paths import MANIFEST, PROCESSED

RAMP_BASE_CAPTURE = "attacks/train/Benign_train"


def manifest() -> dict:
    with open(MANIFEST, encoding="utf-8") as f:
        return json.load(f)


def reserved_windows(cfg) -> int:
    """Windows in the ramp base: attack_set.ramp_reserved_seconds on the stream's window grid."""
    return round(float(P.require(cfg, "attack_set.ramp_reserved_seconds"))
                 / float(P.require(cfg, "streams.window_seconds")))


def benign_segments(kind="benign") -> dict[str, list[pd.DataFrame]]:
    """device_id -> list of benign stream frames, one per capture, in capture-time order.

    The last attack_set.ramp_reserved_seconds of every attacks/train/Benign_train
    stream are the ramp base (changelog A1) and are left out; a shorter stream loses nothing."""
    m = manifest()
    n_res = reserved_windows(P.load())
    out = defaultdict(list)
    for sid, info in m["streams"].items():
        if info.get("kind") != kind:
            continue
        df = pd.read_parquet(PROCESSED / info["file"])
        if info["source_captures"] == [RAMP_BASE_CAPTURE] and len(df) >= n_res:
            df = df.iloc[:len(df) - n_res]
            if df.empty:
                continue
        out[info["device_id"]].append(df)
    for d in out:
        out[d].sort(key=lambda df: float(df["t_abs"].iloc[0]))
    return dict(out)


def transform(X: np.ndarray) -> np.ndarray:
    """Signed log1p: tames heavy-tailed counts and rates before ACF and scoring."""
    return np.sign(X) * np.log1p(np.abs(X))


def block_means(X: np.ndarray, b: int) -> np.ndarray:
    n = (len(X) // b) * b
    if n == 0:
        return np.zeros((0,) + X.shape[1:])
    return X[:n].reshape(n // b, b, *X.shape[1:]).mean(axis=1)
