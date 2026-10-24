"""Gate item 2, part b: do our re-extracted features match the released CSV?

Re-extracts one unspliced capture in the release's own format (consecutive
10-packet chunks) and compares it with the released CSV. A few extraction
choices the release does not document are tried (packet filter, length field,
std ddof); all variants are kept in the JSON.

Two numbers per feature, because only one of them turned out to be
obtainable (measured 2026-10-23 on profiling/Idle):

  quantile_rel_diff  median relative gap between matched quantiles of the two
      samples. This is the gate number. On the best variant the deterministic
      features agree to a fraction of a percent, which is what "we extract the
      same quantity" means.
  match_fraction  share of rows that agree after positional alignment. This
      stays near zero and is kept only as evidence. The released row order
      cannot be reproduced from the pcap: no packet-offset, per-session or
      per-flow grouping lines the rows up (best cross-correlation lag gives
      r = 0.29, and only ~2 of 32689 rows land in the same position), while
      the marginal distributions agree closely. Treat the released CSVs as a
      bag of rows, not a time-ordered stream.

Defaults: feature_set ciciomt39 -> profiling/Idle/Idle vs profiling/CSV/Idle.pcap.csv
          feature_set cic45     -> attacks/train/ARP_Spoofing_train vs attacks/CSV/train/ARP_Spoofing_train.pcap.csv

Output: results/stage1/csv_match.json
"""
from __future__ import annotations

import argparse
import itertools
import json
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import spearmanr

from iomt import protocol as P
from iomt.contracts import features_for
from iomt.paths import INTERIM, STAGE1, ensure
from iomt.streams.captures import DEFAULT_ROOT
from iomt.streams.features import DETERMINISTIC_39, DETERMINISTIC_45, chunk_rows
from iomt.streams.pcap_parse import load_packets

DEFAULTS = {
    "ciciomt39": ("profiling/Idle/Idle", "WiFI_and_MQTT/profiling/CSV/Idle.pcap.csv"),
    "cic45": ("attacks/train/ARP_Spoofing_train",
              "WiFI_and_MQTT/attacks/CSV/train/ARP_Spoofing_train.pcap.csv"),
}
SIG = ["TCP", "UDP", "ARP", "ICMP", "IPv", "Protocol Type"]
RTOL, ATOL = 1e-4, 1e-6
QUANTILES = np.linspace(0.0, 1.0, 101)


def quantile_diff(x: np.ndarray, y: np.ndarray) -> float | None:
    """Median relative gap between the two samples' matched quantiles.

    The release's row order cannot be reproduced from the pcap (see the module
    docstring), so this compares the distribution of each feature instead of
    the rows: it answers "is this the same quantity?" without needing the same
    grouping. Features that are constant and equal in both score 0.

    None means "not comparable", never "agrees". The released CSVs do carry
    non-finite values (NaN in Std and Variance, inf in Rate, in
    profiling/Idle), and one NaN makes np.quantile return NaN for every
    quantile, which the comparison below would otherwise read as a perfect
    match. Non-finite values are dropped, and too few survivors give None.
    """
    x, y = np.asarray(x, float), np.asarray(y, float)
    x, y = x[np.isfinite(x)], y[np.isfinite(y)]
    if len(x) < 2 or len(y) < 2:
        return None
    a, b = np.quantile(x, QUANTILES), np.quantile(y, QUANTILES)
    den = np.maximum(np.abs(a), np.abs(b))
    return float(np.median(np.where(den > 1e-9, np.abs(a - b) / np.maximum(den, 1e-9), 0.0)))


def _filter(pk, how):
    if how == "all":
        return pk
    if how == "ip_or_arp":
        return pk[(pk["ip_ver"] > 0) | (pk["eth_type"] == 0x0806)]
    if how == "ipv4_or_arp":
        return pk[(pk["ip_ver"] == 4) | (pk["eth_type"] == 0x0806)]
    raise ValueError(how)


def _sig(df: pd.DataFrame) -> np.ndarray:
    cols = [c for c in SIG if c in df.columns]
    return np.round(df[cols].to_numpy(dtype=float), 3)


def align(ours: pd.DataFrame, csv: pd.DataFrame, block=500, max_off=300):
    """Piecewise-constant offset alignment. Returns (csv_idx, our_idx) arrays."""
    a, b = _sig(csv), _sig(ours)
    ci, oi = [], []
    prev = 0
    for s in range(0, len(a), block):
        rows = np.arange(s, min(s + block, len(a)))
        best, best_hits = prev, -1
        for off in sorted(range(-max_off, max_off + 1), key=lambda o: abs(o - prev)):
            j = rows + off
            ok = (j >= 0) & (j < len(b))
            if ok.sum() == 0:
                continue
            hits = int((a[rows[ok]] == b[j[ok]]).all(axis=1).sum())
            if hits > best_hits:
                best, best_hits = off, hits
        prev = best
        j = rows + best
        ok = (j >= 0) & (j < len(b))
        ci.append(rows[ok])
        oi.append(j[ok])
    ci = np.concatenate(ci) if ci else np.zeros(0, int)
    oi = np.concatenate(oi) if oi else np.zeros(0, int)
    keep = (a[ci] == b[oi]).all(axis=1)
    return ci[keep], oi[keep]


def compare(ours: pd.DataFrame, csv: pd.DataFrame, features: list[str]) -> dict:
    ci, oi = align(ours, csv)
    out = {"csv_rows": int(len(csv)), "our_rows": int(len(ours)), "aligned_rows": int(len(ci)),
           "aligned_fraction": float(len(ci) / max(1, len(csv))), "features": {}}
    for f in features:
        if f not in csv.columns or f not in ours.columns:
            out["features"][f] = {"status": "missing"}
            continue
        x = csv[f].to_numpy(float)[ci]
        y = ours[f].to_numpy(float)[oi]
        match = np.abs(x - y) <= ATOL + RTOL * np.abs(x)
        rel = np.abs(x - y) / np.maximum(np.abs(x), 1e-9)
        rho = float(spearmanr(x, y).statistic) if len(x) > 2 and np.std(x) > 0 and np.std(y) > 0 else None
        col = csv[f].to_numpy(float)
        out["features"][f] = {"match_fraction": float(match.mean()) if len(x) else 0.0,
                              "median_rel_error": float(np.median(rel)) if len(x) else None,
                              "spearman": rho,
                              # on all rows, not just the aligned ones
                              "quantile_rel_diff": quantile_diff(col, ours[f].to_numpy(float)),
                              "csv_finite_fraction": float(np.isfinite(col).mean())}
    return out


def run(cfg, capture_id=None, csv_path=None, interim=INTERIM, root=DEFAULT_ROOT):
    fs = P.get(cfg, "feature_set", "ciciomt39")
    features = features_for(cfg)
    det = DETERMINISTIC_39 if fs == "ciciomt39" else DETERMINISTIC_45
    d_cap, d_csv = DEFAULTS[fs]
    capture_id = capture_id or d_cap
    csv_path = Path(csv_path or Path(root) / d_csv)
    csv = pd.read_csv(csv_path)
    csv.columns = [c.strip() for c in csv.columns]
    header = list(csv.columns)
    pk, meta = load_packets(interim, capture_id)
    if meta.get("truncated"):
        raise SystemExit(f"{capture_id} was parsed with a packet cap; re-parse it fully")
    variants = []
    for how, lf, ddof in itertools.product(["all", "ip_or_arp", "ipv4_or_arp"], ["frame", "ip"], [0, 1]):
        if fs == "cic45" and ddof == 1:
            continue
        ours = chunk_rows(_filter(pk, how), feature_set=fs, length_field=lf, ddof=ddof)
        res = compare(ours, csv, features)
        fr = [res["features"][f].get("match_fraction", 0.0) for f in det if f in res["features"]]
        dq = {f: res["features"][f].get("quantile_rel_diff") for f in det if f in res["features"]}
        measured = [v for v in dq.values() if v is not None]
        res["variant"] = {"packet_filter": how, "length_field": lf, "std_ddof": ddof}
        res["deterministic_min_match"] = float(min(fr)) if fr else 0.0
        res["deterministic_mean_match"] = float(np.mean(fr)) if fr else 0.0
        res["deterministic_unmeasured"] = sorted(f for f, v in dq.items() if v is None)
        res["deterministic_max_quantile_diff"] = float(max(measured)) if measured else 1.0
        res["row_count_ratio"] = float(res["our_rows"] / max(1, res["csv_rows"]))
        variants.append(res)
        print(f"{how:12s} len={lf:5s} ddof={ddof}: aligned {res['aligned_fraction']:.3f}  "
              f"deterministic min/mean match {res['deterministic_min_match']:.3f}/"
              f"{res['deterministic_mean_match']:.3f}  "
              f"max quantile diff {res['deterministic_max_quantile_diff']:.4f}  "
              f"unmeasured {len(res['deterministic_unmeasured'])}", flush=True)
    # The release's row order is not reproducible, so the variant is chosen on
    # distribution agreement; the row-alignment numbers are kept as evidence.
    best = min(variants, key=lambda r: (len(r["deterministic_unmeasured"]),
                                        r["deterministic_max_quantile_diff"],
                                        -r["aligned_fraction"]))
    report = {
        "protocol_sha256": P.sha256(),
        "feature_set": fs,
        "capture_id": capture_id,
        "csv_path": str(csv_path),
        "csv_header": header,
        "header_matches_protocol": header == features,
        "deterministic_features": det,
        "best": best,
        "variants": [{k: v for k, v in r.items() if k != "features"} for r in variants],
    }
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(description="Re-extracted vs released CSV (gate 2)")
    ap.add_argument("--capture")
    ap.add_argument("--csv")
    a = ap.parse_args(argv)
    cfg = P.load()
    rep = run(cfg, a.capture, a.csv)
    ensure(STAGE1)
    with open(STAGE1 / "csv_match.json", "w", encoding="utf-8") as f:
        json.dump(rep, f, indent=1)
    b = rep["best"]
    print(f"\nheader matches protocol.features: {rep['header_matches_protocol']}")
    print(f"best variant {b['variant']}: aligned {b['aligned_fraction']:.3f} of {b['csv_rows']} rows")
    print(f"deterministic max quantile diff: {b['deterministic_max_quantile_diff']:.4f}; "
          f"not comparable: {b['deterministic_unmeasured'] or 'none'}")
    for name, v in b["features"].items():
        tag = "DET" if name in rep["deterministic_features"] else "   "
        qd = v.get("quantile_rel_diff")
        fin = v.get("csv_finite_fraction", 1.0)
        print(f"  {tag} {name:16s} quantile diff {'NOT COMPARABLE' if qd is None else f'{qd:.4f}':>14}  "
              f"row match {v.get('match_fraction', 0):.3f}"
              + (f"  [{100 * (1 - fin):.2f}% of released rows non-finite]" if fin < 1 else ""))


if __name__ == "__main__":
    main()
