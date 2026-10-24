"""Gate item 5: does the conformal e-detector hold its nominal run length on blocked benign traffic?

Per usable device, at full features:
  1. Cut each benign capture segment chronologically into four parts
     (validity.benign_split): score fit / conformal reference / threshold
     tuning / audit. Parts are aligned to block boundaries.
  2. Fit the benign-only score on the fit windows; turn every part into block
     scores (block size from results/audit/block_size.json only).
  3. For each detector: reference = reference blocks; calibrate the threshold
     on the tuning blocks to gamma = nominal_arl_windows / block_windows, with
     the calibration method chosen by validity/calibration_study.py
     (results/stage1/gate5_calibration_study.json). The study uses the tuning
     blocks only, so the audit split is still unseen here.
  4. Audit: run on the audit blocks in their real order, restarting after every
     alarm, and estimate ARL = audit blocks / alarms.
  5. e-detector only, theory check: threshold = gamma (no calibration). The
     anytime-valid result says ARL >= gamma under exchangeability. Calibration
     cannot change this check.

Gate 5 passes when, pooled over devices,
  (a) calibrated e-detector: measured / nominal within 1 +/- run_length_tolerance,
      with at least validity.min_alarms_for_audit alarms (otherwise inconclusive);
  (b) theory threshold: measured ARL >= (1 - tolerance) * gamma.
CUSUM and the fixed threshold are audited the same way and reported, not gated.

Outputs: results/aggregated/run_length.csv, results/stage1/gate5_run_length.json
"""
from __future__ import annotations

import argparse
import json

import numpy as np
import pandas as pd

from iomt import protocol as P
from iomt.contracts import features_for
from iomt.detectors import make
from iomt.detectors.calibrate import calibrate_with, candidate_label
from iomt.detectors.score import BenignScore
from iomt.paths import AGG, AUDIT, STAGE1, ensure
from iomt.streams.load import benign_segments

STUDY = STAGE1 / "gate5_calibration_study.json"


def split_blocks(n_windows: int, b: int, fractions) -> list[slice]:
    """Chronological window slices, each a whole number of blocks."""
    nb = n_windows // b
    cuts = np.floor(np.cumsum([0] + list(fractions)) / sum(fractions) * nb).astype(int)
    return [slice(cuts[i] * b, cuts[i + 1] * b) for i in range(len(fractions))]


def block_size() -> int:
    with open(AUDIT / "block_size.json", encoding="utf-8") as f:
        bjs = json.load(f)
    b = bjs["block_windows"]
    if not b:
        raise SystemExit("block_size.json has no block size; gate 4 must pass first")
    return int(b)


def device_block_scores(dev, segments, features, b, cfg, seed=0):
    """Split, fit the benign-only score, return block scores per part (None if too little data)."""
    fr = P.require(cfg, "validity.benign_split")
    parts = {"fit": [], "ref": [], "tune": [], "audit": []}
    for df in segments:
        X = df[features].to_numpy(float)
        for name, sl in zip(parts, split_blocks(len(X), b, fr)):
            if sl.stop - sl.start >= b:
                parts[name].append(X[sl])
    if not all(parts.values()):
        return None
    score = BenignScore(P.get(cfg, "score.model", "isolation_forest"), seed=seed).fit(np.vstack(parts["fit"]))
    return {k: [score.block_scores(x, b) for x in v] for k, v in parts.items()}


def concat(segs):
    """Concatenate segments; return the sequence and each segment's start index."""
    return np.concatenate(segs), np.cumsum([0] + [len(x) for x in segs])[:-1]


def chosen_calibration(cfg) -> dict:
    """Calibration method fixed by the tuning-split study (gate 5 adjust loop)."""
    if not STUDY.exists():
        raise SystemExit("run python -m iomt.validity.calibration_study first")
    with open(STUDY, encoding="utf-8") as f:
        st = json.load(f)
    if st.get("protocol_sha256") != P.sha256():
        raise SystemExit("gate5_calibration_study.json is stale; re-run the study")
    if not st.get("chosen"):
        raise SystemExit("the calibration study chose no method; see gate5_calibration_study.json")
    return st["chosen"]


def device_audit(dev, bs, features, b, cfg, rng, calib, seed=0):
    W = float(P.require(cfg, "streams.window_seconds"))
    gamma = float(P.require(cfg, "detectors.nominal_arl_windows")) / b
    ref = np.concatenate(bs["ref"])
    audit_seq, starts = concat(bs["audit"])
    hours = len(audit_seq) * b * W / 3600.0
    r1 = np.corrcoef(audit_seq[:-1], audit_seq[1:])[0, 1] if len(audit_seq) > 2 else np.nan
    rows = []
    for name in P.get(cfg, "detectors.names", ["conformal_e", "cusum", "threshold"]):
        det = make(name, cfg).fit_reference(ref)
        cal = calibrate_with(det, bs["tune"], gamma, rng, **calib)
        inputs = det.prepare(audit_seq, rng)
        modes = [("calibrated", cal["h"])]
        th = det.theory_threshold(gamma)
        if th is not None:
            modes.append(("theory", th))
        for mode, h in modes:
            n_al = len(det.alarms(inputs, h, starts))
            arl = len(audit_seq) / n_al if n_al else float("inf")
            rows.append({
                "device_id": dev, "detector": name, "threshold_mode": mode, "threshold": h,
                "calibration": candidate_label(calib) if mode == "calibrated" else "none",
                "nominal_arl_blocks": gamma, "block_windows": b,
                "audit_blocks": int(len(audit_seq)), "alarms": int(n_al),
                "measured_arl_blocks": arl, "ratio": arl / gamma,
                "false_alarms_per_hour": n_al / hours if hours else np.nan,
                "calibration_reached": cal["reached"] if mode == "calibrated" else None,
                "arl_on_tuning": cal["arl_tune"] if mode == "calibrated" else None,
                "score_block_acf1_audit": float(r1),
                "selector": "none", "k": len(features), "seed": seed, "status": "ok",
            })
    return rows


def pooled(df, detector, mode):
    s = df[(df.detector == detector) & (df.threshold_mode == mode) & (df.status == "ok")]
    blocks, alarms = int(s.audit_blocks.sum()), int(s.alarms.sum())
    gamma = float(s.nominal_arl_blocks.iloc[0]) if len(s) else np.nan
    arl = blocks / alarms if alarms else float("inf")
    return {"audit_blocks": blocks, "alarms": alarms, "measured_arl_blocks": arl,
            "nominal_arl_blocks": gamma, "ratio": arl / gamma if len(s) else None}


def run(cfg, seed=0):
    features = features_for(cfg)
    b = block_size()
    calib = chosen_calibration(cfg)
    tol = float(P.require(cfg, "validity.run_length_tolerance"))
    min_al = int(P.get(cfg, "validity.min_alarms_for_audit", 30))
    rng = np.random.default_rng(seed)
    rows = []
    for dev, segs in sorted(benign_segments().items()):
        bs = device_block_scores(dev, segs, features, b, cfg, seed)
        if bs is None:
            rows.append({"device_id": dev, "status": "too little benign data"})
            continue
        r = device_audit(dev, bs, features, b, cfg, rng, calib, seed)
        rows.extend(r)
        for x in r:
            print(f"{dev:28s} {x['detector']:12s} {x['threshold_mode']:10s} "
                  f"alarms {x['alarms']:4d}/{x['audit_blocks']:6d} blocks  ratio {x['ratio']:.2f}", flush=True)
    df = pd.DataFrame(rows)
    res = {"protocol_sha256": P.sha256(), "block_windows": b, "tolerance": tol,
           "min_alarms_for_audit": min_al, "calibration": calib, "pooled": {}}
    for name in df.detector.dropna().unique():
        res["pooled"][f"{name}/calibrated"] = pooled(df, name, "calibrated")
    res["pooled"]["conformal_e/theory"] = pooled(df, "conformal_e", "theory")
    cal = res["pooled"]["conformal_e/calibrated"]
    thy = res["pooled"]["conformal_e/theory"]
    a_ok = cal["alarms"] >= min_al and cal["ratio"] is not None and abs(cal["ratio"] - 1) <= tol
    a_inconclusive = cal["alarms"] < min_al
    b_ok = thy["measured_arl_blocks"] >= (1 - tol) * thy["nominal_arl_blocks"]
    res["check_a_calibrated_within_tolerance"] = bool(a_ok)
    res["check_a_inconclusive_too_few_alarms"] = bool(a_inconclusive)
    res["check_b_theory_threshold_valid"] = bool(b_ok)
    res["passes"] = bool(a_ok and b_ok)
    res["note"] = ("inconclusive: lower detectors.nominal_arl_windows or add benign data"
                   if a_inconclusive else "")
    return res, df


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run-length audit (gate 5)")
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args(argv)
    cfg = P.load()
    res, df = run(cfg, a.seed)
    ensure(AGG, STAGE1)
    df.to_csv(AGG / "run_length.csv", index=False)
    with open(STAGE1 / "gate5_run_length.json", "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1)
    print(json.dumps(res["pooled"], indent=1))
    print(f"calibration: {candidate_label(res['calibration'])}")
    print(f"(a) calibrated within tolerance: {res['check_a_calibrated_within_tolerance']}"
          f"{'  [INCONCLUSIVE: too few alarms]' if res['check_a_inconclusive_too_few_alarms'] else ''}")
    print(f"(b) theory threshold valid: {res['check_b_theory_threshold_valid']}")
    print("GATE 5", "PASS" if res["passes"] else "FAIL")


if __name__ == "__main__":
    main()
