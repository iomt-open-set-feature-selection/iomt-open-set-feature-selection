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
  5. e-detector only: also run with threshold = gamma (no calibration), reported
     as a number; no gate reads it.

Verdicts (changelog A3, A4). Devices whose role is in validity.audit_excluded_roles
are not audited; their rows are kept and marked. Per audited device, with
E = audit blocks / nominal ARL in blocks (expected alarms), in this order:
calibration not reached = fail; E < validity.min_alarms_for_audit = inconclusive;
else the log ratio against a band that widens as E falls. Per detector: fail if
any audited device fails, pass if none fails and at least half pass, else
inconclusive. Gate 5 passes when the conformal e-detector passes. CUSUM and the
threshold detector get the same verdicts; a fail marks them unmatched.

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
from iomt.streams.device_map import load_inventory
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


def device_verdict(calibration_reached, expected, ratio, tol, min_expected) -> str:
    """Per-device A3 rule, steps in order. n = 0 gives an infinite ratio, which is above the band."""
    if not calibration_reached:
        return "fail"
    if expected < min_expected:
        return "inconclusive"
    half = 1.96 / np.sqrt(expected)
    return "pass" if np.log(1 - tol) - half <= np.log(ratio) <= np.log(1 + tol) + half else "fail"


def detector_verdict(verdicts: list[str]) -> str:
    """Detector level: fail if any audited device fails; pass if none fails and at least half pass."""
    if "fail" in verdicts:
        return "fail"
    return "pass" if verdicts and 2 * verdicts.count("pass") >= len(verdicts) else "inconclusive"


def pooled(df, detector, mode, audited_only=False):
    s = df[(df.detector == detector) & (df.threshold_mode == mode) & (df.status == "ok")]
    if audited_only:
        s = s[~s.audit_excluded.astype(bool)]
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
    min_al = int(P.require(cfg, "validity.min_alarms_for_audit"))
    excluded_roles = set(P.require(cfg, "validity.audit_excluded_roles"))
    roles = {h["device_id"]: h["role"] for h in load_inventory()["hosts"] if "device_id" in h}
    rng = np.random.default_rng(seed)
    rows = []
    for dev, segs in sorted(benign_segments().items()):
        bs = device_block_scores(dev, segs, features, b, cfg, seed)
        if bs is None:
            # E = 0 is below the minimum: inconclusive, and the device stays in the base of the detector rule
            rows.append({"device_id": dev, "status": "too little benign data", "expected_alarms": 0.0,
                         "audit_excluded": roles.get(dev) in excluded_roles,
                         "verdict": "excluded" if roles.get(dev) in excluded_roles else "inconclusive"})
            continue
        r = device_audit(dev, bs, features, b, cfg, rng, calib, seed)
        rows.extend(r)
        for x in r:
            x["audit_excluded"] = roles.get(dev) in excluded_roles
            if x["threshold_mode"] == "calibrated":
                x["expected_alarms"] = x["audit_blocks"] / x["nominal_arl_blocks"]
                x["verdict"] = "excluded" if x["audit_excluded"] else device_verdict(
                    x["calibration_reached"], x["expected_alarms"], x["ratio"], tol, min_al)
            print(f"{dev:28s} {x['detector']:12s} {x['threshold_mode']:10s} "
                  f"alarms {x['alarms']:4d}/{x['audit_blocks']:6d} blocks  ratio {x['ratio']:.2f}", flush=True)
    df = pd.DataFrame(rows)
    res = {"protocol_sha256": P.sha256(), "block_windows": b, "tolerance": tol,
           "min_alarms_for_audit": min_al, "audit_excluded_roles": sorted(excluded_roles),
           "calibration": calib, "pooled": {}, "detectors": {}}
    short = df[(df.status != "ok") & ~df.audit_excluded.astype(bool)].device_id
    for name in df.detector.dropna().unique():
        res["pooled"][f"{name}/calibrated"] = pooled(df, name, "calibrated")
        res["pooled"][f"{name}/calibrated_audited"] = pooled(df, name, "calibrated", audited_only=True)
        cal = df[(df.detector == name) & (df.threshold_mode == "calibrated") & (df.status == "ok")]
        cal = cal[~cal.audit_excluded.astype(bool)]
        v = dict(zip(cal.device_id, cal.verdict)) | {d: "inconclusive" for d in short}
        res["detectors"][name] = {"verdict": detector_verdict(list(v.values())), "devices": v,
                                  "audited": len(v), "passed": list(v.values()).count("pass"),
                                  "failed": [d for d, x in v.items() if x == "fail"],
                                  "inconclusive": [d for d, x in v.items() if x == "inconclusive"]}
    res["pooled"]["conformal_e/theory"] = pooled(df, "conformal_e", "theory")   # reported only
    res["passes"] = res["detectors"]["conformal_e"]["verdict"] == "pass"
    res["unmatched"] = [n for n, d in res["detectors"].items() if d["verdict"] == "fail"]
    res["not_confirmed"] = [n for n, d in res["detectors"].items() if d["verdict"] == "inconclusive"]
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
    for name, d in res["detectors"].items():
        print(f"{name}: {d['verdict']} ({d['passed']}/{d['audited']} audited devices pass; "
              f"failed {d['failed']}; inconclusive {d['inconclusive']})")
    print("GATE 5", "PASS" if res["passes"] else "FAIL")


if __name__ == "__main__":
    main()
