"""Gate 5 adjust loop: choose the calibration method on the tuning split only.

The 2026-10-23 audit showed every detector over-alarming about 2x after a
moving-block-bootstrap calibration with 10-block resamples. Picking a fix by
looking at the audit split would make the audit a tuning set, so the choice is
made here, inside the tuning blocks:

  1. Same split and benign-only score as run_length.py (fit / ref / tune / audit).
  2. Each tuning segment is cut chronologically by detectors.calibration.inner_split
     into a calibrate half and a check half.
  3. For every candidate in detectors.calibration.candidates, the conformal
     e-detector is calibrated on the calibrate half and run on the check half in
     real order (renewal, restart at segment starts).
  4. Pooled over devices: check-half blocks / alarms, divided by gamma.
  5. Rule, fixed in the protocol before this runs: among candidates that ran on
     every device and produced at least validity.min_alarms_for_audit pooled
     check-half alarms, choose the one with the smallest |log(ratio)|; ties go
     to the earlier candidate in the list.

Diagnostic, not part of the rule: the fixed per-block threshold is also
calibrated on the calibrate half (real order) and run on the check half. It
sees only the marginal distribution of block scores, so dependence cannot move
its ratio; a ratio well below 1 means the upper tail of the score is heavier in
the later half, which no calibration method can fix.

run_length.py reads the choice from the output and refuses a stale one. The
audit split is not read here.

Output: results/stage1/gate5_calibration_study.json
"""
from __future__ import annotations

import argparse
import json
import math

import numpy as np

from iomt import protocol as P
from iomt.contracts import features_for
from iomt.detectors import make
from iomt.detectors.calibrate import calibrate_with, candidate_label
from iomt.paths import STAGE1, ensure
from iomt.streams.load import benign_segments
from iomt.validity.run_length import STUDY, block_size, concat, device_block_scores

RULE = ("among candidates with no failed device and >= validity.min_alarms_for_audit pooled "
        "check-half alarms, smallest |log(measured/nominal)| for the conformal e-detector; "
        "ties to the earlier candidate")


def inner_halves(segs, frac):
    """Chronological split of every tuning segment into (calibrate, check) parts."""
    cal, chk = [], []
    f = frac[0] / sum(frac)
    for s in segs:
        k = int(round(len(s) * f))
        if k > 0:
            cal.append(s[:k])
        if len(s) - k > 0:
            chk.append(s[k:])
    return cal, chk


def choose(pooled: list[dict], min_al: int):
    ok = [p for p in pooled if p["devices_failed"] == 0 and p["alarms"] >= min_al and p["ratio"]]
    if not ok:
        return None
    return min(ok, key=lambda p: (abs(math.log(p["ratio"])), p["order"]))


def run(cfg, seed=0):
    features = features_for(cfg)
    b = block_size()
    gamma = float(P.require(cfg, "detectors.nominal_arl_windows")) / b
    cands = P.require(cfg, "detectors.calibration.candidates")
    frac = P.require(cfg, "detectors.calibration.inner_split")
    min_al = int(P.get(cfg, "validity.min_alarms_for_audit", 30))
    rng = np.random.default_rng(seed)
    rows, diag = [], []
    for dev, segs in sorted(benign_segments().items()):
        bs = device_block_scores(dev, segs, features, b, cfg, seed)
        if bs is None:
            continue
        det = make("conformal_e", cfg).fit_reference(np.concatenate(bs["ref"]))
        cal_part, chk_part = inner_halves(bs["tune"], frac)
        if not cal_part or not chk_part:
            for c in cands:
                rows.append({"device_id": dev, "candidate": candidate_label(c), "status": "tuning split too short"})
            continue
        chk_seq, starts = concat(chk_part)
        inputs = det.prepare(chk_seq, rng)
        thr = make("threshold", cfg).fit_reference(np.concatenate(bs["ref"]))
        tcal = calibrate_with(thr, cal_part, gamma, rng, method="contiguous")
        t_al = len(thr.alarms(thr.prepare(chk_seq, rng), tcal["h"], starts))
        diag.append({"device_id": dev, "check_blocks": int(len(chk_seq)), "check_alarms": int(t_al),
                     "calibrate_alarms": tcal["tune_alarms"],
                     "ratio": (len(chk_seq) / t_al / gamma) if t_al else None})
        for c in cands:
            lab = candidate_label(c)
            try:
                cal = calibrate_with(det, cal_part, gamma, rng, **c)
            except ValueError as e:
                rows.append({"device_id": dev, "candidate": lab, "status": str(e)})
                continue
            n_al = len(det.alarms(inputs, cal["h"], starts))
            rows.append({"device_id": dev, "candidate": lab, "status": "ok", "h": cal["h"],
                         "reached": bool(cal["reached"]), "check_blocks": int(len(chk_seq)),
                         "check_alarms": int(n_al),
                         "ratio": (len(chk_seq) / n_al / gamma) if n_al else None})
            print(f"{dev:28s} {lab:11s} alarms {n_al:4d}/{len(chk_seq):6d} check blocks", flush=True)
    pooled = []
    for i, c in enumerate(cands):
        lab = candidate_label(c)
        r = [x for x in rows if x["candidate"] == lab]
        okr = [x for x in r if x["status"] == "ok"]
        blocks = sum(x["check_blocks"] for x in okr)
        alarms = sum(x["check_alarms"] for x in okr)
        pooled.append({"order": i, "candidate": lab, "config": c, "devices_ok": len(okr),
                       "devices_failed": len(r) - len(okr), "check_blocks": blocks, "alarms": alarms,
                       "measured_arl_blocks": (blocks / alarms) if alarms else None,
                       "ratio": (blocks / alarms / gamma) if alarms else None})
    best = choose(pooled, min_al)
    db, da = sum(x["check_blocks"] for x in diag), sum(x["check_alarms"] for x in diag)
    marginal = {"detector": "threshold/contiguous", "check_blocks": db, "alarms": da,
                "ratio": (db / da / gamma) if da else None, "per_device": diag,
                "reading": "ratio well below 1: score tail heavier in the later half (shift, "
                           "not dependence); calibration cannot fix this"}
    return {"protocol_sha256": P.sha256(), "block_windows": b, "nominal_arl_blocks": gamma,
            "inner_split": frac, "min_alarms": min_al, "rule": RULE,
            "audit_split_read": False, "pooled": pooled,
            "chosen": best["config"] if best else None,
            "chosen_label": best["candidate"] if best else None,
            "diagnostic_marginal_shift": marginal,
            "per_device": rows}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Gate 5 calibration study (tuning split only)")
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args(argv)
    res = run(P.load(), a.seed)
    ensure(STAGE1)
    with open(STUDY, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1)
    for p in res["pooled"]:
        r = f"{p['ratio']:.3f}" if p["ratio"] else "n/a"
        print(f"{p['candidate']:11s} alarms {p['alarms']:5d}  ratio {r}  failed devices {p['devices_failed']}")
    m = res["diagnostic_marginal_shift"]
    print(f"diagnostic, fixed threshold (marginal only): ratio "
          f"{m['ratio']:.3f}" if m["ratio"] else "diagnostic: no alarms")
    print("chosen:", res["chosen_label"])


if __name__ == "__main__":
    main()
