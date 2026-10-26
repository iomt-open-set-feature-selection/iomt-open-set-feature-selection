"""Gate item 6 (owner B): per-device lifecycle phase separation.

Rule: protocol/gate6.yaml, committed before any result was computed.
Run from repo root:  python -m iomt.analysis.phases [--no-perm]
Writes results/stage1/gate6_phases.json
"""
import argparse, hashlib, json, math
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
import yaml
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import balanced_accuracy_score

ROOT = Path(__file__).resolve().parents[3]
RULE = ROOT / "protocol" / "gate6.yaml"
INDEX = ROOT / "results" / "handoff" / "A10_benign_windows_index.csv"
STREAMS = ROOT / "data" / "processed" / "streams"
BLOCK = ROOT / "results" / "audit" / "block_size.json"
OUT = ROOT / "results" / "stage1" / "gate6_phases.json"


def rule_sha(path=RULE):
    # same normalisation as protocol.py: drop BOM, CRLF -> LF, so the hash matches on every OS
    data = Path(path).read_bytes().lstrip(b"\xef\xbb\xbf").replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def stream_blocks(path, b, cap):
    df = pd.read_parquet(path).sort_values("t_abs")
    cols = list(df.columns)
    feats = cols[cols.index("n_pkts") + 1:]
    assert len(feats) == 39, f"{path.name}: expected 39 features, got {len(feats)}"
    x = np.nan_to_num(np.log1p(np.clip(df[feats].to_numpy(float), 0, None)))  # log1p per window
    n = len(x) // b
    if n == 0:
        return np.empty((0, len(feats)))
    blocks = x[: n * b].reshape(n, b, -1).mean(axis=1)                       # block = mean of b windows
    if n > cap:
        keep = np.sort(np.random.default_rng(0).choice(n, cap, replace=False))
        blocks = blocks[keep]
    return blocks


def loso_score(X, y, groups, clf_args):
    pred = np.empty(len(y), dtype=object)
    for g in np.unique(groups):
        test = groups == g
        clf = RandomForestClassifier(**clf_args).fit(X[~test], y[~test])
        pred[test] = clf.predict(X[test])
    return balanced_accuracy_score(y, pred, adjusted=True)


def multiset_perms(items):
    c, n = Counter(items), len(items)
    def rec(prefix):
        if len(prefix) == n:
            yield tuple(prefix)
            return
        for k in sorted(c):
            if c[k]:
                c[k] -= 1; prefix.append(k)
                yield from rec(prefix)
                prefix.pop(); c[k] += 1
    yield from rec([])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-perm", action="store_true", help="observed scores only (quick check)")
    args = ap.parse_args()

    rule = yaml.safe_load(RULE.read_text(encoding="utf-8"))["gate6"]
    b = int(json.loads(BLOCK.read_text())["block_windows"])
    full = pd.read_csv(INDEX)
    clf_args = dict(n_estimators=rule["classifier"]["n_estimators"],
                    class_weight=rule["classifier"]["class_weight"],
                    random_state=rule["classifier"]["random_state"], n_jobs=-1)
    perm, cap = rule["permutation"], rule["max_blocks_per_session"]
    out = {"rule_sha256": rule_sha(), "block_windows": b,
           "permutation_run": not args.no_perm, "devices": {}}

    for dev in sorted(full["device_id"].unique()):
        d = full[(full["device_id"] == dev) & full["phase"].isin(rule["phases"])]
        sess = d.groupby("phase")["stream_id"].nunique()
        phases = sorted(p for p, n in sess.items() if n >= rule["min_sessions_per_phase"])
        rec = {"phases": phases, "sessions_per_phase": {p: int(n) for p, n in sess.items()}}
        if len(phases) < rule["min_phases_per_device"]:
            rec.update(status="not_testable", passed=False)
            out["devices"][dev] = rec
            print(f"{dev:24s} not testable ({len(phases)} eligible phases)")
            continue

        Xs, ys, gs = [], [], []
        for r in d[d["phase"].isin(phases)].itertuples():
            blk = stream_blocks(STREAMS / Path(r.file).name, b, cap)
            if len(blk):
                Xs.append(blk); ys += [r.phase] * len(blk); gs += [r.stream_id] * len(blk)
        X, y, g = np.vstack(Xs), np.array(ys, dtype=object), np.array(gs, dtype=object)

        obs = loso_score(X, y, g, clf_args)
        rec.update(status="tested", score=round(float(obs), 4),
                   n_blocks=int(len(y)), n_sessions=int(len(set(gs))))

        passed = None
        if not args.no_perm:
            sess_ids = list(dict.fromkeys(gs))
            labels = [y[g == s][0] for s in sess_ids]
            n_arr = math.factorial(len(labels)) // math.prod(
                math.factorial(v) for v in Counter(labels).values())
            if n_arr <= perm["n"]:
                arrangements, exact = list(multiset_perms(labels)), True
            else:
                rng = np.random.default_rng(0)
                arrangements = [tuple(rng.permutation(labels)) for _ in range(perm["n"])]
                exact = False
            scores = []
            for i, a in enumerate(arrangements, 1):
                m = dict(zip(sess_ids, a))
                scores.append(loso_score(X, np.array([m[s] for s in g], dtype=object), g, clf_args))
                if i % 50 == 0:
                    print(f"  {dev}: {i}/{len(arrangements)} permutations")
            scores = np.array(scores)
            p = (float(np.mean(scores >= obs)) if exact
                 else float((1 + np.sum(scores >= obs)) / (len(scores) + 1)))
            passed = bool(obs >= rule["pass_threshold"] and p < perm["alpha"])
            rec.update(perm_exact=exact, perm_n=len(scores), p_value=round(p, 5))

        rec["passed"] = passed
        out["devices"][dev] = rec
        OUT.write_text(json.dumps(out, indent=1))      # checkpoint after every device
        print(f"{dev:24s} phases={phases} score={obs:.3f} p={rec.get('p_value')} passed={passed}")

    OUT.write_text(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()