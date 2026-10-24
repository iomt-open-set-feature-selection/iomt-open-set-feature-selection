"""Gate item 3: do at least three non-flood classes have enough traffic for repeated streams?

An attack (the unit of analysis) is one (attack capture, target device) pair
in which the attacker sent at least ``gate.min_attacker_packets_per_attack``
packets to a usable device. Attacker = a MAC the device inventory lists as attacker, i.e. one pinned in
protocol network.attacker_macs.

For every attack we also record when the attacker's first packet arrives
after the capture starts. Onsets are spliced at capture boundaries, so a late
first packet adds directly to measured delay; Stage 2 has to account for it.

Classes are counted at the protocol's family level (attack_set.non_flood) and,
for information, at the capture-subtype level.

Flood captures are only counted for volume, from the released CSV row counts
(no need to parse 60 GB of floods for the gate).

Output: results/stage1/attack_inventory.json and attacks.csv
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

from iomt import protocol as P
from iomt.paths import INTERIM, STAGE1, ensure
from iomt.streams.captures import DEFAULT_ROOT, list_captures
from iomt.streams.device_map import (attacker_macs, device_ips_in, device_mask, load_inventory,
                                     outbound_mask, usable_devices)
from iomt.streams.pcap_parse import load_packets, out_path


def family_map(cfg) -> dict[str, str]:
    out = {}
    for item in P.get(cfg, "attack_set.non_flood", []) or []:
        for prefix in item.get("captures") or []:
            out[prefix] = item["id"]
    return out


def family_of(subtype: str, fmap: dict[str, str]) -> str | None:
    for prefix, fam in fmap.items():
        if subtype.startswith(prefix):
            return fam
    return None


def csv_rows(root: Path, capture) -> int | None:
    rel = Path(capture.path).relative_to(Path(root) / "WiFI_and_MQTT" / "attacks" / "PCAP")
    csv = Path(root) / "WiFI_and_MQTT" / "attacks" / "CSV" / rel.parent / (rel.name + ".csv")
    if not csv.exists():
        return None
    with open(csv, "rb") as f:
        return max(0, sum(1 for _ in f) - 1)


def run(cfg, interim=INTERIM, root=DEFAULT_ROOT, episode_seconds=300.0):
    inv = load_inventory()
    hosts = usable_devices(inv)
    att = np.asarray(attacker_macs(inv), dtype=np.uint64)
    fmap = family_map(cfg)
    min_pk = int(P.get(cfg, "gate.min_attacker_packets_per_attack", 20))
    attacks, skipped = [], []
    for c in list_captures():
        if c.kind != "non_flood":
            continue
        if not out_path(interim, c.capture_id).exists():
            skipped.append({"capture_id": c.capture_id, "reason": "not parsed"})
            continue
        pk, meta = load_packets(interim, c.capture_id)
        if meta.get("truncated"):
            skipped.append({"capture_id": c.capture_id, "reason": "parsed with a packet cap"})
            continue
        fam = family_of(c.subtype, fmap) or c.family
        cap_t0, cap_t1 = float(pk["ts"][0]), float(pk["ts"][-1])
        for h in hosts:
            ips = device_ips_in(inv, h, c.capture_id)
            mac = [int(h["mac"].replace(":", ""), 16)]
            m = device_mask(pk, ips, mac)
            sub = pk[m]
            ob = outbound_mask(sub, ips, mac)
            from_att = np.isin(sub["src_mac"], att) & ~ob
            n_att = int(from_att.sum())
            if n_att == 0:
                continue
            ts = sub["ts"][from_att]
            dur = float(ts[-1] - ts[0])
            attacks.append({
                "attack_id": f"{fam}__{c.capture_id.split('/')[-1]}__{h['device_id']}",
                "family": fam, "subtype": c.subtype, "capture_id": c.capture_id, "split": c.split,
                "device_id": h["device_id"], "attacker_packets": n_att,
                "device_packets": int(len(sub)),
                "first_attacker_packet_after_capture_start_s": float(ts[0] - cap_t0),
                "attacker_active_s": dur, "capture_seconds": cap_t1 - cap_t0,
                "episodes_of_%ds" % int(episode_seconds): int(dur // episode_seconds),
                "counts": n_att >= min_pk,
            })
        del pk
    df = pd.DataFrame(attacks)
    min_att = int(P.require(cfg, "gate.min_attacks_per_class"))
    min_cls = int(P.require(cfg, "gate.min_non_flood_classes"))
    fams = [i["id"] for i in P.get(cfg, "attack_set.non_flood", [])]
    per_family, per_subtype = {}, {}
    if len(df):
        ok = df[df["counts"]]
        for f in fams:
            sub = ok[ok["family"] == f]
            per_family[f] = {"attacks": int(len(sub)), "devices": sorted(sub["device_id"].unique().tolist()),
                             "captures": sorted(sub["capture_id"].unique().tolist()),
                             "attacker_packets": int(sub["attacker_packets"].sum()),
                             "enough": len(sub) >= min_att}
        for s, sub in ok.groupby("subtype"):
            per_subtype[s] = {"attacks": int(len(sub)), "enough": len(sub) >= min_att}
    else:
        per_family = {f: {"attacks": 0, "enough": False} for f in fams}
    floods = defaultdict(lambda: {"captures": 0, "csv_rows": 0})
    for c in list_captures():
        if c.kind == "flood":
            r = csv_rows(Path(root), c)
            floods[c.family]["captures"] += 1
            floods[c.family]["csv_rows"] += r or 0
    n_enough = sum(1 for v in per_family.values() if v["enough"])
    rep = {
        "protocol_sha256": P.sha256(),
        "min_attacker_packets_per_attack": min_pk,
        "min_attacks_per_class": min_att,
        "min_non_flood_classes": min_cls,
        "per_family": per_family,
        "per_subtype": per_subtype,
        "n_families_with_enough": n_enough,
        "passes": n_enough >= min_cls,
        "skipped_captures": skipped,
        "floods_from_released_csv": dict(floods),
        "attacks": attacks,
    }
    return rep, df


def main(argv=None):
    ap = argparse.ArgumentParser(description="Attacks per non-flood class (gate 3)")
    ap.add_argument("--episode-seconds", type=float, default=300.0)
    a = ap.parse_args(argv)
    cfg = P.load()
    rep, df = run(cfg, episode_seconds=a.episode_seconds)
    ensure(STAGE1)
    with open(STAGE1 / "attack_inventory.json", "w", encoding="utf-8") as f:
        json.dump(rep, f, indent=1)
    df.to_csv(STAGE1 / "attacks.csv", index=False)
    for fam, v in rep["per_family"].items():
        print(f"{fam:16s} attacks {v['attacks']:4d}  enough={v['enough']}")
    for s, v in rep["per_subtype"].items():
        print(f"   {s:28s} {v['attacks']:4d}")
    print(f"families with enough attacks: {rep['n_families_with_enough']} "
          f"(need {rep['min_non_flood_classes']}) -> {'PASS' if rep['passes'] else 'FAIL'}")


if __name__ == "__main__":
    main()
