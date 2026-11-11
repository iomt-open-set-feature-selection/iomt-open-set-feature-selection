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
(no need to parse 60 GB of floods for the gate). Floods that have been parsed
in full (paths.FLOOD_INTERIM) also get one ``flood_pairs`` row per (capture,
target device); attacker packets there are frames from attack_set.flood_attacker_macs,
not network.attacker_macs. From them the amended gate 3 count (changelog A1) is
written as ``amended_gate3``, apart from the recorded count above, which does not
change. Both are left out, with the reason in ``flood_pairs_note``, while
attack_set.flood_attacker_macs is null or IOMT_FLOOD_INTERIM is unset or the same
folder as INTERIM (device_map reads every parsed capture there).

Output: results/stage1/attack_inventory.json and attacks.csv
"""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

from iomt import protocol as P
from iomt.paths import FLOOD_INTERIM, INTERIM, STAGE1, ensure
from iomt.streams.captures import DEFAULT_ROOT, list_captures
from iomt.streams.device_map import (attacker_macs, device_ips_in, device_mask, load_inventory,
                                     outbound_mask, usable_devices)
from iomt.streams.load import RAMP_BASE_CAPTURE, reserved_windows
from iomt.streams.pcap_parse import load_packets, out_path, u64_mac


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


def ramp_attacks(files, pairs, ramp_id, base_devices, gap_seconds, min_packets) -> int:
    """Ramp attacks of one family (changelog A1). Flood files are one recording unless the next
    starts more than gap_seconds after the last frame so far (the device_map.sessions() cut, on the
    files' first and last frame). Per base device, the attacker packets of a recording are summed;
    it counts with at least min_packets. Only pairs whose device IPs come from the capture are used."""
    rec_of, end, k = {}, None, -1
    for f in sorted((f for f in files if f["ramp_family"] == ramp_id), key=lambda f: f["capture_t0"]):
        if end is None or f["capture_t0"] - end > gap_seconds:
            k, end = k + 1, f["capture_t1"]
        else:
            end = max(end, f["capture_t1"])
        rec_of[f["capture_id"]] = k
    totals = defaultdict(int)
    for r in pairs:
        if (r["ramp_family"] == ramp_id and r["ips_from"] == "capture" and r["device_id"] in base_devices
                and r["capture_id"] in rec_of):
            totals[(r["device_id"], rec_of[r["capture_id"]])] += r["attacker_packets"]
    return sum(t >= min_packets for t in totals.values())


MAC_FORMAT = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def check_flood_macs(macs, inv):
    """Stop if a flood attacker MAC is not lower-case aa:bb:cc:dd:ee:ff or belongs to a usable device, broker or gateway."""
    for m in macs:
        if not isinstance(m, str) or not MAC_FORMAT.match(m):
            raise SystemExit(f"attack_set.flood_attacker_macs: '{m}' is not a lower-case MAC aa:bb:cc:dd:ee:ff")
        bad = [h for h in inv["hosts"] if h["mac"] == m and (h.get("usable") or h["role"] in ("broker", "gateway"))]
        if bad:
            raise SystemExit(f"attack_set.flood_attacker_macs: {m} is a usable device, broker or gateway "
                             f"({bad[0]['role']}) in the device inventory")


def run(cfg, interim=INTERIM, root=DEFAULT_ROOT, episode_seconds=300.0, flood_interim=FLOOD_INTERIM):
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
    # top_src_macs ranks ALL inbound sources (cross-check); attacker_packets counts flood_attacker_macs only.
    flood_macs = P.get(cfg, "attack_set.flood_attacker_macs", None)
    check_flood_macs(flood_macs or [], inv)
    ramps = P.get(cfg, "attack_set.ramps", []) or []
    rmap = {p: r["id"] for r in ramps for p in r.get("base_capture") or []}
    att_fl = np.asarray([int(m.replace(":", ""), 16) for m in flood_macs or []], dtype=np.uint64)
    flood_note = None
    if not flood_macs:
        flood_note = "attack_set.flood_attacker_macs is null: no flood_pairs and no amended count"
    elif flood_interim is None:
        flood_note = "IOMT_FLOOD_INTERIM is not set: no flood_pairs and no amended count"
    elif Path(flood_interim).resolve() == Path(interim).resolve():
        flood_note = "IOMT_FLOOD_INTERIM is the INTERIM folder: no flood_pairs and no amended count"
    flood_pairs, flood_skipped, flood_files = [], [], []
    for c in (list_captures() if flood_note is None else []):
        if c.kind != "flood" or not out_path(flood_interim, c.capture_id).exists():
            continue
        pk, meta = load_packets(flood_interim, c.capture_id)
        if meta.get("truncated"):
            flood_skipped.append({"capture_id": c.capture_id, "reason": "parsed with a packet cap"})
            continue
        flood_files.append({"capture_id": c.capture_id, "ramp_family": family_of(c.subtype, rmap),
                            "capture_t0": float(pk["ts"].min()), "capture_t1": float(pk["ts"].max())})
        for h in hosts:
            mac = [int(h["mac"].replace(":", ""), 16)]
            # devices change IP between sessions: prefer the IPs the device sent from in this capture
            sent = pk["src_ip"][(pk["src_mac"] == mac[0]) & (pk["src_ip"] != 0)]
            ips_from = "capture" if len(sent) else "inventory"
            ips = np.unique(sent).tolist() if len(sent) else device_ips_in(inv, h, c.capture_id)
            m = device_mask(pk, ips, mac) & ~outbound_mask(pk, ips, mac)
            if not m.any():
                continue
            src, ts = pk["src_mac"][m], pk["ts"][m]
            ts = ts[np.isin(src, att_fl)]
            macs, cnt = np.unique(src, return_counts=True)
            top = np.argsort(-cnt, kind="stable")[:3]
            flood_pairs.append({
                "capture_id": c.capture_id, "device_id": h["device_id"], "ips_from": ips_from,
                "ramp_family": family_of(c.subtype, rmap),
                "attacker_packets": int(len(ts)),
                "first_attacker_ts": float(ts.min()) if len(ts) else None,
                "last_attacker_ts": float(ts.max()) if len(ts) else None,
                "top_src_macs": [{"mac": u64_mac(macs[i]), "packets": int(cnt[i])} for i in top],
            })
        del pk
    n_enough = sum(1 for v in per_family.values() if v["enough"])
    amended = None
    if flood_note is None:
        reserve = reserved_windows(cfg) * float(P.require(cfg, "streams.window_seconds"))
        base_devices = [h["device_id"] for h in hosts
                        if h.get("captures", {}).get(RAMP_BASE_CAPTURE, {}).get("span_s", 0) >= reserve]
        gap = float(P.require(cfg, "streams.session_gap_seconds"))
        ramp_n = {r["id"]: ramp_attacks(flood_files, flood_pairs, r["id"], base_devices, gap, min_pk)
                  for r in ramps}
        n_ramp = sum(1 for v in ramp_n.values() if v >= min_att)
        # every flood capture of a ramp family needs a full parse, else its recordings are unknown
        have = {f["capture_id"] for f in flood_files}
        missing = sorted(c.capture_id for c in list_captures()
                         if c.kind == "flood" and family_of(c.subtype, rmap) and c.capture_id not in have)
        amended = {"status": "incomplete" if missing else "complete", "missing_files": missing,
                   "recorded_families_enough": n_enough, "ramp_attacks": ramp_n,
                   "ramp_families_enough": n_ramp, "n_families_with_enough": n_enough + n_ramp,
                   "passes": not missing and n_enough + n_ramp >= min_cls}
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
        "flood_pairs": flood_pairs,
        "flood_skipped": flood_skipped,
        "flood_files": flood_files,
        "attacks": attacks,
    }
    if amended:
        rep["amended_gate3"] = amended
    else:
        rep["flood_pairs_note"] = flood_note
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
    am = rep.get("amended_gate3")
    print(f"amended count ({am['status']}): {am['n_families_with_enough']} families with enough "
          f"(ramp attacks {am['ramp_attacks']}) -> {'PASS' if am['passes'] else 'FAIL'}" if am
          else rep["flood_pairs_note"])


if __name__ == "__main__":
    main()
