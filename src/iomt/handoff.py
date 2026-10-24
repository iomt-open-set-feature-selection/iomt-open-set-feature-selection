"""Package Person A's Stage 1 handoffs for Person B, plus the gate report.

  A1   results/handoff/A1_devices.csv          usable devices
       results/handoff/A1_attack_classes.csv   attacks and traffic per class
       results/handoff/A1_features.json        feature names exactly as extracted, with definitions
  A10  results/handoff/A10_benign_windows_index.csv
       per-device benign window streams with timestamps and lifecycle metadata
       (files under data/processed/streams/, verified by SHA-256)
  Gate report: results/stage1/GATE_REPORT.md
"""
from __future__ import annotations

import json
from datetime import date

import pandas as pd

from iomt import protocol as P
from iomt.contracts import features_for
from iomt.paths import AUDIT, HANDOFF, PROCESSED, STAGE1, ensure
from iomt.streams.load import manifest

FEATURE_DEFINITIONS_39 = {
    "Header_Length": "mean transport-header length in the window (TCP data offset, UDP 8, else 0)",
    "Protocol Type": "mode of IP protocol numbers in the window (0 for non-IP)",
    "Time_To_Live": "mean TTL / hop limit",
    "Rate": "packets per second in the window",
    "fin_flag_number": "share of packets with TCP FIN", "syn_flag_number": "share with SYN",
    "rst_flag_number": "share with RST", "psh_flag_number": "share with PSH",
    "ack_flag_number": "share with ACK", "ece_flag_number": "share with ECE",
    "cwr_flag_number": "share with CWR",
    "ack_count": "packets with ACK", "syn_count": "packets with SYN",
    "fin_count": "packets with FIN", "rst_count": "packets with RST",
    "HTTP": "share of packets on port 80/8080", "HTTPS": "share on port 443", "DNS": "share on port 53",
    "Telnet": "share on port 23", "SMTP": "share on port 25", "SSH": "share on port 22",
    "IRC": "share on port 194", "TCP": "share TCP", "UDP": "share UDP", "DHCP": "share on port 67/68",
    "ARP": "share ARP", "ICMP": "share ICMP/ICMPv6", "IGMP": "share IGMP", "IPv": "share IPv4/IPv6",
    "LLC": "share of parsed link-layer frames",
    "Tot sum": "sum of packet lengths", "Min": "minimum packet length", "Max": "maximum packet length",
    "AVG": "mean packet length", "Std": "standard deviation of packet lengths",
    "Tot size": "mean packet length (equals AVG, as in the release)",
    "IAT": "mean gap between consecutive packets in the window (s)",
    "Number": "packets in the window", "Variance": "variance of packet lengths",
}


def _load(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _identification(h: dict) -> str:
    """How confident we are about what this device is (B may exclude the weak ones)."""
    if h.get("name"):
        return "named by its profiling capture"
    # Bit 1 of the first octet: locally administered, i.e. a randomised MAC,
    # which on this testbed means a phone or laptop more often than an IoMT device.
    if int(h["mac"][:2], 16) & 2:
        return "unidentified, randomised MAC"
    return "unidentified"


def a1(cfg):
    inv = _load(STAGE1 / "device_inventory.json")
    rows = [{k: h.get(k) for k in ("device_id", "name", "role", "mac", "main_ip",
                                   "benign_active_windows", "benign_span_s")}
            | {"identification": _identification(h),
               "non_flood_attack_captures": ";".join(h.get("non_flood_attack_captures", []))}
            for h in inv["hosts"] if h.get("usable")]
    pd.DataFrame(rows).to_csv(HANDOFF / "A1_devices.csv", index=False)
    ai = _load(STAGE1 / "attack_inventory.json")
    rows = []
    for fam, v in ai["per_family"].items():
        rows.append({"level": "family", "class": fam, "attacks": v.get("attacks", 0),
                     "attacker_packets": v.get("attacker_packets", 0),
                     "devices": ";".join(v.get("devices", [])), "enough": v.get("enough")})
    for s, v in ai["per_subtype"].items():
        rows.append({"level": "subtype", "class": s, "attacks": v["attacks"], "enough": v["enough"]})
    for fam, v in ai["floods_from_released_csv"].items():
        rows.append({"level": "flood_floor", "class": fam, "captures": v["captures"],
                     "released_csv_rows": v["csv_rows"]})
    pd.DataFrame(rows).to_csv(HANDOFF / "A1_attack_classes.csv", index=False)
    feats = features_for(cfg)
    cm = _load(STAGE1 / "csv_match.json") if (STAGE1 / "csv_match.json").exists() else None
    out = {"feature_set": P.get(cfg, "feature_set", "ciciomt39"), "features": feats,
           "n_features": len(feats), "window_seconds": P.get(cfg, "streams.window_seconds"),
           "definitions": FEATURE_DEFINITIONS_39 if len(feats) == 39 else "see src/iomt/streams/features.py",
           "csv_match": ({f: cm["best"]["features"].get(f) for f in feats} if cm else None),
           "csv_match_variant": cm["best"]["variant"] if cm else None,
           "protocol_sha256": P.sha256()}
    with open(HANDOFF / "A1_features.json", "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)


def a10():
    m = manifest()
    rows = []
    for sid, info in m["streams"].items():
        if info.get("kind") != "benign":
            continue
        df = pd.read_parquet(PROCESSED / info["file"], columns=["t_abs", "n_pkts"])
        rows.append({"stream_id": sid, "device_id": info["device_id"],
                     "source_capture": info["source_captures"][0], "phase": info.get("phase"),
                     "phase_detail": info.get("phase_detail"), "file": info["file"],
                     "sha256": info["sha256"], "n_windows": info["n_windows"],
                     "n_packets": info["n_packets"],
                     "active_fraction": float((df["n_pkts"] > 0).mean()),
                     "t_abs_start": float(df["t_abs"].iloc[0]), "t_abs_end": float(df["t_abs"].iloc[-1])})
    pd.DataFrame(rows).sort_values(["device_id", "t_abs_start"]).to_csv(
        HANDOFF / "A10_benign_windows_index.csv", index=False)


def gate_report(cfg):
    L = [f"# Stage 1 gate report, Person A ({date.today().isoformat()})", "",
         f"Protocol SHA-256 (draft, not frozen): `{P.sha256()}`", "",
         "B closes items 1-5 by re-running `pytest -m gate tests/gates -v` on their machine "
         "after rebuilding the artefacts (see RUNBOOK.md).", "", "| Item | Result | Key numbers |", "|---|---|---|"]

    def row(i, ok, txt):
        L.append(f"| {i} | {'PASS' if ok else 'FAIL'} | {txt} |")

    inv = _load(STAGE1 / "device_inventory.json")
    row(1, inv["n_usable_streams"] >= P.get(cfg, "gate.min_streams"),
        f"{inv['n_usable_streams']} usable streams (need {P.get(cfg, 'gate.min_streams')}): "
        + ", ".join(inv["usable_device_ids"]))
    m = manifest()
    onset = [s for s, i in m["streams"].items() if i.get("kind") == "onset"]
    cm = _load(STAGE1 / "csv_match.json") if (STAGE1 / "csv_match.json").exists() else None
    if cm:
        b = cm["best"]
        thr = float(P.get(cfg, "gate.csv_match_max_quantile_diff"))
        ok2 = bool(onset) and cm["header_matches_protocol"] \
            and b["deterministic_max_quantile_diff"] <= thr
        row(2, ok2, f"stream {onset[0] if onset else 'MISSING'}; deterministic features agree to "
                    f"{b['deterministic_max_quantile_diff']:.4f} on matched quantiles (limit {thr}); "
                    f"row-by-row alignment {b['aligned_fraction']:.3f}, not reproducible from the pcap")
    ai = _load(STAGE1 / "attack_inventory.json")
    row(3, ai["passes"], "; ".join(f"{k}: {v['attacks']}" for k, v in ai["per_family"].items()))
    bs = _load(AUDIT / "block_size.json")
    row(4, bool(bs["block_windows"]) and not bs["devices_above_threshold_at_block"],
        f"block = {bs['block_windows']} windows ({bs['block_seconds']} s); above threshold: "
        f"{bs['devices_above_threshold_at_block'] or 'none'}")
    g5 = _load(STAGE1 / "gate5_run_length.json")
    c = g5["pooled"]["conformal_e/calibrated"]
    t = g5["pooled"]["conformal_e/theory"]
    cl = g5.get("calibration") or {}
    cl = (f"mbb{cl.get('mbb_len_blocks')}" if cl.get("method") == "mbb" else cl.get("method", "mbb10"))
    row(5, g5["passes"], f"calibration {cl} (chosen on the tuning split); "
                         f"calibrated ratio {c['ratio']:.2f} over {c['alarms']} alarms; "
                         f"theory-threshold ARL {t['measured_arl_blocks']:.0f} vs nominal {t['nominal_arl_blocks']:.0f} blocks"
                         + (" (INCONCLUSIVE: too few alarms)" if g5["check_a_inconclusive_too_few_alarms"] else ""))
    L += ["", "Item 6 (phase separation) is B's; A reviews and closes it once B submits it.", "",
          "## Handoffs to B", "", "- A1: `results/handoff/A1_devices.csv`, `A1_attack_classes.csv`, `A1_features.json`",
          "- A10: `results/handoff/A10_benign_windows_index.csv` + the `benign__*.parquet` files it lists",
          "", "## For the protocol freeze", "",
          "- Every value marked `PROPOSED (A)` in protocol/protocol.yaml.",
          "- Feature set: ciciomt39 (proposed) vs cic45; the k grid tops out at the set size.",
          "- Attacks whose first attacker packet arrives long after the capture starts (see "
          "`first_attacker_packet_after_capture_start_s` in results/stage1/attacks.csv): onset at the capture boundary "
          "would add that time to every delay.",
          "- Gate 5 calibration study: results/stage1/gate5_calibration_study.json (method choice and the "
          "fixed-threshold marginal-shift diagnostic).",
          "- CODEOWNERS: updated to the 21 Oct split on branch a/stage1-gates (B reviews)."]
    with open(STAGE1 / "GATE_REPORT.md", "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    print("\n".join(L))


def main():
    cfg = P.load()
    ensure(HANDOFF, STAGE1)
    a1(cfg)
    a10()
    gate_report(cfg)


if __name__ == "__main__":
    main()
