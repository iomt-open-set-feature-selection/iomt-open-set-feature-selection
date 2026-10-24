"""Build per-device window streams (ARCHITECTURE.md 4.1) and the manifest.

  python -m iomt.streams.build benign   one benign stream per (usable device,
                                        benign or profiling capture). These are
                                        handoff A10 and feed gates 4 and 5.
  python -m iomt.streams.build gate2    one onset stream: the tail of a benign
                                        capture spliced to the ARP spoofing
                                        capture at the capture boundary, with
                                        features re-extracted from the merged
                                        packets (gate item 2).

Files: data/processed/streams/<stream_id>.parquet
Manifest: data/processed/streams_manifest.json (SHA-256 per file)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re

import numpy as np
import pandas as pd

from iomt import protocol as P
from iomt.contracts import STREAM_META, check_stream_frame, features_for
from iomt.paths import INTERIM, MANIFEST, STREAMS, ensure
from iomt.streams.captures import by_id, list_captures
from iomt.streams.device_map import (attacker_macs, device_ips_in, device_mask, load_inventory,
                                     outbound_mask, sessions, usable_devices)
from iomt.streams.features import stream_windows
from iomt.streams.pcap_parse import load_packets, out_path


def _flat(capture_id: str) -> str:
    return capture_id.replace("/", "~")


def _sha256(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _settings(cfg):
    return dict(feature_set=P.get(cfg, "feature_set", "ciciomt39"),
                window_seconds=float(P.require(cfg, "streams.window_seconds")),
                length_field=P.get(cfg, "streams.length_field", "frame"),
                std_ddof=int(P.get(cfg, "streams.std_ddof", 1)),
                idle_timeout=P.get(cfg, "streams.flow_idle_timeout_s", 60),
                active_timeout=P.get(cfg, "streams.flow_active_timeout_s", 300))


def _mac_u64(mac: str) -> int:
    return int(mac.replace(":", ""), 16)


def device_packets(pk, inv, host, capture_id):
    ips = device_ips_in(inv, host, capture_id)
    mac = [_mac_u64(host["mac"])]
    m = device_mask(pk, ips, mac)
    sub = pk[m]
    return sub, outbound_mask(sub, ips, mac)


def phase_of(capture, host) -> tuple[str, str]:
    """(phase, phase_detail) from capture metadata, for handoff A10."""
    if capture.kind == "benign":
        return "unlabelled", capture.subtype
    fam = capture.family  # active | idle | interaction | power
    if fam in ("active", "idle"):
        return fam, capture.subtype
    named = re.sub(r"_(Power|LAN.*|WAN.*)$", "", capture.subtype)
    if host.get("name") and named == host["name"]:
        return fam, capture.subtype
    return f"background_{fam}", capture.subtype


def _frame(win: pd.DataFrame, features, **meta) -> pd.DataFrame:
    df = pd.DataFrame({k: meta[k] for k in meta}, index=win.index)
    df["t_start"], df["t_end"] = win["t_start"].to_numpy(), win["t_end"].to_numpy()
    df["n_pkts"] = win["n_pkts"].to_numpy()
    for f in features:
        df[f] = win[f].to_numpy(dtype=np.float64)
    first = list(STREAM_META) + ["source_capture", "t_abs", "phase", "phase_detail", "n_pkts"]
    return df[[c for c in first if c in df.columns] + list(features)]


def _write(df: pd.DataFrame, stream_id: str, manifest: dict, info: dict, features):
    probs = check_stream_frame(df, features)
    if probs:
        raise ValueError(f"{stream_id}: schema problems {probs}")
    ensure(STREAMS)
    path = STREAMS / f"{stream_id}.parquet"
    df.to_parquet(path, index=False)
    manifest["streams"][stream_id] = info | {
        "file": f"streams/{stream_id}.parquet", "sha256": _sha256(path),
        "n_windows": int(len(df)), "n_packets": int(df["n_pkts"].sum())}


def load_manifest():
    if MANIFEST.exists():
        with open(MANIFEST, encoding="utf-8") as f:
            return json.load(f)
    return {"streams": {}}


def save_manifest(m, cfg, st):
    m["protocol_sha256"] = P.sha256()
    m["feature_set"] = st["feature_set"]
    m["window_seconds"] = st["window_seconds"]
    m["features"] = features_for(cfg)
    ensure(MANIFEST.parent)
    with open(MANIFEST, "w", encoding="utf-8") as f:
        json.dump(m, f, indent=1, sort_keys=True)


def build_benign(cfg):
    st = _settings(cfg)
    feats = features_for(cfg)
    gap = float(P.require(cfg, "streams.session_gap_seconds"))
    inv = load_inventory()
    hosts = usable_devices(inv)
    m = load_manifest()
    caps = [c for c in list_captures() if c.kind in ("benign", "profiling")
            and out_path(INTERIM, c.capture_id).exists()]
    for c in caps:
        pk, meta = load_packets(INTERIM, c.capture_id)
        for si, (s0, s1) in enumerate(sessions(pk["ts"], gap)):
            t0, t1 = s0, s1 + 1e-6
            for h in hosts:
                if c.capture_id not in h.get("captures", {}):
                    continue
                sub, ob = device_packets(pk, inv, h, c.capture_id)
                in_session = (sub["ts"] >= t0) & (sub["ts"] <= s1)
                sub, ob = sub[in_session], ob[in_session]
                if len(sub) == 0:
                    continue
                win = stream_windows(sub, ob, t0, t1, **st)
                phase, detail = phase_of(c, h)
                sid = f"benign__{h['device_id']}__{_flat(c.capture_id)}__s{si}"
                df = _frame(win, feats, stream_id=sid, device_id=h["device_id"], segment="benign",
                            family="benign", attack_id="", onset_t=np.nan, splice_id="",
                            source_capture=c.capture_id, phase=phase, phase_detail=detail,
                            t_abs=t0 + win["t_start"].to_numpy())
                _write(df, sid, m, {"kind": "benign", "device_id": h["device_id"],
                                    "source_captures": [c.capture_id], "phase": phase,
                                    "phase_detail": detail, "capture_t0": t0,
                                    "session": si, "session_seconds": s1 - s0,
                                    "extraction": "device_packets_of_one_session"}, feats)
                print(f"{sid}: {len(df)} windows, {int(df['n_pkts'].sum())} packets", flush=True)
        del pk
    save_manifest(m, cfg, st)


def build_onset(cfg, benign_capture, attack_capture, family, device=None, pre_onset_seconds=3600.0):
    """Benign tail + attack capture for one device, spliced at the capture boundary."""
    st = _settings(cfg)
    feats = features_for(cfg)
    W = st["window_seconds"]
    inv = load_inventory()
    caps = by_id()
    hosts = {h["device_id"]: h for h in usable_devices(inv)}
    if device is None:
        att_pk = [(h.get("captures", {}).get(attack_capture, {}).get("attacker_packets", 0), d)
                  for d, h in hosts.items() if benign_capture in h.get("captures", {})]
        if not att_pk or max(att_pk)[0] == 0:
            raise SystemExit(f"no usable device is hit by attackers in {attack_capture}")
        device = max(att_pk)[1]
    h = hosts[device]
    bpk, _ = load_packets(INTERIM, benign_capture)
    apk, _ = load_packets(INTERIM, attack_capture)
    b_first, b_last = float(bpk["ts"][0]), float(bpk["ts"][-1])
    a_first, a_last = float(apk["ts"][0]), float(apk["ts"][-1])
    t0 = max(b_first, b_last - pre_onset_seconds)
    bsub, bob = device_packets(bpk, inv, h, benign_capture)
    keep = bsub["ts"] >= t0
    bsub, bob = bsub[keep], bob[keep]
    asub, aob = device_packets(apk, inv, h, attack_capture)
    # Onset on the first window boundary after the benign capture ends.
    onset_rel = math.ceil((b_last - t0 + 1e-9) / W) * W
    shift = (t0 + onset_rel) - a_first
    asub = asub.copy()
    asub["ts"] = asub["ts"] + shift
    merged = np.concatenate([bsub, asub])
    ob = np.concatenate([bob, aob])
    t1 = t0 + onset_rel + (a_last - a_first) + 1e-6
    win = stream_windows(merged, ob, t0, t1, **st)
    is_att = win["t_start"].to_numpy() >= onset_rel - 1e-9
    a_stem = attack_capture.split("/")[-1]
    attack_id = f"{family}__{a_stem}__{device}"
    sid = f"onset__{device}__{_flat(benign_capture)}__{_flat(attack_capture)}"
    splice = f"{benign_capture}|{attack_capture}"
    rel = win["t_start"].to_numpy()
    df = _frame(win, feats, stream_id=sid, device_id=device,
                segment=np.where(is_att, "attack", "benign"),
                family=np.where(is_att, family, "benign"), attack_id=attack_id,
                onset_t=onset_rel, splice_id=splice,
                source_capture=np.where(is_att, attack_capture, benign_capture),
                phase="unlabelled", phase_detail="",
                t_abs=np.where(is_att, a_first + (rel - onset_rel), t0 + rel))
    att_macs = attacker_macs(inv)
    first_att = asub["ts"][np.isin(asub["src_mac"], att_macs)]
    first_att_off = float(first_att.min() - (t0 + onset_rel)) if len(first_att) else None
    m = load_manifest()
    _write(df, sid, m, {
        "kind": "onset", "device_id": device, "family": family, "attack_id": attack_id,
        "source_captures": [benign_capture, attack_capture], "onset_t": onset_rel,
        "benign_seconds": onset_rel, "attack_seconds": a_last - a_first,
        "n_packets_benign": int(len(bsub)), "n_packets_attack": int(len(asub)),
        "n_attacker_packets": int(len(first_att)),
        "first_attacker_packet_after_onset_s": first_att_off,
        "extraction": "merged_packets", "time_shift_attack_s": shift}, feats)
    save_manifest(m, cfg, st)
    print(f"{sid}: {len(df)} windows; onset at {onset_rel:.0f}s; "
          f"{int(is_att.sum())} attack windows; first attacker packet +{first_att_off}s")
    return sid


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build window streams")
    ap.add_argument("what", choices=["benign", "gate2"])
    ap.add_argument("--benign-capture", default="attacks/train/Benign_train")
    ap.add_argument("--attack-capture", default="attacks/train/ARP_Spoofing_train")
    ap.add_argument("--device", default=None, help="device_id (default: most-attacked usable device)")
    ap.add_argument("--pre-onset-seconds", type=float, default=3600.0)
    a = ap.parse_args(argv)
    cfg = P.load()
    if a.what == "benign":
        build_benign(cfg)
    else:
        build_onset(cfg, a.benign_capture, a.attack_capture, "arp_spoofing", a.device,
                    a.pre_onset_seconds)


if __name__ == "__main__":
    main()
