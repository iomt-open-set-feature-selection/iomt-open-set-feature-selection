"""gate.usable_stream.excluded_macs: an excluded host is never usable (dev_243)."""
import json

import numpy as np

from iomt import protocol as P
from iomt.streams import device_map
from iomt.streams.captures import Capture
from iomt.streams.pcap_parse import PKT_DTYPE, out_path

ATT, A, B = "dc:a6:32:dc:27:d5", "00:00:00:00:00:0a", "e6:aa:e4:09:fc:8a"
A_IP, B_IP, ATT_IP = 0xC0A8890A, 0xC0A8890B, 0xC0A88963      # 192.168.137.10, .11, .99


def save(interim, cid, rows, kind, family):
    arr = np.zeros(len(rows), dtype=PKT_DTYPE)
    for i, (ts, src, sip, dip) in enumerate(rows):
        arr[i]["ts"], arr[i]["src_mac"], arr[i]["ip_ver"] = ts, int(src.replace(":", ""), 16), 4
        arr[i]["src_ip"], arr[i]["dst_ip"] = sip, dip
    op = out_path(interim, cid)
    op.parent.mkdir(parents=True, exist_ok=True)
    meta = {"n_packets": len(rows), "truncated": False, "kind": kind, "family": family, "split": "train"}
    np.savez_compressed(op, pkts=arr, meta=np.array(json.dumps(meta)))


def test_excluded_mac_is_not_usable(tmp_path, monkeypatch):
    benign = [(1000.0 + t, m, ip, 0xC0A88901) for t in range(2000) for m, ip in ((A, A_IP), (B, B_IP))]
    attack = [(1000.0 + t, ATT, ATT_IP, ip) for t in range(60) for ip in (A_IP, B_IP)]
    save(tmp_path, "attacks/train/Benign_train", benign, "benign", "benign")
    save(tmp_path, "attacks/train/Recon-Port_Scan_train", attack, "non_flood", "recon")
    caps = [Capture("attacks/train/Benign_train", "", "benign", "benign", "benign", "train", "Benign", 0),
            Capture("attacks/train/Recon-Port_Scan_train", "", "attack", "recon", "non_flood", "train",
                    "Recon-Port_Scan", 0)]
    monkeypatch.setattr(device_map, "list_captures", lambda: caps)
    cfg = P.load()
    cfg["gate"]["usable_stream"]["excluded_macs"] = []
    inv = device_map.build_inventory(cfg, tmp_path)
    assert inv["n_usable_streams"] == 2                      # the data is otherwise valid for both hosts
    cfg["gate"]["usable_stream"]["excluded_macs"] = [B.upper()]
    inv = device_map.build_inventory(cfg, tmp_path)
    host = {h["mac"]: h for h in inv["hosts"]}
    assert inv["n_usable_streams"] == 1 and host[A]["usable"] and not host[B]["usable"]
    assert host[B]["unusable_reasons"] == ["excluded by gate.usable_stream.excluded_macs"]
