"""flood_pairs in the attack inventory, on one hand-built flood capture."""
import json

import numpy as np

from iomt import protocol as P
from iomt.streams import attack_inventory
from iomt.streams.captures import Capture
from iomt.streams.pcap_parse import PKT_DTYPE, out_path

ATT, OTHER, DEV = "dc:a6:32:dc:27:d5", "fa:3a:d3:4c:e3:37", "00:00:00:00:00:01"
DEV2 = "00:00:00:00:00:02"
DEV_IP, ATT_IP, DEV2_IP = 0x0A000002, 0x0A000001, 0x0A000003


def mac(m):
    return int(m.replace(":", ""), 16)


def packets(rows):
    arr = np.zeros(len(rows), dtype=PKT_DTYPE)
    for i, (ts, src, sip, dip) in enumerate(rows):
        arr[i]["ts"], arr[i]["src_mac"], arr[i]["ip_ver"] = ts, mac(src), 4
        arr[i]["src_ip"], arr[i]["dst_ip"] = sip, dip
    return arr


def save(interim, cid, rows, truncated=False):
    op = out_path(interim, cid)
    op.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(op, pkts=packets(rows), meta=np.array(json.dumps({"truncated": truncated})))


def test_flood_pairs(tmp_path, monkeypatch):
    root = tmp_path / "root"
    cap = lambda name: Capture(f"attacks/train/{name}", str(root / "WiFI_and_MQTT" / "attacks" / "PCAP" / "train"
                               / (name + ".pcap")), "attack", "syn_flood", "flood", "train", "DDoS-SYN", 0)
    caps = [cap("TCP_IP-DDoS-SYN1_train"), cap("TCP_IP-DDoS-SYN2_train"), cap("TCP_IP-DDoS-SYN3_train")]
    # SYN1: 3 attacker packets, 1 from another MAC, 1 reply from the device (not counted)
    save(tmp_path, caps[0].capture_id, [(10.0, ATT, ATT_IP, DEV_IP), (11.0, ATT, ATT_IP, DEV_IP),
                                        (12.0, OTHER, ATT_IP, DEV_IP), (13.0, ATT, ATT_IP, DEV_IP),
                                        (14.0, DEV, DEV_IP, ATT_IP),
                                        # dev_b: flooded only by the unpinned MAC, on an IP that is not its main_ip
                                        (20.0, OTHER, ATT_IP, DEV2_IP), (21.0, OTHER, ATT_IP, DEV2_IP),
                                        (22.0, DEV2, DEV2_IP, ATT_IP)])
    save(tmp_path, caps[1].capture_id, [(1.0, ATT, ATT_IP, DEV_IP)], truncated=True)  # capped: listed as skipped
    # SYN3 not parsed: not listed anywhere
    inv = {"hosts": [{"usable": True, "mac": DEV, "device_id": "dev_a", "main_ip": "10.0.0.2"},
                     {"usable": True, "mac": DEV2, "device_id": "dev_b", "main_ip": "10.0.0.9"}],
           "attackers": [ATT], "cap_ip_mac": {}}
    monkeypatch.setattr(attack_inventory, "list_captures", lambda: caps)
    monkeypatch.setattr(attack_inventory, "load_inventory", lambda: inv)
    rep, _ = attack_inventory.run(P.load(), interim=tmp_path, root=root)
    assert rep["flood_pairs"] == [
        {"capture_id": caps[0].capture_id, "device_id": "dev_a", "ips_from": "capture", "attacker_packets": 3,
         "first_attacker_ts": 10.0, "last_attacker_ts": 13.0,
         "top_src_macs": [{"mac": ATT, "packets": 3}, {"mac": OTHER, "packets": 1}]},
        {"capture_id": caps[0].capture_id, "device_id": "dev_b", "ips_from": "capture", "attacker_packets": 0,
         "first_attacker_ts": None, "last_attacker_ts": None,
         "top_src_macs": [{"mac": OTHER, "packets": 2}]}]
    assert rep["flood_skipped"] == [{"capture_id": caps[1].capture_id, "reason": "parsed with a packet cap"}]
    assert rep["skipped_captures"] == []

    monkeypatch.setattr(attack_inventory, "list_captures", lambda: [])
    rep = attack_inventory.run(P.load(), interim=tmp_path, root=root)[0]
    assert rep["flood_pairs"] == [] and rep["flood_skipped"] == []
