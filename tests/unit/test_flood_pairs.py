"""flood_pairs and the amended gate 3 count in the attack inventory, on hand-built flood captures."""
import json

import numpy as np
import pytest

from iomt import protocol as P
from iomt.streams import attack_inventory
from iomt.streams.captures import Capture
from iomt.streams.load import RAMP_BASE_CAPTURE
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


def syn(root, name):
    return Capture(f"attacks/train/{name}", str(root / "WiFI_and_MQTT" / "attacks" / "PCAP" / "train"
                   / (name + ".pcap")), "attack", "syn_flood", "flood", "train", "TCP_IP-DDoS-SYN", 0)


def test_flood_pairs(tmp_path, monkeypatch):
    root, interim, flood = tmp_path / "root", tmp_path / "interim", tmp_path / "flood"
    caps = [syn(root, "TCP_IP-DDoS-SYN1_train"), syn(root, "TCP_IP-DDoS-SYN2_train"),
            syn(root, "TCP_IP-DDoS-SYN3_train")]
    # SYN1: 3 attacker packets, 1 from another MAC, 1 reply from the device (not counted)
    save(flood, caps[0].capture_id, [(10.0, ATT, ATT_IP, DEV_IP), (11.0, ATT, ATT_IP, DEV_IP),
                                     (12.0, OTHER, ATT_IP, DEV_IP), (13.0, ATT, ATT_IP, DEV_IP),
                                     (14.0, DEV, DEV_IP, ATT_IP),
                                     # dev_b: flooded only by the unpinned MAC, on an IP that is not its main_ip
                                     (20.0, OTHER, ATT_IP, DEV2_IP), (21.0, OTHER, ATT_IP, DEV2_IP),
                                     (22.0, DEV2, DEV2_IP, ATT_IP)])
    save(flood, caps[1].capture_id, [(1.0, ATT, ATT_IP, DEV_IP)], truncated=True)  # capped: listed as skipped
    # SYN3 not parsed: not listed in flood_skipped
    # network.attacker_macs (inv["attackers"]) is not the flood attacker set
    inv = {"hosts": [{"usable": True, "mac": DEV, "device_id": "dev_a", "main_ip": "10.0.0.2", "role": "device",
                      "captures": {RAMP_BASE_CAPTURE: {"span_s": 4000.0}}},
                     {"usable": True, "mac": DEV2, "device_id": "dev_b", "main_ip": "10.0.0.9", "role": "device",
                      "captures": {RAMP_BASE_CAPTURE: {"span_s": 3599.0}}}],
           "attackers": [OTHER], "cap_ip_mac": {}}
    cfg = P.load()
    cfg["attack_set"]["flood_attacker_macs"] = [ATT]
    cfg["gate"].update(min_attacker_packets_per_attack=2, min_attacks_per_class=1)
    monkeypatch.setattr(attack_inventory, "list_captures", lambda: caps)
    monkeypatch.setattr(attack_inventory, "load_inventory", lambda: inv)
    rep, _ = attack_inventory.run(cfg, interim=interim, flood_interim=flood, root=root)
    assert rep["flood_pairs"] == [
        {"capture_id": caps[0].capture_id, "device_id": "dev_a", "ips_from": "capture", "ramp_family": "ramp_syn_flood",
         "attacker_packets": 3,
         "first_attacker_ts": 10.0, "last_attacker_ts": 13.0,
         "top_src_macs": [{"mac": ATT, "packets": 3}, {"mac": OTHER, "packets": 1}]},
        {"capture_id": caps[0].capture_id, "device_id": "dev_b", "ips_from": "capture", "ramp_family": "ramp_syn_flood",
         "attacker_packets": 0,
         "first_attacker_ts": None, "last_attacker_ts": None,
         "top_src_macs": [{"mac": OTHER, "packets": 2}]}]
    assert rep["flood_skipped"] == [{"capture_id": caps[1].capture_id, "reason": "parsed with a packet cap"}]
    assert rep["skipped_captures"] == []
    # one ramp attack on dev_a (3 >= 2 attacker packets); dev_b has no 3,600 s base. SYN2 (capped) and SYN3
    # (not parsed) are SYN files without a full parse, so the count is incomplete and not a pass.
    assert rep["amended_gate3"] == {
        "status": "incomplete", "missing_files": [caps[1].capture_id, caps[2].capture_id],
        "recorded_families_enough": 0, "ramp_attacks": {"ramp_syn_flood": 1, "ramp_mqtt_publish_flood": 0},
        "ramp_families_enough": 1, "n_families_with_enough": 1, "passes": False}
    assert rep["n_families_with_enough"] == 0 and "flood_pairs_note" not in rep

    # with every SYN file fully parsed the count is complete (still 1 family of 3: not a pass)
    monkeypatch.setattr(attack_inventory, "list_captures", lambda: caps[:1])
    am = attack_inventory.run(cfg, interim=interim, flood_interim=flood, root=root)[0]["amended_gate3"]
    assert am["status"] == "complete" and am["missing_files"] == [] and am["passes"] is False

    cfg["attack_set"]["flood_attacker_macs"] = None   # not set: no pairs, no amended count, reason given
    rep = attack_inventory.run(cfg, interim=interim, flood_interim=flood, root=root)[0]
    assert rep["flood_pairs"] == [] and "amended_gate3" not in rep and "flood_attacker_macs is null" in rep["flood_pairs_note"]

    cfg["attack_set"]["flood_attacker_macs"] = [ATT]
    monkeypatch.setattr(attack_inventory, "list_captures", lambda: [])
    rep = attack_inventory.run(cfg, interim=interim, flood_interim=flood, root=root)[0]
    assert rep["flood_pairs"] == [] and rep["flood_skipped"] == []


def test_no_flood_loop_without_a_separate_flood_folder(tmp_path, monkeypatch):
    root, interim = tmp_path / "root", tmp_path / "interim"
    c = syn(root, "TCP_IP-DDoS-SYN1_train")
    save(interim, c.capture_id, [(10.0, ATT, ATT_IP, DEV_IP)])
    inv = {"hosts": [{"usable": True, "mac": DEV, "device_id": "dev_a", "main_ip": "10.0.0.2", "role": "device"}],
           "attackers": [], "cap_ip_mac": {}}
    cfg = P.load()
    cfg["attack_set"]["flood_attacker_macs"] = [ATT]
    monkeypatch.setattr(attack_inventory, "list_captures", lambda: [c])
    monkeypatch.setattr(attack_inventory, "load_inventory", lambda: inv)
    for flood_interim, why in ((None, "IOMT_FLOOD_INTERIM is not set"),
                               (interim, "IOMT_FLOOD_INTERIM is the INTERIM folder"),
                               (interim / ".." / "interim", "IOMT_FLOOD_INTERIM is the INTERIM folder")):
        rep = attack_inventory.run(cfg, interim=interim, flood_interim=flood_interim, root=root)[0]
        assert rep["flood_pairs"] == [] and rep["flood_skipped"] == [] and "amended_gate3" not in rep
        assert why in rep["flood_pairs_note"]


def test_flood_attacker_mac_check():
    inv = {"hosts": [
        {"mac": "00:00:00:00:00:0a", "role": "device", "usable": True},
        {"mac": "00:00:00:00:00:0b", "role": "device", "usable": False},   # a device that is not usable may be listed
        {"mac": "00:00:00:00:00:0c", "role": "broker", "usable": False},
        {"mac": "00:00:00:00:00:0d", "role": "gateway"},
        {"mac": ATT, "role": "attacker"}]}
    attack_inventory.check_flood_macs([ATT, "00:00:00:00:00:0b"], inv)
    for bad in ("DC:A6:32:DC:27:D5", "dc:a6:32:dc:27", "dc-a6-32-dc-27-d5", "00:00:00:00:00:0a",
                "00:00:00:00:00:0c", "00:00:00:00:00:0d"):
        with pytest.raises(SystemExit, match="flood_attacker_macs"):
            attack_inventory.check_flood_macs([bad], inv)


def f(cid, t0, t1, ramp="ramp_syn_flood"):
    return {"capture_id": cid, "ramp_family": ramp, "capture_t0": t0, "capture_t1": t1}


def pair(cid, n, ips_from="capture", dev="dev_a", ramp="ramp_syn_flood"):
    return {"capture_id": cid, "ramp_family": ramp, "device_id": dev, "ips_from": ips_from, "attacker_packets": n}


def ramp(files, pairs, devs=("dev_a",)):
    return attack_inventory.ramp_attacks(files, pairs, "ramp_syn_flood", list(devs), 300, 20)


def test_ramp_attacks_gap_equal_to_the_limit_is_one_recording():
    pairs = [pair("a", 12), pair("b", 12)]       # 12 + 12 >= 20 in one recording, 12 < 20 in two
    assert ramp([f("a", 0, 100), f("b", 400, 500)], pairs) == 1
    assert ramp([f("a", 0, 100), f("b", 401, 500)], pairs) == 0


def test_ramp_attacks_a_middle_file_without_a_pair_row_still_joins_its_neighbours():
    files = [f("a", 0, 100), f("b", 350, 450), f("c", 700, 800)]     # gaps of 250 s
    pairs = [pair("a", 12), pair("c", 12)]                           # the device has no packets in b
    assert ramp(files, pairs) == 1
    assert ramp([files[0], files[2]], pairs) == 0                    # without b the gap is 600 s


def test_ramp_attacks_a_long_file_is_not_cut_and_overlapping_files_merge():
    assert ramp([f("a", 0, 5000), f("b", 100, 200)], [pair("a", 12), pair("b", 12)]) == 1


def test_ramp_attacks_count_only_capture_ips_base_devices_and_the_family():
    files = [f("a", 0, 10), f("b", 1000, 1010), f("c", 2000, 2010, ramp="ramp_mqtt_publish_flood")]
    pairs = [pair("a", 25, ips_from="inventory"), pair("a", 25, dev="dev_b"), pair("a", 25, ramp=None),
             pair("c", 25, ramp="ramp_mqtt_publish_flood"), pair("a", 0), pair("b", 25), pair("zzz", 25)]
    assert ramp(files, pairs) == 1
