"""Device inventory and usable-stream count (gate item 1, handoff A1).

Works from the parsed packet tables (pcap_parse). Devices are keyed by MAC,
because IPs can change between recording sessions. For every capture we record
which IPv4 address each device used there.

Roles, inferred from traffic (attacker excepted) and written out so they can be checked:
  gateway    MAC that forwards packets from >= 5 distinct public IPs
  attacker   MACs pinned in network.attacker_macs (protocol). The old rule, a MAC
             seen in attack captures but in no benign/profiling capture, is still
             computed and written as attackers_inferred, as a cross-check only
  broker     IP serving MQTT (source port in network.mqtt_ports) to >= 3 clients
  sim        IP inside network.sim_subnets (simulated MQTT fleet)
  device     every other host in network.lan_subnets that sends traffic
Device names come from the profiling captures named after a device
(Power/<Name>_Power.pcap, Interactions/<Name>/...): the busiest candidate host
in such a capture takes the name.

Usable stream (protocol gate.usable_stream): role device or broker, enough
benign activity, and (if required) present in a non-flood attack capture.

Output: results/stage1/device_inventory.json and device_inventory.csv
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

from iomt import protocol as P
from iomt.paths import INTERIM, STAGE1, ensure
from iomt.streams.captures import list_captures
from iomt.streams.pcap_parse import load_packets, out_path, u32_ip, u64_mac

BROADCAST_MAC = 0xFFFFFFFFFFFF


def _mac_u64(mac: str) -> int:
    return int(mac.replace(":", ""), 16)


def sessions(ts: np.ndarray, gap_seconds: float) -> list[tuple[float, float]]:
    """(first, last) of each recording session: a capture is cut where every
    device went silent for longer than ``gap_seconds``. The wall-clock gap
    between sessions is not observed time and must not count as benign data."""
    t = np.sort(np.asarray(ts, float))
    cuts = np.r_[0, np.flatnonzero(np.diff(t) > gap_seconds) + 1, len(t)]
    return [(float(t[a]), float(t[b - 1])) for a, b in zip(cuts[:-1], cuts[1:])]


def _nets(cidrs):
    return [ipaddress.ip_network(c) for c in cidrs]


def _in_nets(ip_u32: int, nets) -> bool:
    a = ipaddress.ip_address(int(ip_u32))
    return any(a in n for n in nets)


def _is_private(ip_u32: int) -> bool:
    return ipaddress.ip_address(int(ip_u32)).is_private


def _is_unicast_mac(m: int) -> bool:
    return m != BROADCAST_MAC and not ((m >> 40) & 1)


def parsed_captures(interim: Path, kinds=None):
    for c in list_captures():
        if kinds and c.kind not in kinds:
            continue
        if out_path(interim, c.capture_id).exists():
            yield c


def capture_host_table(pk: np.ndarray) -> pd.DataFrame:
    """(src_mac, src_ip) -> packets, for IPv4 packets."""
    v4 = pk[pk["ip_ver"] == 4]
    if len(v4) == 0:
        return pd.DataFrame(columns=["src_mac", "src_ip", "n"])
    df = pd.DataFrame({"src_mac": v4["src_mac"], "src_ip": v4["src_ip"]})
    return df.value_counts().rename("n").reset_index()


def device_mask(pk: np.ndarray, ips, macs) -> np.ndarray:
    """Packets that belong to a device's stream (sent by it, sent to it, or ARP about it)."""
    ips = np.asarray(sorted(ips), dtype=np.uint32)
    macs = np.asarray(sorted(macs), dtype=np.uint64)
    v4 = pk["ip_ver"] == 4
    m = v4 & (np.isin(pk["src_ip"], ips) | np.isin(pk["dst_ip"], ips))
    m |= ~v4 & (np.isin(pk["src_mac"], macs) | np.isin(pk["dst_mac"], macs))
    arp = pk["eth_type"] == 0x0806
    m |= arp & (np.isin(pk["arp_spa"], ips) | np.isin(pk["arp_tpa"], ips))
    return m


def outbound_mask(pk: np.ndarray, ips, macs) -> np.ndarray:
    ips = np.asarray(sorted(ips), dtype=np.uint32)
    macs = np.asarray(sorted(macs), dtype=np.uint64)
    v4 = pk["ip_ver"] == 4
    return (v4 & np.isin(pk["src_ip"], ips)) | (~v4 & np.isin(pk["src_mac"], macs))


def build_inventory(cfg: dict, interim: Path = INTERIM) -> dict:
    lan = _nets(P.get(cfg, "network.lan_subnets", ["192.168.137.0/24"]))
    sims = _nets(P.get(cfg, "network.sim_subnets", []))
    mqtt_ports = set(P.get(cfg, "network.mqtt_ports", [1883, 8883]))
    W = float(P.get(cfg, "streams.window_seconds", 1.0))
    crit = P.get(cfg, "gate.usable_stream", {}) or {}
    min_active = int(crit.get("min_benign_active_windows", 600))
    min_span = float(crit.get("min_benign_span_seconds", 1800))
    need_attack = bool(crit.get("require_attack_presence", True))
    min_att_pkts = int(crit.get("min_attack_capture_packets", 50))

    caps = list(parsed_captures(interim))
    if not caps:
        raise SystemExit(f"no parsed captures under {interim}; run pcap_parse first")
    benign_like = [c for c in caps if c.kind in ("benign", "profiling")]
    attack_caps = [c for c in caps if c.role == "attack"]

    # ---- pass 1: who sends what, where -------------------------------------
    mac_ips = defaultdict(Counter)            # mac -> ip -> pkts (IPv4 src)
    mac_caps = defaultdict(set)               # mac -> capture ids where it sent IPv4/ARP
    mac_public_srcs = defaultdict(set)        # mac -> public src IPs it carried
    cap_ip_mac = {}                           # capture -> {ip: mac} (dominant)
    mqtt_server_clients = defaultdict(set)    # ip -> client ips
    cap_meta = {}
    for c in caps:
        pk, meta = load_packets(interim, c.capture_id)
        cap_meta[c.capture_id] = meta
        ht = capture_host_table(pk)
        best = {}
        for r in ht.itertuples(index=False):
            mac, ip, n = int(r.src_mac), int(r.src_ip), int(r.n)
            if not _is_unicast_mac(mac):
                continue
            mac_caps[mac].add(c.capture_id)
            if _is_private(ip):
                mac_ips[mac][ip] += n
                if ip not in best or n > best[ip][1]:
                    best[ip] = (mac, n)
            else:
                mac_public_srcs[mac].add(ip)
        arp = pk[pk["eth_type"] == 0x0806]
        for mac in np.unique(arp["src_mac"]):
            if _is_unicast_mac(int(mac)):
                mac_caps[int(mac)].add(c.capture_id)
        cap_ip_mac[c.capture_id] = {ip: m for ip, (m, _) in best.items()}
        if c.kind in ("benign", "profiling"):
            tcp = pk[(pk["ip_ver"] == 4) & (pk["proto"] == 6)]
            srv = tcp[np.isin(tcp["sport"], list(mqtt_ports))]
            for s_ip, d_ip in zip(srv["src_ip"], srv["dst_ip"]):
                mqtt_server_clients[int(s_ip)].add(int(d_ip))
        del pk

    benign_ids = {c.capture_id for c in benign_like}
    gateways = {m for m, s in mac_public_srcs.items() if len(s) >= 5}
    inferred = {m for m, cs in mac_caps.items() if cs and not (cs & benign_ids) and m not in gateways}
    # An attack host that also idles during benign recording defeats the
    # "absent from benign captures" rule, so the protocol may pin it instead.
    pinned = [_mac_u64(m) for m in (P.get(cfg, "network.attacker_macs", []) or [])]
    attackers = set(pinned) if pinned else inferred
    brokers = {ip for ip, cl in mqtt_server_clients.items() if len(cl) >= 3}

    # ---- hosts (by MAC) ------------------------------------------------------
    hosts = {}
    for mac, ipc in mac_ips.items():
        if mac in gateways:
            role = "gateway"
        elif mac in attackers:
            role = "attacker"
        else:
            main_ip = ipc.most_common(1)[0][0]
            # sim before broker: the simulated fleet's own broker is not a device.
            if sims and _in_nets(main_ip, sims):
                role = "sim"
            elif main_ip in brokers:
                role = "broker"
            elif _in_nets(main_ip, lan):
                role = "device"
            else:
                role = "other_private"
        main_ip = ipc.most_common(1)[0][0]
        hosts[mac] = {
            "mac": u64_mac(mac), "mac_u64": mac, "role": role,
            "main_ip": u32_ip(main_ip),
            "ips": {u32_ip(i): int(n) for i, n in ipc.most_common()},
        }
    for mac in attackers - set(hosts):
        hosts[mac] = {"mac": u64_mac(mac), "mac_u64": mac, "role": "attacker",
                      "main_ip": None, "ips": {}}

    # ---- names from per-device profiling captures --------------------------
    name_votes = defaultdict(Counter)
    for c in benign_like:
        if c.kind != "profiling" or c.family not in ("power", "interaction"):
            continue
        name = re.sub(r"_(Power|LAN.*|WAN.*)$", "", c.subtype)
        pk, _ = load_packets(interim, c.capture_id)
        counts = Counter()
        for mac, h in hosts.items():
            if h["role"] not in ("device", "broker"):
                continue
            ip_here = [ip for ip, m in cap_ip_mac[c.capture_id].items() if m == mac]
            if not ip_here:
                continue
            counts[mac] = int(device_mask(pk, ip_here, [mac]).sum())
        if counts:
            mac, n = counts.most_common(1)[0]
            if n > 0:
                name_votes[mac][name] += 1
        del pk
    for mac, h in hosts.items():
        if name_votes.get(mac):
            h["name"] = name_votes[mac].most_common(1)[0][0]
            h["name_votes"] = dict(name_votes[mac])
        else:
            h["name"] = None

    # ---- activity per capture for candidate hosts -------------------------
    cand = [m for m, h in hosts.items() if h["role"] in ("device", "broker")]
    for mac in cand:
        hosts[mac]["captures"] = {}
    gap = float(P.get(cfg, "streams.session_gap_seconds", 300))
    for c in caps:
        pk, meta = load_packets(interim, c.capture_id)
        sess = sessions(pk["ts"], gap)
        for mac in cand:
            h = hosts[mac]
            ips = [ip for ip, m in cap_ip_mac[c.capture_id].items() if m == mac]
            if not ips:
                ips = [int(ipaddress.ip_address(h["main_ip"]))]
            m = device_mask(pk, ips, [mac])
            n = int(m.sum())
            if n == 0:
                continue
            ts = pk["ts"][m]
            active = int(len(np.unique(np.floor((ts - pk["ts"][0]) / W))))
            # Only sessions the device appears in, and only their recorded span:
            # the wall clock between sessions was never observed.
            span = sum(b - a for a, b in sess if ((ts >= a) & (ts <= b)).any())
            rec = {"ips": [u32_ip(i) for i in ips], "packets": n, "active_windows": active,
                   "span_s": float(span), "kind": c.kind, "family": c.family}
            if c.role == "attack":
                srcs = pk["src_mac"][m]
                rec["attacker_packets"] = int(np.isin(srcs, list(attackers)).sum())
            h["captures"][c.capture_id] = rec
        del pk

    # ---- usable --------------------------------------------------------------
    for mac in cand:
        h = hosts[mac]
        caps_h = h["captures"]
        b = [v for v in caps_h.values() if v["kind"] in ("benign", "profiling")]
        a = [k for k, v in caps_h.items() if v["kind"] == "non_flood" and v["packets"] >= min_att_pkts]
        h["benign_active_windows"] = int(sum(v["active_windows"] for v in b))
        h["benign_span_s"] = float(sum(v["span_s"] for v in b))
        h["non_flood_attack_captures"] = sorted(a)
        reasons = []
        if h["benign_active_windows"] < min_active:
            reasons.append(f"benign active windows {h['benign_active_windows']} < {min_active}")
        if h["benign_span_s"] < min_span:
            reasons.append(f"benign span {h['benign_span_s']:.0f}s < {min_span:.0f}s")
        if need_attack and not a:
            reasons.append("absent from every non-flood attack capture")
        h["usable"] = not reasons
        h["unusable_reasons"] = reasons

    # One device can use several MACs across recording sessions. device_mask
    # keys on IP, so those hosts carry the same packets: keep only the busiest.
    same_ip = defaultdict(list)
    for mac in cand:
        if hosts[mac]["usable"]:
            same_ip[hosts[mac]["main_ip"]].append(mac)
    for ip, macs in same_ip.items():
        if len(macs) < 2:
            continue
        keep = max(macs, key=lambda m: sum(v["packets"] for v in hosts[m]["captures"].values()))
        for m in macs:
            if m != keep:
                hosts[m]["usable"] = False
                hosts[m]["unusable_reasons"].append(
                    f"duplicate IP stream: {ip} is already covered by {u64_mac(keep)}")

    used_ids = set()
    for mac in sorted(cand, key=lambda m: hosts[m]["main_ip"]):
        h = hosts[mac]
        base = h["name"] or ("broker" if h["role"] == "broker" else
                             "dev_" + h["main_ip"].replace(".", "_"))
        did = base
        i = 2
        while did in used_ids:
            did = f"{base}_{i}"
            i += 1
        used_ids.add(did)
        h["device_id"] = did

    inv = {
        "protocol_sha256": P.sha256(),
        "window_seconds": W,
        "criteria": {"min_benign_active_windows": min_active, "min_benign_span_seconds": min_span,
                     "require_attack_presence": need_attack, "min_attack_capture_packets": min_att_pkts},
        "captures_parsed": {cid: {k: m.get(k) for k in ("n_packets", "truncated", "kind", "family", "split")}
                            for cid, m in cap_meta.items()},
        "gateways": [u64_mac(m) for m in sorted(gateways)],
        "attackers": [u64_mac(m) for m in sorted(attackers)],
        "attackers_pinned_by_protocol": bool(pinned),
        "attackers_inferred": [u64_mac(m) for m in sorted(inferred)],
        "brokers": [u32_ip(i) for i in sorted(brokers)],
        "cap_ip_mac": {cid: {u32_ip(ip): u64_mac(m) for ip, m in d.items()} for cid, d in cap_ip_mac.items()},
        "hosts": sorted(hosts.values(), key=lambda h: (h["role"], h.get("main_ip") or "")),
    }
    usable = [h for h in inv["hosts"] if h.get("usable")]
    inv["n_usable_streams"] = len(usable)
    inv["usable_device_ids"] = [h["device_id"] for h in usable]
    return inv


def load_inventory(path: Path | None = None) -> dict:
    with open(path or STAGE1 / "device_inventory.json", encoding="utf-8") as f:
        return json.load(f)


def usable_devices(inv: dict) -> list[dict]:
    return [h for h in inv["hosts"] if h.get("usable")]


def device_ips_in(inv: dict, host: dict, capture_id: str) -> list[int]:
    """IPv4 addresses (as u32) the device used in a capture; falls back to its main IP."""
    d = inv["cap_ip_mac"].get(capture_id, {})
    ips = [ip for ip, m in d.items() if m == host["mac"]]
    if not ips and host.get("main_ip"):
        ips = [host["main_ip"]]
    return [int(ipaddress.ip_address(i)) for i in ips]


def attacker_macs(inv: dict) -> list[int]:
    return [_mac_u64(m) for m in inv["attackers"]]


def main(argv=None):
    ap = argparse.ArgumentParser(description="Device inventory and usable-stream count (gate 1)")
    ap.add_argument("--protocol", default=None)
    a = ap.parse_args(argv)
    cfg = P.load(a.protocol)
    inv = build_inventory(cfg)
    ensure(STAGE1)
    with open(STAGE1 / "device_inventory.json", "w", encoding="utf-8") as f:
        json.dump(inv, f, indent=1)
    rows = []
    for h in inv["hosts"]:
        rows.append({k: h.get(k) for k in ("device_id", "name", "role", "mac", "main_ip", "usable",
                                           "benign_active_windows", "benign_span_s")}
                    | {"non_flood_attack_captures": ";".join(h.get("non_flood_attack_captures", [])),
                       "unusable_reasons": "; ".join(h.get("unusable_reasons", []))})
    pd.DataFrame(rows).to_csv(STAGE1 / "device_inventory.csv", index=False)
    print(f"hosts: {Counter(h['role'] for h in inv['hosts'])}")
    print(f"gateways {inv['gateways']}  brokers {inv['brokers']}  attackers {inv['attackers']}")
    print(f"usable per-device streams: {inv['n_usable_streams']}  {inv['usable_device_ids']}")


if __name__ == "__main__":
    main()
