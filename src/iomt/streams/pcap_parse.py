"""Parse a pcap into a compact per-packet table (numpy structured array).

One row per frame. Everything the 45 window features need is kept, plus the
addresses needed to assign packets to devices. Output goes to
data/interim/packets/<capture_id>.npz and is reused by every later step.

Resumable: an existing, complete npz is skipped. Large captures can be capped
with --max-packets (the npz then records truncated=True).
"""
from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import time
from pathlib import Path

import dpkt
import numpy as np

PKT_DTYPE = np.dtype([
    ("ts", "f8"), ("frame_len", "u4"), ("eth_type", "u2"),
    ("src_mac", "u8"), ("dst_mac", "u8"),
    ("ip_ver", "u1"), ("src_ip", "u4"), ("dst_ip", "u4"),
    ("proto", "u1"), ("ttl", "u1"), ("ip_hl", "u2"), ("l4_hl", "u2"),
    ("ip_len", "u4"), ("payload_len", "u4"),
    ("tcp_flags", "u2"), ("sport", "u2"), ("dport", "u2"),
    ("arp_op", "u1"), ("arp_spa", "u4"), ("arp_tpa", "u4"), ("arp_sha", "u8"),
    ("igmp", "u1"),
])


def mac_u64(b: bytes) -> int:
    return int.from_bytes(b, "big")


def ip_u32(b: bytes) -> int:
    return struct.unpack("!I", b)[0]


def u32_ip(x: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", int(x)))


def u64_mac(x: int) -> str:
    return int(x).to_bytes(6, "big").hex(":")


def _reader(f):
    try:
        return dpkt.pcap.Reader(f)
    except ValueError:
        f.seek(0)
        return dpkt.pcapng.Reader(f)


def parse_pcap(path: str, max_packets: int | None = None):
    rows = []
    append = rows.append
    n = 0
    truncated = False
    errors = 0
    with open(path, "rb") as f:
        for ts, buf in _reader(f):
            if max_packets is not None and n >= max_packets:
                truncated = True
                break
            n += 1
            flen = len(buf)
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                errors += 1
                append((ts, flen, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
                continue
            etype = eth.type if eth.type is not None else 0
            smac = mac_u64(eth.src)
            dmac = mac_u64(eth.dst)
            ipver = sip = dip = proto = ttl = iphl = l4hl = iplen = plen = 0
            flags = sport = dport = 0
            arp_op = spa = tpa = sha = 0
            igmp = 0
            d = eth.data
            if isinstance(d, dpkt.ip.IP):
                ipver = 4
                sip, dip = ip_u32(d.src), ip_u32(d.dst)
                proto, ttl, iphl, iplen = d.p, d.ttl, d.hl * 4, d.len
                l4 = d.data
            elif isinstance(d, dpkt.ip6.IP6):
                ipver = 6
                proto, ttl, iphl, iplen = d.nxt, d.hlim, 40, d.plen + 40
                l4 = d.data
            elif isinstance(d, dpkt.arp.ARP):
                arp_op = d.op
                if len(d.spa) == 4 and len(d.tpa) == 4:
                    spa, tpa = ip_u32(d.spa), ip_u32(d.tpa)
                sha = mac_u64(d.sha) if len(d.sha) == 6 else 0
                l4 = None
            else:
                l4 = None
            if ipver:
                if isinstance(l4, dpkt.tcp.TCP):
                    flags, sport, dport = l4.flags, l4.sport, l4.dport
                    l4hl = l4.off * 4
                    plen = len(l4.data)
                elif isinstance(l4, dpkt.udp.UDP):
                    sport, dport, l4hl = l4.sport, l4.dport, 8
                    plen = len(l4.data)
                elif isinstance(l4, (bytes, bytearray)):
                    plen = len(l4)
                else:
                    try:
                        l4hl = len(l4.pack_hdr())
                        plen = len(l4.data) if hasattr(l4, "data") else 0
                    except Exception:
                        pass
                if proto == 2:
                    igmp = 1
            append((ts, flen, etype, smac, dmac, ipver, sip, dip, proto, ttl, iphl,
                    l4hl, iplen, plen, flags, sport, dport, arp_op, spa, tpa, sha, igmp))
    arr = np.array(rows, dtype=PKT_DTYPE)
    return arr, {"n_packets": int(n), "truncated": truncated, "parse_errors": errors}


def out_path(interim: Path, capture_id: str) -> Path:
    return interim / "packets" / (capture_id + ".npz")


def load_packets(interim: Path, capture_id: str):
    z = np.load(out_path(interim, capture_id), allow_pickle=False)
    meta = json.loads(str(z["meta"]))
    return z["pkts"], meta


def run(capture, interim: Path, max_packets=None, force=False) -> dict:
    op = out_path(interim, capture.capture_id)
    if op.exists() and not force:
        _, meta = load_packets(interim, capture.capture_id)
        if max_packets is None and meta.get("truncated"):
            pass  # re-parse fully
        else:
            return meta
    op.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    arr, meta = parse_pcap(capture.path, max_packets)
    meta.update(capture.to_dict())
    meta["max_packets"] = max_packets
    meta["parse_seconds"] = round(time.time() - t0, 2)
    tmp = op.with_suffix(".tmp.npz")
    np.savez_compressed(tmp, pkts=arr, meta=np.array(json.dumps(meta)))
    tmp.replace(op)
    return meta


def main(argv=None):
    from iomt.paths import INTERIM
    from iomt.streams.captures import list_captures
    ap = argparse.ArgumentParser(description="Parse pcaps into data/interim/packets/*.npz")
    ap.add_argument("--interim", default=str(INTERIM))
    ap.add_argument("--kinds", nargs="*", default=["benign", "non_flood", "profiling"],
                    help="capture kinds to parse: benign non_flood profiling flood")
    ap.add_argument("--ids", nargs="*", help="capture ids (overrides --kinds)")
    ap.add_argument("--max-packets", type=int, default=None,
                    help="cap every capture at this many packets (floods: use 300000)")
    ap.add_argument("--budget", type=float, default=1e9, help="stop after N seconds")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args(argv)
    caps = list_captures()
    if a.ids:
        caps = [c for c in caps if c.capture_id in set(a.ids)]
    else:
        caps = [c for c in caps if c.kind in set(a.kinds)]
    t0 = time.time()
    done = 0
    for c in caps:
        if time.time() - t0 > a.budget:
            print("budget reached; re-run to continue", file=sys.stderr)
            break
        mp = a.max_packets
        op = out_path(Path(a.interim), c.capture_id)
        if op.exists() and not a.force:
            continue
        meta = run(c, Path(a.interim), mp, a.force)
        done += 1
        print(f"{c.capture_id}: {meta['n_packets']} pkts truncated={meta['truncated']} "
              f"{meta['parse_seconds']}s", flush=True)
    remaining = [c.capture_id for c in caps if not out_path(Path(a.interim), c.capture_id).exists()]
    print(f"parsed {done}; remaining {len(remaining)}")
    return 0 if not remaining else 3


if __name__ == "__main__":
    sys.exit(main())
