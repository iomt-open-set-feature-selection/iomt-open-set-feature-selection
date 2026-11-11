"""parse_pcap on a tiny synthetic pcap: flushing in chunks must not change the result."""
import dpkt
import numpy as np

from iomt.streams import pcap_parse


def write_pcap(path, n=7, arp_op=None):
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f)
        for i in range(n):
            tcp = dpkt.tcp.TCP(sport=1000 + i, dport=80, flags=dpkt.tcp.TH_SYN)
            ip = dpkt.ip.IP(src=b"\x0a\x00\x00\x01", dst=b"\x0a\x00\x00\x02", p=dpkt.ip.IP_PROTO_TCP,
                            data=tcp)
            ip.len = len(bytes(ip))
            eth = dpkt.ethernet.Ethernet(src=b"\xaa" * 6, dst=b"\xbb" * 6, type=dpkt.ethernet.ETH_TYPE_IP,
                                         data=ip)
            w.writepkt(bytes(eth), ts=1000.0 + i)
        w.writepkt(b"\x01\x02", ts=1010.0)  # too short to be an Ethernet frame
        if arp_op is not None:
            arp = dpkt.arp.ARP(op=arp_op, sha=b"\xaa" * 6, spa=b"\x0a\x00\x00\x01",
                               tha=b"\x00" * 6, tpa=b"\x0a\x00\x00\x02")
            eth = dpkt.ethernet.Ethernet(src=b"\xaa" * 6, dst=b"\xff" * 6, type=dpkt.ethernet.ETH_TYPE_ARP,
                                         data=arp)
            w.writepkt(bytes(eth), ts=1011.0)
    return path


def test_chunked_parse_equals_unchunked(tmp_path, monkeypatch):
    pcap = write_pcap(tmp_path / "t.pcap")
    whole, meta_whole = pcap_parse.parse_pcap(str(pcap))
    monkeypatch.setattr(pcap_parse, "CHUNK_ROWS", 3)  # 8 rows -> two flushes plus a tail
    chunked, meta_chunked = pcap_parse.parse_pcap(str(pcap))
    assert meta_whole["n_packets"] == 8 and meta_whole["parse_errors"] == 1
    assert chunked.dtype == whole.dtype == pcap_parse.PKT_DTYPE
    assert chunked.tobytes() == whole.tobytes()
    assert meta_chunked == meta_whole


def test_chunked_parse_keeps_truncation(tmp_path, monkeypatch):
    pcap = write_pcap(tmp_path / "t.pcap")
    monkeypatch.setattr(pcap_parse, "CHUNK_ROWS", 2)
    arr, meta = pcap_parse.parse_pcap(str(pcap), max_packets=5)
    assert len(arr) == 5 and meta == {"n_packets": 5, "truncated": True, "parse_errors": 0}


def test_arp_opcode_above_255_does_not_abort(tmp_path):
    arr, meta = pcap_parse.parse_pcap(str(write_pcap(tmp_path / "t.pcap", n=1, arp_op=300)))
    assert meta["n_packets"] == 3 and arr["arp_op"].tolist() == [0, 0, 0]
