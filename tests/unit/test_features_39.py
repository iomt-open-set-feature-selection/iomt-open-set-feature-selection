"""39-feature values on hand-built packets (no data needed).

One window of four packets whose expected feature values are worked out by
hand in the test, so a change in the extraction shows up here before it
reaches the streams.
"""
import numpy as np
import pytest

from iomt.contracts import FEATURES_39
from iomt.streams.features import chunk_rows, stream_windows
from iomt.streams.pcap_parse import PKT_DTYPE

TCP, UDP = 6, 17
SYN, ACK = 0x02, 0x10


def pkt(**kw):
    return kw


def packets(*rows):
    arr = np.zeros(len(rows), dtype=PKT_DTYPE)
    for i, row in enumerate(rows):
        for k, v in row.items():
            arr[i][k] = v
    return arr


@pytest.fixture
def four():
    """TCP SYN to :80, SYN-ACK back, a DNS query, an ARP frame; 0.1 s apart."""
    return packets(
        pkt(ts=1000.0, frame_len=60, eth_type=0x0800, ip_ver=4, proto=TCP, ttl=64,
            ip_hl=20, l4_hl=20, tcp_flags=SYN, sport=1234, dport=80),
        pkt(ts=1000.1, frame_len=60, eth_type=0x0800, ip_ver=4, proto=TCP, ttl=128,
            ip_hl=20, l4_hl=20, tcp_flags=SYN | ACK, sport=80, dport=1234),
        pkt(ts=1000.2, frame_len=80, eth_type=0x0800, ip_ver=4, proto=UDP, ttl=64,
            ip_hl=20, l4_hl=8, sport=5353, dport=53),
        pkt(ts=1000.3, frame_len=42, eth_type=0x0806, arp_op=1),
    )


EXPECTED = {
    "Header_Length": (20 + 20 + 8 + 0) / 4,   # transport header; 0 for non-IP
    "Protocol Type": TCP,                      # mode over [6, 6, 17, 0]
    "Time_To_Live": (64 + 128 + 64 + 0) / 4,
    "Rate": 4.0,                               # 4 packets / 1 s window
    "fin_flag_number": 0.0, "syn_flag_number": 0.5, "rst_flag_number": 0.0,
    "psh_flag_number": 0.0, "ack_flag_number": 0.25,
    "ece_flag_number": 0.0, "cwr_flag_number": 0.0,
    "ack_count": 1.0, "syn_count": 2.0, "fin_count": 0.0, "rst_count": 0.0,
    "HTTP": 0.5, "HTTPS": 0.0, "DNS": 0.25, "Telnet": 0.0, "SMTP": 0.0,
    "SSH": 0.0, "IRC": 0.0, "TCP": 0.5, "UDP": 0.25, "DHCP": 0.0,
    "ARP": 0.25, "ICMP": 0.0, "IGMP": 0.0, "IPv": 0.75, "LLC": 1.0,
    "Tot sum": 242.0, "Min": 42.0, "Max": 80.0, "AVG": 60.5, "Tot size": 60.5,
    # Sample formula (streams.std_ddof = 1), as the released CSVs use:
    # lengths 60, 60, 80, 42 -> squared deviations sum to 723, over n - 1 = 3.
    "Std": np.sqrt(241.0), "Variance": 241.0,
    "IAT": 0.1,                                # mean gap inside the window
    "Number": 4.0,
}


def test_window_feature_values(four):
    win = stream_windows(four, np.ones(4, bool), 1000.0, 1001.0,
                         feature_set="ciciomt39", window_seconds=1.0)
    assert len(win) == 1
    row = win.iloc[0]
    assert set(EXPECTED) == set(FEATURES_39)
    for name, want in EXPECTED.items():
        assert row[name] == pytest.approx(want, rel=1e-9, abs=1e-9), name
    assert row["n_pkts"] == 4


def test_empty_windows_are_kept_as_zeros(four):
    """Silence is information: a window with no packets is all zeros, not dropped."""
    win = stream_windows(four, np.ones(4, bool), 1000.0, 1003.0,
                         feature_set="ciciomt39", window_seconds=1.0)
    assert len(win) == 3
    assert win["n_pkts"].tolist() == [4, 0, 0]
    assert (win.loc[1:, FEATURES_39].to_numpy() == 0).all()
    assert win["t_start"].tolist() == [0.0, 1.0, 2.0]
    assert win["t_end"].tolist() == [1.0, 2.0, 3.0]


def test_packets_outside_the_span_are_dropped(four):
    win = stream_windows(four, np.ones(4, bool), 1000.15, 1001.15,
                         feature_set="ciciomt39", window_seconds=1.0)
    assert win["n_pkts"].tolist() == [2]        # only the DNS and ARP frames
    assert win.iloc[0]["Rate"] == 2.0


def test_rate_is_per_second_not_per_window(four):
    win = stream_windows(four, np.ones(4, bool), 1000.0, 1001.0,
                         feature_set="ciciomt39", window_seconds=0.2)
    assert len(win) == 5
    assert win["n_pkts"].tolist() == [2, 2, 0, 0, 0]
    assert win["Rate"].tolist() == [10.0, 10.0, 0.0, 0.0, 0.0]   # 2 packets per 0.2 s


def test_chunk_rows_use_inverse_iat_for_rate(four):
    """Released-CSV mode: Rate = 1 / IAT, and a partial tail chunk is dropped."""
    rows = chunk_rows(four, feature_set="ciciomt39", chunk=2)
    assert len(rows) == 2
    assert rows["IAT"].tolist() == pytest.approx([0.1, 0.1])
    assert rows["Rate"].tolist() == pytest.approx([10.0, 10.0])
    assert chunk_rows(four, feature_set="ciciomt39", chunk=3).shape[0] == 1


def test_single_packet_window_has_zero_iat_and_variance():
    one = packets(pkt(ts=5.0, frame_len=100, eth_type=0x0800, ip_ver=4, proto=UDP,
                      ttl=10, ip_hl=20, l4_hl=8, sport=1, dport=2))
    win = stream_windows(one, np.ones(1, bool), 5.0, 6.0,
                         feature_set="ciciomt39", window_seconds=1.0)
    row = win.iloc[0]
    assert row["IAT"] == 0.0        # no gap to measure
    assert row["Variance"] == 0.0   # sample variance of one packet is undefined -> 0
    assert row["Std"] == 0.0
    assert row["Min"] == row["Max"] == row["AVG"] == 100.0


def test_std_ddof_reaches_the_features(four):
    """streams.std_ddof picks the divisor, so the protocol value must get through."""
    pop = stream_windows(four, np.ones(4, bool), 1000.0, 1001.0,
                         feature_set="ciciomt39", window_seconds=1.0, std_ddof=0)
    assert pop.iloc[0]["Variance"] == pytest.approx(723 / 4)   # population: over n
    assert pop.iloc[0]["Std"] == pytest.approx(np.sqrt(723 / 4))


def test_every_feature_column_is_finite_and_ordered(four):
    win = stream_windows(four, np.ones(4, bool), 1000.0, 1002.0,
                         feature_set="ciciomt39", window_seconds=1.0)
    assert list(win.columns) == ["t_start", "t_end", "n_pkts"] + FEATURES_39
    assert np.isfinite(win[FEATURES_39].to_numpy(float)).all()
