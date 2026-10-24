"""CICIoMT2024 features, re-extracted from packets.

Two feature sets (protocol ``feature_set``), two grouping modes.

Feature sets
------------
ciciomt39 (proposed default): the 2024 README table and profiling-CSV header.
  Every feature is computed over the packets of one window:
    Header_Length   mean transport-header length (TCP data offset, UDP 8, else 0)
    Protocol Type   mode of the IP protocol numbers (0 for non-IP)
    Time_To_Live    mean TTL / hop limit
    Rate            packets per second in the window
    *_flag_number   share of packets with that TCP flag
    ack/syn/fin/rst_count   number of packets with that flag
    HTTP..LLC       share of packets of that protocol (application protocols by port)
    Tot sum, Min, Max, AVG, Std, Variance   packet lengths in the window
    Tot size        mean packet length (equals AVG, as in the released CSVs)
    IAT             mean gap between consecutive packets in the window
    Number          packets in the window
cic45: the attack-CSV header (CICIoT2023 style). Flow-cumulative features;
  see packet_features_45 for the definitions used.

Grouping modes
--------------
stream: one device's packets cut into fixed time windows of
  ``window_seconds``. Empty windows are kept with all-zero features: silence
  is information. Rate = n / window_seconds.
chunk: all packets of a capture in consecutive chunks of 10, which is how the
  released CSV rows were built. Used only by the gate-2 comparison.
  Rate = 1 / IAT (what the released CSVs contain).
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from iomt.contracts import FEATURES_39, FEATURES_45

APP_PORTS = {
    "HTTP": (80, 8080),
    "HTTPS": (443,),
    "DNS": (53,),
    "Telnet": (23,),
    "SMTP": (25,),
    "SSH": (22,),
    # Port 194 only: the released CSVs score IRC as 0 everywhere, including the
    # 28746 Idle packets on 6667, which is an IoT control channel here, not IRC.
    "IRC": (194,),
    "DHCP": (67, 68),
}
FLAG_BITS = {"fin": 0x01, "syn": 0x02, "rst": 0x04, "psh": 0x08,
             "ack": 0x10, "ece": 0x40, "cwr": 0x80}
INDICATORS = list(APP_PORTS) + ["TCP", "UDP", "ARP", "ICMP", "IGMP", "IPv", "LLC"]
FLAG_COLS = [f"{k}_flag_number" for k in FLAG_BITS]

# Features that depend only on the packet itself (no flow, no timing). Gate 2
# requires these to match the released CSV rows.
DETERMINISTIC_39 = ["Protocol Type", "Time_To_Live", "Header_Length"] + FLAG_COLS + \
    ["ack_count", "syn_count", "fin_count", "rst_count"] + INDICATORS + \
    ["Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "Number", "Variance"]
DETERMINISTIC_45 = ["Protocol Type", "Duration"] + FLAG_COLS + INDICATORS + ["Tot size"]


def packet_base(pk: np.ndarray, length_field: str = "frame") -> pd.DataFrame:
    """Per-packet columns shared by both feature sets."""
    ipver = pk["ip_ver"]
    proto = pk["proto"].astype(np.int64)
    is_ip = ipver > 0
    flags = pk["tcp_flags"].astype(np.int64)
    is_tcp = is_ip & (proto == 6)
    sport, dport = pk["sport"], pk["dport"]
    if length_field == "frame":
        ln = pk["frame_len"].astype(np.float64)
    elif length_field == "ip":
        ln = np.where(is_ip, pk["ip_len"], pk["frame_len"]).astype(np.float64)
    else:
        raise ValueError(length_field)
    b = {
        "ts": pk["ts"].astype(np.float64),
        "len": ln,
        "l4_hl": np.where(is_ip, pk["l4_hl"], 0).astype(np.float64),
        "hdr": np.where(is_ip, pk["ip_hl"].astype(np.float64) + pk["l4_hl"], 0.0),
        "proto": np.where(is_ip, proto, 0).astype(np.int64),
        "ttl": pk["ttl"].astype(np.float64),
    }
    for name, bit in FLAG_BITS.items():
        b[f"{name}_flag_number"] = (is_tcp & ((flags & bit) != 0)).astype(np.float64)
    for name, ports in APP_PORTS.items():
        b[name] = (is_ip & (np.isin(sport, ports) | np.isin(dport, ports))).astype(np.float64)
    b["TCP"] = is_tcp.astype(np.float64)
    b["UDP"] = (is_ip & (proto == 17)).astype(np.float64)
    b["ARP"] = (pk["eth_type"] == 0x0806).astype(np.float64)
    b["ICMP"] = (is_ip & ((proto == 1) | (proto == 58))).astype(np.float64)
    b["IGMP"] = (is_ip & (proto == 2)).astype(np.float64)
    b["IPv"] = is_ip.astype(np.float64)
    b["LLC"] = (pk["eth_type"] != 0).astype(np.float64)
    return pd.DataFrame(b)


# --------------------------------------------------------------------------- 39

def _group_mode(values: np.ndarray, groups: np.ndarray) -> pd.Series:
    df = pd.DataFrame({"g": groups, "v": values})
    cnt = df.groupby(["g", "v"]).size().reset_index(name="n")
    cnt = cnt.sort_values(["g", "n", "v"], ascending=[True, False, True])
    return cnt.drop_duplicates("g").set_index("g")["v"]


def aggregate_39(base: pd.DataFrame, groups: np.ndarray, *, rate: str,
                 window_seconds: float | None = None, ddof: int = 1) -> pd.DataFrame:
    """39 features per group. ``groups`` is a non-decreasing int label per packet."""
    g = pd.Series(groups)
    grp = base.groupby(groups)
    n = grp.size()
    res = pd.DataFrame(index=n.index)
    res["Header_Length"] = grp["l4_hl"].mean()
    res["Protocol Type"] = _group_mode(base["proto"].to_numpy(), groups).reindex(n.index)
    res["Time_To_Live"] = grp["ttl"].mean()
    for c in FLAG_COLS:
        res[c] = grp[c].mean()
    for k in ("ack", "syn", "fin", "rst"):
        res[f"{k}_count"] = grp[f"{k}_flag_number"].sum()
    for c in INDICATORS:
        res[c] = grp[c].mean()
    ln = grp["len"]
    res["Tot sum"] = ln.sum()
    res["Min"] = ln.min()
    res["Max"] = ln.max()
    res["AVG"] = ln.mean()
    var = ln.var(ddof=ddof).fillna(0.0)
    res["Std"] = np.sqrt(var)
    res["Tot size"] = res["AVG"]
    ts = base["ts"].to_numpy()
    d = np.diff(ts, prepend=np.nan)
    same = g.to_numpy() == np.r_[-1, g.to_numpy()[:-1]]
    d = np.where(same, d, np.nan)
    res["IAT"] = pd.Series(d).groupby(groups).mean().fillna(0.0)
    res["Number"] = n.astype(float)
    res["Variance"] = var
    if rate == "per_window":
        res["Rate"] = n / float(window_seconds)
    elif rate == "inverse_iat":
        with np.errstate(divide="ignore"):
            res["Rate"] = np.where(res["IAT"] > 0, 1.0 / res["IAT"].where(res["IAT"] > 0, 1.0), 0.0)
    else:
        raise ValueError(rate)
    return res[FEATURES_39]


# --------------------------------------------------------------------------- 45

def _flow_ids(pk: np.ndarray, idle_timeout, active_timeout) -> np.ndarray:
    ipv4 = pk["ip_ver"] == 4
    a_addr = np.where(ipv4, pk["src_ip"].astype(np.uint64), pk["src_mac"])
    b_addr = np.where(ipv4, pk["dst_ip"].astype(np.uint64), pk["dst_mac"])
    a = (a_addr << np.uint64(16)) | pk["sport"].astype(np.uint64)
    b = (b_addr << np.uint64(16)) | pk["dport"].astype(np.uint64)
    lo, hi = np.minimum(a, b), np.maximum(a, b)
    proto = np.where(pk["ip_ver"] > 0, pk["proto"].astype(np.int64), -pk["eth_type"].astype(np.int64))
    if len(pk) == 0:
        return np.zeros(0, np.int64)
    key = pd.MultiIndex.from_arrays([proto, lo, hi]).factorize()[0]
    if idle_timeout is None and active_timeout is None:
        return key
    ts = pk["ts"]
    order = np.lexsort((ts, key))
    k_s, t_s = key[order], ts[order]
    new_key = np.r_[True, k_s[1:] != k_s[:-1]]
    gap = np.r_[np.inf, np.diff(t_s)]
    new_seg = new_key | (gap > (idle_timeout if idle_timeout is not None else np.inf))
    seg = np.cumsum(new_seg) - 1
    seg_start = t_s[new_seg][seg]
    sub = (np.floor((t_s - seg_start) / active_timeout).astype(np.int64)
           if active_timeout is not None else np.zeros(len(t_s), np.int64))
    fid_sorted = pd.MultiIndex.from_arrays([seg, sub]).factorize()[0]
    fid = np.empty_like(fid_sorted)
    fid[order] = fid_sorted
    return fid


def packet_features_45(pk: np.ndarray, base: pd.DataFrame, outbound: np.ndarray | None, *,
                       idle_timeout=60.0, active_timeout=300.0) -> pd.DataFrame:
    """Per-packet cic45 values (averaged over a group afterwards).

    Header_Length: flow-cumulative IP+transport header bytes. Duration: TTL.
    *_count: flow-cumulative flag counts. Tot sum/Min/Max/AVG/Std/Number: flow
    so far. IAT: gap to previous packet of the flow. Magnitue = sqrt(mean_in +
    mean_out), Radius = sqrt(var_in + var_out), Covariance = cov(length,
    outbound), Variance = var_in / var_out, Weight = n_in * n_out.
    """
    fid = _flow_ids(pk, idle_timeout, active_timeout)
    if outbound is None:
        ipv4 = pk["ip_ver"] == 4
        src = np.where(ipv4, pk["src_ip"].astype(np.uint64), pk["src_mac"])
        outbound = src == pd.Series(src).groupby(fid).transform("first").to_numpy()
    out = np.asarray(outbound, bool)
    ln = base["len"].to_numpy()
    f = {}
    f["Header_Length"] = base["hdr"].groupby(fid).cumsum().to_numpy()
    f["Protocol Type"] = base["proto"].to_numpy(np.float64)
    f["Duration"] = base["ttl"].to_numpy()
    for c in FLAG_COLS:
        f[c] = base[c].to_numpy()
    for k in ("ack", "syn", "fin", "rst"):
        f[f"{k}_count"] = base[f"{k}_flag_number"].groupby(fid).cumsum().to_numpy()
    for c in INDICATORS:
        f[c] = base[c].to_numpy()
    gl = pd.Series(ln).groupby(fid)
    cnt = pd.Series(ln).groupby(fid).cumcount().to_numpy() + 1.0
    csum = gl.cumsum().to_numpy()
    csq = pd.Series(ln * ln).groupby(fid).cumsum().to_numpy()
    mean = csum / cnt
    var = np.maximum(csq / cnt - mean * mean, 0.0)
    f["Tot sum"], f["Min"], f["Max"] = csum, gl.cummin().to_numpy(), gl.cummax().to_numpy()
    f["AVG"], f["Std"], f["Tot size"] = mean, np.sqrt(var), ln
    iat = base["ts"].groupby(fid).diff().fillna(0.0).to_numpy()
    f["IAT"], f["Number"] = iat, cnt

    def dstats(mask):
        m = mask.astype(np.float64)
        c = pd.Series(m).groupby(fid).cumsum().to_numpy()
        s = pd.Series(ln * m).groupby(fid).cumsum().to_numpy()
        q = pd.Series(ln * ln * m).groupby(fid).cumsum().to_numpy()
        safe = np.where(c > 0, c, 1.0)
        mu = np.where(c > 0, s / safe, 0.0)
        v = np.where(c > 0, np.maximum(q / safe - mu * mu, 0.0), 0.0)
        return c, s, mu, v

    n_in, _, mu_in, v_in = dstats(~out)
    n_out, s_out, mu_out, v_out = dstats(out)
    f["Magnitue"] = np.sqrt(mu_in + mu_out)
    f["Radius"] = np.sqrt(v_in + v_out)
    f["Covariance"] = s_out / cnt - mean * (n_out / cnt)
    f["Variance"] = np.where(v_out > 0, v_in / np.where(v_out > 0, v_out, 1.0), 0.0)
    f["Weight"] = n_in * n_out
    f["_inv_iat"] = np.where(iat > 0, 1.0 / np.where(iat > 0, iat, 1.0), 0.0)
    f["_out"] = out.astype(np.float64)
    return pd.DataFrame(f)


AVERAGED_45 = [c for c in FEATURES_45 if c not in ("Rate", "Srate", "Drate")]


def aggregate_45(pf: pd.DataFrame, groups: np.ndarray, *, rate: str,
                 window_seconds: float | None = None) -> pd.DataFrame:
    grp = pf.groupby(groups)
    res = grp[AVERAGED_45].mean()
    n = grp.size()
    if rate == "per_window":
        W = float(window_seconds)
        outs = grp["_out"].sum()
        res["Rate"] = n / W
        res["Srate"] = outs / W
        res["Drate"] = (n - outs) / W
    else:
        r = grp["_inv_iat"].mean()
        res["Rate"], res["Srate"], res["Drate"] = r, r, 0.0
    return res[FEATURES_45]


# ------------------------------------------------------------------- front door

def stream_windows(pk: np.ndarray, outbound: np.ndarray, t0: float, t1: float, *,
                   feature_set: str, window_seconds: float, length_field: str = "frame",
                   std_ddof: int = 1, idle_timeout=60.0, active_timeout=300.0) -> pd.DataFrame:
    """Fixed time windows covering [t0, t1) for one device's time-sorted packets.

    Returns t_start, t_end (relative to t0), n_pkts and the feature columns.
    """
    W = float(window_seconds)
    feats = FEATURES_39 if feature_set == "ciciomt39" else FEATURES_45
    n_win = max(1, int(np.ceil((t1 - t0) / W - 1e-9)))
    out = pd.DataFrame(0.0, index=np.arange(n_win), columns=feats)
    n_pkts = np.zeros(n_win, np.int64)
    if len(pk):
        w = np.floor((pk["ts"] - t0) / W).astype(np.int64)
        keep = (w >= 0) & (w < n_win)
        pk, w, ob = pk[keep], w[keep], np.asarray(outbound, bool)[keep]
        # Released pcaps are not perfectly time-sorted and IAT reads the row
        # order, so a few reordered frames would give negative gaps.
        order = np.argsort(pk["ts"], kind="stable")
        pk, w, ob = pk[order], w[order], ob[order]
    if len(pk):
        base = packet_base(pk, length_field)
        if feature_set == "ciciomt39":
            agg = aggregate_39(base, w, rate="per_window", window_seconds=W, ddof=std_ddof)
        else:
            pf = packet_features_45(pk, base, ob, idle_timeout=idle_timeout,
                                    active_timeout=active_timeout)
            agg = aggregate_45(pf, w, rate="per_window", window_seconds=W)
        out.loc[agg.index, feats] = agg.to_numpy()
        cnt = np.bincount(w, minlength=n_win)
        n_pkts[:] = cnt[:n_win]
    out.insert(0, "n_pkts", n_pkts)
    out.insert(0, "t_end", (np.arange(n_win) + 1) * W)
    out.insert(0, "t_start", np.arange(n_win) * W)
    return out


def chunk_rows(pk: np.ndarray, *, feature_set: str, chunk: int = 10,
               length_field: str = "frame", ddof: int = 1) -> pd.DataFrame:
    """Released-CSV style rows: consecutive chunks of ``chunk`` packets (partial tail dropped)."""
    n = (len(pk) // chunk) * chunk
    pk = pk[:n]
    groups = np.arange(n) // chunk
    base = packet_base(pk, length_field)
    if feature_set == "ciciomt39":
        return aggregate_39(base, groups, rate="inverse_iat", ddof=ddof)
    pf = packet_features_45(pk, base, None, idle_timeout=None, active_timeout=None)
    return aggregate_45(pf, groups, rate="inverse_iat")
