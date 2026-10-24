"""Shared schemas (ARCHITECTURE.md section 4). Both A and B approve changes here."""
from __future__ import annotations

import math
from dataclasses import dataclass, asdict

# Two feature sets ship with CICIoMT2024. protocol `feature_set` picks one.
#
# ciciomt39: the profiling-CSV header and the 2024 README feature table. Every
#   feature is defined over the window's own packets.
# cic45: the attack-CSV header (CICIoT2023 style). Several features are
#   flow-cumulative; Srate == Rate and Drate == 0 in the released rows.
FEATURES_39: list[str] = [
    "Header_Length", "Protocol Type", "Time_To_Live", "Rate",
    "fin_flag_number", "syn_flag_number", "rst_flag_number", "psh_flag_number",
    "ack_flag_number", "ece_flag_number", "cwr_flag_number",
    "ack_count", "syn_count", "fin_count", "rst_count",
    "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP",
    "ARP", "ICMP", "IGMP", "IPv", "LLC",
    "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "IAT", "Number", "Variance",
]
assert len(FEATURES_39) == 39

# Exactly the released CICIoMT2024 attack-CSV header, in order.
FEATURES_45: list[str] = [
    "Header_Length", "Protocol Type", "Duration", "Rate", "Srate", "Drate",
    "fin_flag_number", "syn_flag_number", "rst_flag_number", "psh_flag_number",
    "ack_flag_number", "ece_flag_number", "cwr_flag_number",
    "ack_count", "syn_count", "fin_count", "rst_count",
    "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP",
    "ARP", "ICMP", "IGMP", "IPv", "LLC",
    "Tot sum", "Min", "Max", "AVG", "Std", "Tot size",
    "IAT", "Number", "Magnitue", "Radius", "Covariance", "Variance", "Weight",
]
assert len(FEATURES_45) == 45

FEATURE_SETS = {"ciciomt39": FEATURES_39, "cic45": FEATURES_45}
DEFAULT_FEATURE_SET = "ciciomt39"


def features_for(cfg: dict | None) -> list[str]:
    """Feature names for the protocol's feature_set; checks protocol.features if filled."""
    name = (cfg or {}).get("feature_set") or DEFAULT_FEATURE_SET
    names = FEATURE_SETS[name]
    listed = (cfg or {}).get("features")
    if listed and list(listed) != names:
        raise ValueError(f"protocol.features does not match feature_set '{name}'")
    return list(names)

# 4.1 window stream: metadata columns, then FEATURES.
STREAM_META: dict[str, str] = {
    "stream_id": "str",
    "device_id": "str",
    "t_start": "float",      # seconds from stream start
    "t_end": "float",
    "segment": "str",        # benign | attack
    "family": "str",         # attack family or "benign"
    "attack_id": "str",      # "" for benign-only streams
    "onset_t": "float",      # NaN for benign-only streams
    "splice_id": "str",      # capture boundary this window sits next to ("" if none)
}
# Extra columns A adds (allowed by the contract: not features, never fed to a score).
STREAM_EXTRA: dict[str, str] = {
    "source_capture": "str",  # capture the window's packets came from
    "t_abs": "float",         # capture epoch time of window start (before any shift)
    "phase": "str",           # lifecycle phase from capture metadata (A10)
    "phase_detail": "str",    # capture subtype, e.g. Blink_Camera_LAN_MIC
    "n_pkts": "int",          # packets in the window
}
def stream_columns(features: list[str]) -> list[str]:
    return list(STREAM_META) + list(STREAM_EXTRA) + list(features)


def check_stream_frame(df, features: list[str]) -> list[str]:
    """Return a list of schema problems (empty list = OK)."""
    FEATURES = features
    problems = []
    for c in STREAM_META:
        if c not in df.columns:
            problems.append(f"missing column {c}")
    for c in FEATURES:
        if c not in df.columns:
            problems.append(f"missing feature {c}")
    if problems:
        return problems
    # Order matters: a column appended after the features (t_abs used to be)
    # silently shifts "the last len(FEATURES) columns" by one.
    if list(df.columns) != stream_columns(FEATURES):
        problems.append(f"columns are not in 4.1 order: {list(df.columns)}")
    if not df["segment"].isin(["benign", "attack"]).all():
        problems.append("segment must be benign|attack")
    if (df["t_end"] <= df["t_start"]).any():
        problems.append("t_end <= t_start")
    if not df["t_start"].is_monotonic_increasing:
        problems.append("t_start not increasing")
    feats = df[FEATURES].to_numpy(dtype=float)
    if not math.isfinite(float(abs(feats).sum())):
        problems.append("non-finite feature values")
    return problems


# 4.4 delay record
@dataclass
class DelayRecord:
    stream_id: str
    attack_id: str
    family: str
    selector: str
    k: int
    detector: str
    seed: int
    onset_t: float
    alarm_t: float          # NaN on a miss
    delay_s: float          # NaN on a miss
    detected_within_horizon: bool
    pre_onset_false_alarms: int
    benign_hours: float

    def to_dict(self):
        return asdict(self)
