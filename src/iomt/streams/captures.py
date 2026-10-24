"""Catalog of CICIoMT2024 Wi-Fi/MQTT packet captures.

Every capture gets a stable id, a role (benign / attack / profiling) and, for
attacks, a family from the frozen attack set. Paths are relative to the
CICIoMT2024 root, which is passed in (env IOMT_CICIOMT_ROOT or --root).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path

DEFAULT_ROOT = os.environ.get(
    "IOMT_CICIOMT_ROOT",
    str(Path(__file__).resolve().parents[4] / "DATASETS" / "CICIoMT2024"),
)

# Attack family per capture-name prefix. Non-flood families are the ones the
# study is about; floods are the floor. Order matters: first match wins.
FAMILY_RULES = [
    (r"^ARP_Spoofing", "arp_spoofing", "non_flood"),
    (r"^Recon-", "recon", "non_flood"),
    (r"^MQTT-Malformed", "malformed_mqtt", "non_flood"),
    (r"^MQTT-DD?oS-Publish", "mqtt_publish_flood", "flood"),
    (r"^MQTT-DD?oS-Connect", "mqtt_connect_flood", "flood"),
    (r"^TCP_IP-DD?oS-SYN", "syn_flood", "flood"),
    (r"^TCP_IP-DD?oS-TCP", "tcp_flood", "flood"),
    (r"^TCP_IP-DD?oS-UDP", "udp_flood", "flood"),
    (r"^TCP_IP-DD?oS-ICMP", "icmp_flood", "flood"),
    (r"^Benign", "benign", "benign"),
]


@dataclass
class Capture:
    capture_id: str      # e.g. "attacks/train/ARP_Spoofing_train"
    path: str            # absolute path
    role: str            # benign | attack | profiling
    family: str          # attack family, "benign", or profiling phase
    kind: str            # non_flood | flood | benign | profiling
    split: str           # train | test | profiling
    subtype: str         # e.g. Recon-Port_Scan, Idle, Blink_Camera_LAN_MIC
    size_bytes: int

    def to_dict(self):
        return asdict(self)


def _family(name: str):
    for pat, fam, kind in FAMILY_RULES:
        if re.match(pat, name):
            return fam, kind
    raise ValueError(f"no family rule for capture {name}")


def _subtype(stem: str) -> str:
    s = re.sub(r"_(train|test)$", "", stem)
    return re.sub(r"\d+$", "", s)  # DDoS-UDP3 -> DDoS-UDP


def profiling_phase(rel: Path) -> str:
    """Lifecycle phase from the profiling folder name (CICIoMT2024 layout)."""
    top = rel.parts[0].lower()
    return {"active": "active", "broker": "active", "idle": "idle",
            "interactions": "interaction", "power": "power"}.get(top, top)


def list_captures(root: str | None = None) -> list[Capture]:
    root = Path(root or DEFAULT_ROOT) / "WiFI_and_MQTT"
    out: list[Capture] = []
    for split in ("train", "test"):
        for p in sorted((root / "attacks" / "PCAP" / split).glob("*.pcap")):
            stem = p.stem
            fam, kind = _family(stem)
            # The release ships TCP_IP-DoS-ICMP1_train.pcap inside test/; keep
            # the folder as the split and flag it in the id.
            cid = f"attacks/{split}/{stem}"
            out.append(Capture(cid, str(p), "benign" if fam == "benign" else "attack",
                               fam, kind, split, _subtype(stem), p.stat().st_size))
    prof = root / "profiling" / "PCAP"
    for p in sorted(prof.rglob("*.pcap")):
        rel = p.relative_to(prof)
        out.append(Capture(f"profiling/{rel.with_suffix('').as_posix()}", str(p),
                           "profiling", profiling_phase(rel), "profiling",
                           "profiling", p.stem, p.stat().st_size))
    return out


def by_id(captures=None, root=None) -> dict[str, Capture]:
    return {c.capture_id: c for c in (captures or list_captures(root))}
