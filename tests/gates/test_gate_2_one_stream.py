"""Gate item 2 (owner A, closed by B): one stream (benign + ARP spoofing) end to end.

Passes when the stream exists, matches the 4.1 schema, was re-extracted from
merged packets with the onset on a capture boundary, and an unspliced
capture's re-extracted features match its released CSV rows.
"""
import numpy as np
import pandas as pd
import pytest

from conftest import ROOT, assert_current_protocol, load_artifact
from iomt import protocol as P
from iomt.contracts import check_stream_frame, features_for

pytestmark = pytest.mark.gate

MAN = ROOT / "data" / "processed" / "streams_manifest.json"
CSVM = ROOT / "results" / "stage1" / "csv_match.json"


def _onset_streams(man):
    return {s: i for s, i in man["streams"].items()
            if i.get("kind") == "onset" and i.get("family") == "arp_spoofing"}


def test_onset_stream_end_to_end(cfg):
    man = load_artifact(MAN)
    assert_current_protocol(man, "streams_manifest.json")
    streams = _onset_streams(man)
    assert streams, "no benign + ARP spoofing onset stream in the manifest"
    sid, info = next(iter(streams.items()))
    assert info["extraction"] == "merged_packets"
    df = pd.read_parquet(ROOT / "data" / "processed" / info["file"])
    feats = features_for(cfg)
    assert check_stream_frame(df, feats) == []
    assert list(df.columns[-len(feats):]) == feats
    onset = df["onset_t"].unique()
    assert len(onset) == 1 and np.isfinite(onset[0])
    W = float(P.require(cfg, "streams.window_seconds"))
    assert abs(onset[0] / W - round(onset[0] / W)) < 1e-6, "onset not on a window boundary"
    seg = df["segment"].to_numpy()
    first_att = int(np.argmax(seg == "attack"))
    assert (seg[:first_att] == "benign").all() and (seg[first_att:] == "attack").all()
    assert df["t_start"].iloc[first_att] == pytest.approx(onset[0])
    assert df["source_capture"].iloc[first_att - 1] != df["source_capture"].iloc[first_att]
    assert df.loc[df.segment == "attack", "n_pkts"].sum() > 0
    assert df.loc[df.segment == "benign", "n_pkts"].sum() > 0
    assert info["n_attacker_packets"] > 0, "spliced attack capture has no attacker packets for this device"


def test_reextraction_matches_released_csv(cfg):
    """Distribution match, not a row match: see csv_match.py for why the
    released row order cannot be reproduced from the pcap."""
    cm = load_artifact(CSVM)
    assert_current_protocol(cm, "csv_match.json")
    assert cm["header_matches_protocol"], "protocol.features differ from the released CSV header"
    thr = float(P.require(cfg, "gate.csv_match_max_quantile_diff"))
    b = cm["best"]
    assert abs(b["row_count_ratio"] - 1) <= 0.01, (
        f"we build {b['our_rows']} rows against the release's {b['csv_rows']}: "
        "the packet filter does not match the release")
    # "not comparable" is a failure, not a pass: the released CSVs carry NaN and
    # inf, and a quantile comparison on those silently looks like agreement.
    assert not b["deterministic_unmeasured"], (
        "deterministic features with too few finite values in the release to compare: "
        f"{b['deterministic_unmeasured']}")
    diffs = {f: b["features"][f].get("quantile_rel_diff") for f in cm["deterministic_features"]}
    bad = {f: round(v, 4) for f, v in diffs.items() if v is not None and v > thr}
    assert not bad, f"deterministic features whose quantiles differ by more than {thr}: {bad}"
