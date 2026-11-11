"""benign_segments leaves out the last attack_set.ramp_reserved_seconds of each Benign_train stream."""
import numpy as np
import pandas as pd

from iomt.streams import load


def test_reserved_windows_are_absent(tmp_path, monkeypatch):
    streams = {  # stream id -> (device, source capture, windows)
        "a_base": ("dev_a", "attacks/train/Benign_train", 5000),
        "a_prof": ("dev_a", "profiling/Active/Active", 4000),
        "b_short": ("dev_b", "attacks/train/Benign_train", 3000),   # shorter than 3,600 s: loses nothing
        "c_exact": ("dev_c", "attacks/train/Benign_train", 3600),    # nothing is left, so no segment
    }
    info = {}
    for sid, (dev, cap, n) in streams.items():
        pd.DataFrame({"t_abs": 1000.0 + np.arange(n), "n_pkts": 1}).to_parquet(tmp_path / f"{sid}.parquet")
        info[sid] = {"kind": "benign", "device_id": dev, "source_captures": [cap], "file": f"{sid}.parquet"}
    monkeypatch.setattr(load, "manifest", lambda: {"window_seconds": 1.0, "streams": info})
    monkeypatch.setattr(load, "PROCESSED", tmp_path)
    seg = load.benign_segments()
    base, prof = seg["dev_a"]
    assert len(base) == 5000 - 3600 and base["t_abs"].iloc[-1] == 1000.0 + 1399   # the first 1,400 windows stay
    assert len(prof) == 4000
    assert len(seg["dev_b"][0]) == 3000
    assert "dev_c" not in seg


def test_a10_usable_windows(tmp_path, monkeypatch):
    from iomt import handoff, protocol as P
    info = {}
    for sid, cap, n in (("base", "attacks/train/Benign_train", 5000), ("short", "attacks/train/Benign_train", 3000),
                        ("prof", "profiling/Active/Active", 4000)):
        pd.DataFrame({"t_abs": 1000.0 + np.arange(n), "n_pkts": 1}).to_parquet(tmp_path / f"{sid}.parquet")
        info[sid] = {"kind": "benign", "device_id": "dev_" + sid, "source_captures": [cap], "file": f"{sid}.parquet",
                     "n_windows": n, "n_packets": n, "sha256": "x", "phase": None, "phase_detail": None}
    monkeypatch.setattr(handoff, "manifest", lambda: {"window_seconds": 1.0, "streams": info})
    monkeypatch.setattr(handoff, "PROCESSED", tmp_path)
    monkeypatch.setattr(handoff, "HANDOFF", tmp_path)
    handoff.a10(P.load())
    idx = pd.read_csv(tmp_path / "A10_benign_windows_index.csv").set_index("stream_id")
    assert idx["usable_windows"].to_dict() == {"base": 5000 - 3600, "short": 3000, "prof": 4000}
    assert idx["n_windows"].to_dict() == {"base": 5000, "short": 3000, "prof": 4000}
