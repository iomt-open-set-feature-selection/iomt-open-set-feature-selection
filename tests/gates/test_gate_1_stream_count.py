"""Gate item 1 (owner A, closed by B): at least gate.min_streams usable per-device IP streams."""
import hashlib

import pytest

from conftest import ROOT, assert_current_protocol, load_artifact
from iomt import protocol as P

pytestmark = pytest.mark.gate

INV = ROOT / "results" / "stage1" / "device_inventory.json"
MAN = ROOT / "data" / "processed" / "streams_manifest.json"


def test_usable_stream_count(cfg):
    inv = load_artifact(INV)
    man = load_artifact(MAN)
    assert_current_protocol(inv, "device_inventory.json")
    usable = set(inv["usable_device_ids"])
    with_benign = {i["device_id"] for i in man["streams"].values() if i.get("kind") == "benign"}
    n = len(usable & with_benign)
    need = int(P.require(cfg, "gate.min_streams"))
    assert n >= need, (f"only {n} usable per-device streams with benign windows (need {need}); "
                       "below the bar: stop and take the fallback")


def test_usable_devices_are_real_targets():
    inv = load_artifact(INV)
    for h in inv["hosts"]:
        if h.get("usable"):
            assert h["role"] in ("device", "broker"), f"{h['device_id']} has role {h['role']}"
            assert h["mac"] not in inv["attackers"] and h["mac"] not in inv["gateways"]


def test_manifest_hashes_match_files():
    man = load_artifact(MAN)
    assert_current_protocol(man, "streams_manifest.json")
    for sid, info in man["streams"].items():
        p = ROOT / "data" / "processed" / info["file"]
        assert p.exists(), f"{sid}: file missing"
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        assert h == info["sha256"], f"{sid}: SHA-256 mismatch"
