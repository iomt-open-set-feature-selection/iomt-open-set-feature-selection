"""Gate item 3 (owner A per the 21 Oct split, closed by B): at least
gate.min_non_flood_classes non-flood classes, each with at least
gate.min_attacks_per_class attacks."""
import pytest

from conftest import ROOT, assert_current_protocol, load_artifact
from iomt import protocol as P

pytestmark = pytest.mark.gate

AI = ROOT / "results" / "stage1" / "attack_inventory.json"


def test_enough_non_flood_classes(cfg):
    ai = load_artifact(AI)
    assert_current_protocol(ai, "attack_inventory.json")
    assert not [s for s in ai["skipped_captures"] if s["reason"] != "not parsed"], ai["skipped_captures"]
    min_att = int(P.require(cfg, "gate.min_attacks_per_class"))
    min_cls = int(P.require(cfg, "gate.min_non_flood_classes"))
    min_pk = int(P.require(cfg, "gate.min_attacker_packets_per_attack"))
    counts = {}
    for a in ai["attacks"]:
        if a["attacker_packets"] >= min_pk:
            counts[a["family"]] = counts.get(a["family"], 0) + 1
    fams = [i["id"] for i in P.require(cfg, "attack_set.non_flood")]
    enough = [f for f in fams if counts.get(f, 0) >= min_att]
    assert len(enough) >= min_cls, f"attacks per family {counts}; need {min_cls} families with >= {min_att}"


def test_every_non_flood_capture_parsed():
    ai = load_artifact(AI)
    assert not ai["skipped_captures"], f"non-flood captures not analysed: {ai['skipped_captures']}"
