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


def test_amended_count_enough_families(cfg):
    """Changelog A1: recorded families plus ramp families; the test above is unchanged."""
    ai = load_artifact(AI)
    assert_current_protocol(ai, "attack_inventory.json")
    if "amended_gate3" not in ai:
        note = ai.get("flood_pairs_note", "no amended count in attack_inventory.json; parse the floods and rerun")
        # only a null MAC list means the amended count is not in force; a missing flood folder is a failure
        (pytest.skip if "flood_attacker_macs is null" in note else pytest.fail)(note)
    am = ai["amended_gate3"]
    assert am["status"] == "complete", f"amended count is incomplete; no full parse for {am['missing_files']}"
    min_cls = int(P.require(cfg, "gate.min_non_flood_classes"))
    assert am["n_families_with_enough"] >= min_cls, (
        f"amended count: {am['recorded_families_enough']} recorded families + ramp attacks {am['ramp_attacks']}; "
        f"need {min_cls} families")
