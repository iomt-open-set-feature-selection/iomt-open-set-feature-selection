"""Gate item 4 (owner A per the 21 Oct split, closed by B): block size chosen;
mean |ACF| at the block lag below validity.acf_threshold on every device."""
import pytest

from conftest import ROOT, assert_current_protocol, load_artifact
from iomt import protocol as P

pytestmark = pytest.mark.gate

BS = ROOT / "results" / "audit" / "block_size.json"
INV = ROOT / "results" / "stage1" / "device_inventory.json"


def test_block_size_below_threshold_on_every_device(cfg):
    bs = load_artifact(BS)
    inv = load_artifact(INV)
    assert_current_protocol(bs, "block_size.json")
    thr = float(P.require(cfg, "validity.acf_threshold"))
    assert bs["acf_threshold"] == thr
    assert bs["block_windows"], f"no block size in the grid works: {bs['devices_without_any_block']}"
    missing = set(inv["usable_device_ids"]) - set(bs["per_device"])
    assert not missing, f"usable devices without an ACF measurement: {missing}"
    above = {d: a for d, a in bs["mean_abs_acf_at_block"].items() if a is None or a >= thr}
    assert not above, f"mean |ACF| >= {thr} at block {bs['block_windows']}: {above}"
