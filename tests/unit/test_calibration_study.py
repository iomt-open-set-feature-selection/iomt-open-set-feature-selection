"""Gate 5 study helpers: chronological inner split and the pre-stated choice rule (no data)."""
import numpy as np

from iomt.validity.calibration_study import choose, inner_halves


def test_inner_halves_is_chronological_and_complete():
    segs = [np.arange(10.0), np.arange(100.0, 107.0)]
    cal, chk = inner_halves(segs, [0.5, 0.5])
    assert [len(x) for x in cal] == [5, 4] and [len(x) for x in chk] == [5, 3]
    for c, k, s in zip(cal, chk, segs):
        assert np.array_equal(np.r_[c, k], s) and c.max() < k.min()


def _p(order, ratio, alarms=100, failed=0):
    return {"order": order, "candidate": str(order), "ratio": ratio, "alarms": alarms,
            "devices_failed": failed}


def test_choose_takes_ratio_closest_to_one_in_log_terms():
    assert choose([_p(0, 0.5), _p(1, 1.9), _p(2, 1.3)], 30)["order"] == 2
    # Equal ratios: the earlier entry wins.
    assert choose([_p(0, 1.25), _p(1, 1.25)], 30)["order"] == 0


def test_choose_skips_candidates_with_failures_or_too_few_alarms():
    assert choose([_p(0, 1.0, alarms=5), _p(1, 1.0, failed=1), _p(2, 0.6)], 30)["order"] == 2
    assert choose([_p(0, 1.0, alarms=5)], 30) is None
