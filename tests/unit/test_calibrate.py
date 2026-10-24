"""Threshold calibration hits its target run length (no data needed).

Calibration is what matches the three detectors on false-alarm rate, so each
one has to land near the target ARL on benign blocks it did not see.
"""
import numpy as np
import pytest

from iomt.detectors.calibrate import calibrate, moving_block_bootstrap
from iomt.detectors.conformal_e import ConformalE
from iomt.detectors.cusum import Cusum
from iomt.detectors.threshold import Threshold

TARGET, TOL = 100.0, 0.25


def detectors():
    return [ConformalE(), Cusum(0.5), Threshold()]


@pytest.mark.parametrize("det", detectors(), ids=lambda d: d.name)
def test_calibrated_threshold_hits_the_target_arl_on_fresh_benign(det):
    rng = np.random.default_rng(7)
    det.fit_reference(rng.normal(size=500))
    cal = calibrate(det, [rng.normal(size=2000) for _ in range(3)], TARGET, rng)
    assert cal["reached"]
    fresh = rng.normal(size=20000)
    n = len(det.alarms(det.prepare(fresh, rng), cal["h"]))
    assert n > 0, "no alarms at all on 20000 benign blocks"
    assert abs(len(fresh) / n / TARGET - 1) <= TOL


def test_bootstrap_keeps_within_segment_blocks():
    rng = np.random.default_rng(0)
    segs = [np.arange(100.0), np.arange(1000.0, 1100.0)]
    seq = moving_block_bootstrap(segs, 500, 10, rng)
    assert len(seq) == 500
    # Every block of 10 is consecutive values from one segment.
    for i in range(0, 500, 10):
        assert np.allclose(np.diff(seq[i:i + 10]), 1.0)


def test_bootstrap_rejects_segments_shorter_than_one_block():
    rng = np.random.default_rng(0)
    with pytest.raises(ValueError):
        moving_block_bootstrap([np.arange(5.0)], 100, 10, rng)


def test_target_too_high_to_measure_shows_as_an_infinite_tuning_arl():
    """No alarms on the whole bootstrap means the threshold is unverified, and says so."""
    det = Threshold().fit_reference(np.random.default_rng(0).normal(size=500))
    rng = np.random.default_rng(0)
    cal = calibrate(det, [rng.normal(size=2000)], 1e12, rng)
    assert cal["arl_tune"] == float("inf")


def test_target_the_bracket_cannot_reach_comes_back_unreached():
    """CUSUM alarms on every block even at its top threshold if the target is absurd."""
    rng = np.random.default_rng(0)
    det = Cusum(0.5).fit_reference(rng.normal(size=500))
    cal = calibrate(det, [rng.normal(loc=50.0, size=2000)], 1e6, rng)
    assert cal["reached"] is False
    assert cal["arl_tune"] < 1e6


# --- gate 5 adjust loop (2026-10-24) -------------------------------------------

from iomt.detectors.calibrate import calibrate_contiguous, calibrate_with, candidate_label


@pytest.mark.parametrize("det", detectors(), ids=lambda d: d.name)
def test_contiguous_calibration_hits_the_target_arl_on_fresh_benign(det):
    rng = np.random.default_rng(11)
    det.fit_reference(rng.normal(size=500))
    cal = calibrate_contiguous(det, [rng.normal(size=10000) for _ in range(3)], TARGET, rng)
    assert cal["reached"] and cal["tune_alarms"] > 0
    fresh = rng.normal(size=20000)
    n = len(det.alarms(det.prepare(fresh, rng), cal["h"]))
    assert n > 0
    assert abs(len(fresh) / n / TARGET - 1) <= 0.35


def test_contiguous_calibration_restarts_at_segment_starts():
    # Two segments; the restart index means no statistic carries across them.
    det = Cusum(0.5).fit_reference(np.zeros(100) + np.r_[np.ones(50), -np.ones(50)])
    rng = np.random.default_rng(0)
    cal = calibrate_contiguous(det, [np.full(30, 0.9), np.full(30, 0.9)], 1e9, rng)
    assert cal["tune_blocks"] == 60


def test_calibrate_with_dispatches_and_labels():
    rng = np.random.default_rng(3)
    det = Threshold().fit_reference(rng.normal(size=500))
    segs = [rng.normal(size=3000)]
    a = calibrate_with(det, segs, TARGET, rng, method="mbb", mbb_len_blocks=30)
    b = calibrate_with(det, segs, TARGET, rng, method="contiguous")
    assert a["method"] == "mbb" and a["mbb_len_blocks"] == 30
    assert b["method"] == "contiguous" and b["mbb_len_blocks"] is None
    assert candidate_label({"method": "mbb", "mbb_len_blocks": 30}) == "mbb30"
    assert candidate_label({"method": "contiguous"}) == "contiguous"
    with pytest.raises(ValueError):
        calibrate_with(det, segs, TARGET, rng, method="nope")


def test_short_resamples_under_state_dependence_and_contiguous_does_not():
    # AR(1) block scores, phi = 0.9, CUSUM. One-block resamples destroy the
    # dependence, so CUSUM's threshold comes out too low and fresh data alarms
    # far more often than nominal (ratio about 0.2). Calibrating on the real
    # order keeps the dependence and lands near 1. (A fixed per-block threshold
    # only sees the marginal distribution, so resample length cannot matter to it.)
    def ar1(n, rng, phi=0.9):
        x = np.empty(n); x[0] = rng.normal()
        e = rng.normal(size=n) * np.sqrt(1 - phi ** 2)
        for i in range(1, n):
            x[i] = phi * x[i - 1] + e[i]
        return x
    rng = np.random.default_rng(5)
    det = Cusum(0.5).fit_reference(ar1(5000, rng))
    tune, fresh = [ar1(20000, rng)], ar1(200000, rng)
    F = det.prepare(fresh, rng)
    ratio = {}
    for name, kw in {"mbb1": dict(method="mbb", mbb_len_blocks=1),
                     "contiguous": dict(method="contiguous")}.items():
        h = calibrate_with(det, tune, TARGET, rng, **kw)["h"]
        ratio[name] = len(fresh) / len(det.alarms(F, h)) / TARGET
    assert ratio["mbb1"] < 0.5
    assert abs(np.log(ratio["contiguous"])) < 0.25
