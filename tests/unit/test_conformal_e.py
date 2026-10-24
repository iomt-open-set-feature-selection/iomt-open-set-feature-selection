"""Validity and detection of the conformal e-detector (no data needed).

The properties the gate-5 argument rests on: conformal p-values are uniform
and independent under exchangeability, the theory threshold gamma gives
gamma <= ARL <= gamma / rho, and a mean shift is caught quickly.

Seeds are fixed, so these are deterministic checks, not flaky statistics.
"""
import numpy as np
import pytest
from scipy import stats

from iomt.detectors.conformal_e import ConformalE

GAMMA, RHO, RUNS = 50.0, 0.5, 300


def test_rho_must_be_a_proper_shift():
    with pytest.raises(ValueError):
        ConformalE(rho=0.0)
    with pytest.raises(ValueError):
        ConformalE(rho=1.0)


def test_pvalues_are_uniform_under_iid_scores():
    rng = np.random.default_rng(0)
    det = ConformalE().fit_reference(rng.normal(size=500))
    p = det.pvalues(rng.normal(size=4000), rng)
    assert (p > 0).all() and (p < 1).all()
    assert stats.kstest(p, "uniform").pvalue > 0.01


def test_pvalues_are_independent_under_iid_scores():
    rng = np.random.default_rng(1)
    det = ConformalE().fit_reference(rng.normal(size=500))
    p = det.pvalues(rng.normal(size=4000), rng)
    assert abs(np.corrcoef(p[:-1], p[1:])[0, 1]) < 0.05


def test_a_large_score_gets_a_small_pvalue():
    det = ConformalE().fit_reference(np.arange(100.0))
    rng = np.random.default_rng(2)
    p = det.pvalues([1000.0, -1000.0], rng)
    assert p[0] < 0.02 and p[1] > 0.98


def _run_length(seed, gamma, n_scores):
    rng = np.random.default_rng(seed)
    det = ConformalE(rho=RHO).fit_reference(rng.normal(size=500))
    F = det.prepare(rng.normal(size=n_scores), rng)
    alarms = det.alarms(F, gamma)
    return int(alarms[0]) + 1 if len(alarms) else len(F)


def test_theory_threshold_gives_arl_between_gamma_and_gamma_over_rho():
    """The anytime-valid claim behind gate 5, measured on iid benign scores."""
    n = int(GAMMA / RHO) + 5
    runs = np.array([_run_length(1000 + r, GAMMA, n) for r in range(RUNS)])
    assert GAMMA <= runs.mean() <= GAMMA / RHO
    # rho * t alone reaches gamma, so an alarm is certain by gamma / rho.
    assert runs.max() <= GAMMA / RHO


def test_mean_shift_is_detected_quickly():
    delays = []
    for r in range(50):
        rng = np.random.default_rng(r)
        det = ConformalE().fit_reference(rng.normal(size=500))
        scores = np.r_[rng.normal(size=100), rng.normal(loc=3.0, size=100)]
        after = [i for i in det.alarms(det.prepare(scores, rng), 100.0) if i >= 100]
        delays.append(after[0] - 100 if after else np.nan)
    delays = np.array(delays, float)
    assert np.isfinite(delays).all(), "the shift was missed on some runs"
    assert np.median(delays) <= 5


def test_alarms_restart_the_statistic_after_an_alarm_and_at_segment_starts():
    rng = np.random.default_rng(3)
    det = ConformalE().fit_reference(rng.normal(size=200))
    F = det.prepare(np.r_[rng.normal(size=50), rng.normal(loc=5.0, size=50)], rng)
    assert len(det.alarms(F, 20.0)) > 1, "no renewal: only one alarm fired"
    # A segment start resets the statistic, so it cannot alarm on that block.
    late = det.alarms(F, 20.0, starts=[60])
    assert 60 not in late
