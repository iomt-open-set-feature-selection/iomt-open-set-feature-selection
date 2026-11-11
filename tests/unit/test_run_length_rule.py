"""Gate 5 verdict rule (changelog A3, A4) on plain numbers: no data needed."""
import numpy as np

from iomt.validity.run_length import detector_verdict, device_verdict

TOL, M = 0.2, 30


def verdict(reached=True, expected=32.0, n=32, tol=TOL, m=M):
    return device_verdict(reached, expected, expected / n if n else float("inf"), tol, m)


def test_calibration_not_reached_fails_before_anything_else():
    assert verdict(reached=False, expected=5.0, n=5) == "fail"    # would be inconclusive on E


def test_expected_alarms_below_the_minimum_is_inconclusive_whatever_n_and_r_are():
    assert verdict(expected=18.4, n=18) == "inconclusive"
    assert verdict(expected=18.4, n=0) == "inconclusive"
    assert verdict(expected=18.4, n=90) == "inconclusive"


def test_no_alarms_with_enough_expected_alarms_fails():
    assert verdict(expected=32.0, n=0) == "fail"


def test_band_is_set_by_expected_alarms_and_widens_as_it_falls():
    half = 1.96 / np.sqrt(30)
    lo, hi = np.exp(np.log(0.8) - half), np.exp(np.log(1.2) + half)
    assert round(lo, 2) == 0.56 and round(hi, 2) == 1.72          # the A3 Why figures at E = 30
    ok = lambda r: device_verdict(True, 30.0, r, TOL, M)
    assert ok(lo * 1.001) == "pass" and ok(lo * 0.999) == "fail"
    assert ok(hi * 0.999) == "pass" and ok(hi * 1.001) == "fail"
    # at E = 120 the same ratio 1.5 is outside the narrower band
    assert device_verdict(True, 120.0, 1.5, TOL, M) == "fail" and device_verdict(True, 30.0, 1.5, TOL, M) == "pass"


def test_detector_level():
    assert detector_verdict(["pass", "pass", "fail"]) == "fail"
    assert detector_verdict(["pass", "pass", "inconclusive", "inconclusive"]) == "pass"      # exactly half
    assert detector_verdict(["pass", "inconclusive", "inconclusive"]) == "inconclusive"
    assert detector_verdict(["inconclusive", "inconclusive"]) == "inconclusive"
    assert detector_verdict([]) == "inconclusive"


def test_run_marks_broker_excluded_and_counts_a_short_device_as_inconclusive(monkeypatch):
    import pandas as pd
    from iomt import protocol as P
    from iomt.validity import run_length

    def fake_audit(dev, bs, features, b, cfg, rng, calib, seed):
        r = {"device_id": dev, "detector": "conformal_e", "threshold_mode": "calibrated", "alarms": 32,
             "audit_blocks": 5760, "nominal_arl_blocks": 180.0, "ratio": 1.0, "calibration_reached": True,
             "status": "ok"}
        return [r, dict(r, threshold_mode="theory", calibration_reached=None)]

    inv = {"hosts": [{"mac": "dc:a6:32:dc:27:d5", "role": "attacker", "main_ip": None},     # no device_id (H1)
                     {"device_id": "a", "role": "device"}, {"device_id": "broker", "role": "broker"},
                     {"device_id": "short", "role": "device"}]}
    monkeypatch.setattr(run_length, "load_inventory", lambda: inv)
    monkeypatch.setattr(run_length, "block_size", lambda: 10)
    monkeypatch.setattr(run_length, "chosen_calibration", lambda cfg: {"method": "contiguous"})
    monkeypatch.setattr(run_length, "benign_segments", lambda: {"a": [], "broker": [], "short": []})
    monkeypatch.setattr(run_length, "device_block_scores",
                        lambda dev, *args, **kw: None if dev == "short" else {})
    monkeypatch.setattr(run_length, "device_audit", fake_audit)
    res, df = run_length.run(P.load())
    d = res["detectors"]["conformal_e"]
    assert d["devices"] == {"a": "pass", "short": "inconclusive"} and d["audited"] == 2   # short stays in the base
    assert d["verdict"] == "pass" and res["passes"]
    cal = df[(df.threshold_mode == "calibrated") & (df.status == "ok")].set_index("device_id")
    assert cal.loc["broker", "verdict"] == "excluded" and bool(cal.loc["broker", "audit_excluded"])
    short = df[df.status != "ok"].iloc[0]
    assert short.verdict == "inconclusive" and short.expected_alarms == 0.0
