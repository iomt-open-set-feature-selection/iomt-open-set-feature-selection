"""Gate item 5 (owner A, closed by B): the conformal e-detector holds its nominal
run length on blocked benign traffic (calibrated threshold within tolerance on
the audit split, and the theory threshold does not alarm early)."""
import pytest

from conftest import ROOT, assert_current_protocol, load_artifact
from iomt import protocol as P

pytestmark = pytest.mark.gate

G5 = ROOT / "results" / "stage1" / "gate5_run_length.json"
BS = ROOT / "results" / "audit" / "block_size.json"
ST = ROOT / "results" / "stage1" / "gate5_calibration_study.json"


def test_run_length_uses_current_block_size():
    g5 = load_artifact(G5)
    bs = load_artifact(BS)
    assert_current_protocol(g5, "gate5_run_length.json")
    assert g5["block_windows"] == bs["block_windows"], "gate 5 ran with a stale block size"


def test_calibrated_e_detector_within_tolerance(cfg):
    g5 = load_artifact(G5)
    tol = float(P.require(cfg, "validity.run_length_tolerance"))
    min_al = int(P.require(cfg, "validity.min_alarms_for_audit"))
    c = g5["pooled"]["conformal_e/calibrated"]
    assert c["alarms"] >= min_al, (f"inconclusive: {c['alarms']} alarms < {min_al}; lower "
                                   "detectors.nominal_arl_windows at the freeze or add benign data")
    assert abs(c["ratio"] - 1) <= tol, f"measured/nominal = {c['ratio']:.3f}, tolerance {tol}"


def test_theory_threshold_does_not_alarm_early(cfg):
    g5 = load_artifact(G5)
    tol = float(P.require(cfg, "validity.run_length_tolerance"))
    t = g5["pooled"]["conformal_e/theory"]
    assert t["measured_arl_blocks"] >= (1 - tol) * t["nominal_arl_blocks"], (
        f"theory threshold: ARL {t['measured_arl_blocks']:.1f} < (1 - {tol}) x {t['nominal_arl_blocks']:.1f}")


def test_calibration_chosen_on_tuning_split_and_used_by_the_audit():
    """Adjust loop (2026-10-24): the method comes from the tuning-split study, not the audit."""
    st = load_artifact(ST)
    g5 = load_artifact(G5)
    assert_current_protocol(st, "gate5_calibration_study.json")
    assert st["audit_split_read"] is False
    assert st["block_windows"] == g5["block_windows"], "study and audit used different block sizes"
    assert st["chosen"] is not None, "no calibration candidate met the study rule"
    assert g5["calibration"] == st["chosen"], "audit ran with a calibration the study did not choose"
