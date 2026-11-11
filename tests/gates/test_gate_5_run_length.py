"""Gate item 5 (owner A, closed by B): the conformal e-detector holds its nominal
run length on blocked benign traffic (changelog A3, A4: per-device verdicts on
the audit split, detector level pass; broker excluded by role)."""
import pytest

from conftest import ROOT, assert_current_protocol, load_artifact

pytestmark = pytest.mark.gate

G5 = ROOT / "results" / "stage1" / "gate5_run_length.json"
BS = ROOT / "results" / "audit" / "block_size.json"
ST = ROOT / "results" / "stage1" / "gate5_calibration_study.json"


def test_run_length_uses_current_block_size():
    g5 = load_artifact(G5)
    bs = load_artifact(BS)
    assert_current_protocol(g5, "gate5_run_length.json")
    assert g5["block_windows"] == bs["block_windows"], "gate 5 ran with a stale block size"


def test_conformal_e_detector_passes_the_a3_rule():
    g5 = load_artifact(G5)
    assert_current_protocol(g5, "gate5_run_length.json")
    d = g5["detectors"]["conformal_e"]
    assert d["verdict"] == "pass", (f"conformal_e is {d['verdict']}: failed {d['failed']}, "
                                    f"inconclusive {d['inconclusive']}, {d['passed']}/{d['audited']} audited devices pass")


def test_calibration_chosen_on_tuning_split_and_used_by_the_audit():
    """Adjust loop (2026-10-24): the method comes from the tuning-split study, not the audit."""
    st = load_artifact(ST)
    g5 = load_artifact(G5)
    assert_current_protocol(st, "gate5_calibration_study.json")
    assert st["audit_split_read"] is False
    assert st["block_windows"] == g5["block_windows"], "study and audit used different block sizes"
    assert st["chosen"] is not None, "no calibration candidate met the study rule"
    assert g5["calibration"] == st["chosen"], "audit ran with a calibration the study did not choose"
