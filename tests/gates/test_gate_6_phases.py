"""Gate item 6: lifecycle phases separate per device (owner B, closer A)."""
import json
from pathlib import Path

import pandas as pd
import pytest
import yaml

from iomt.analysis.phases import INDEX, OUT, RULE, rule_sha

pytestmark = pytest.mark.gate


def _load():
    assert OUT.exists(), "run: python -m iomt.analysis.phases"
    return (json.loads(OUT.read_text()),
            yaml.safe_load(RULE.read_text(encoding="utf-8"))["gate6"])


def test_result_uses_current_rule_and_permutations():
    out, _ = _load()
    assert out["rule_sha256"] == rule_sha(), "gate6.yaml changed after the run: rerun"
    assert out["permutation_run"], "the final result needs the permutation test (no --no-perm)"


def test_every_device_reported():
    out, _ = _load()
    assert set(pd.read_csv(INDEX)["device_id"]) == set(out["devices"])


def test_lifecycle_phases_separate():
    out, rule = _load()
    passing = [d for d, r in out["devices"].items()
               if r.get("passed") and len(r["phases"]) >= rule["gate_min_phases_for_pass"]]
    assert len(passing) >= rule["gate_min_passing_devices"], (
        f"devices passing with >= {rule['gate_min_phases_for_pass']} phases: {passing}")