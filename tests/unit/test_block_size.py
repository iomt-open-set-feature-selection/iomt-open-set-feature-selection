"""audit/autocorr: the block size is pinned by validity.block_windows, not selected."""
import numpy as np
import pandas as pd

from iomt import protocol as P
from iomt.audit import autocorr
from iomt.contracts import features_for


def test_block_size_is_the_protocol_value_even_if_a_device_selects_another(monkeypatch):
    cfg = P.load()
    feats = features_for(cfg)
    rng = np.random.default_rng(0)
    noise = pd.DataFrame(rng.normal(size=(3000, len(feats))), columns=feats)        # independent: b = 1 is enough
    monkeypatch.setattr(autocorr, "benign_segments", lambda: {"dev_a": [noise]})
    rep = autocorr.run(cfg)
    assert rep["per_device"]["dev_a"]["chosen_block_windows"] == 1
    assert rep["block_windows"] == int(cfg["validity"]["block_windows"]) == 10
    assert rep["block_seconds"] == 10.0 and "1" in rep["per_device"]["dev_a"]["mean_abs_acf_lag1"]
    cfg["validity"]["block_windows"] = 20
    assert autocorr.run(cfg)["block_windows"] == 20
