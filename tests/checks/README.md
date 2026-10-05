# Checks

Run in CI on committed files once code exists. Unlike gates, they never close; they guard every later PR.

| Planned test | Guards | Fails when |
|---|---|---|
| `test_holdout_isolation.py` | The held-out rule in `selection/` | Any ranking file lists its `held_out_family` inside `trained_on_families` |
| `test_splice_chance.py` | Splice artefacts | `results/audit/splice_classifier.json` reports an AUC interval that excludes chance, or power below `protocol.streams.splice_classifier.min_power`, for a stream group that was not dropped |
| `test_protocol.py` | The freeze | `protocol.yaml` no longer matches `protocol.sha256` |
| `test_contracts.py` | The four schemas | Stub or real outputs don't match `ARCHITECTURE.md` §4 |
