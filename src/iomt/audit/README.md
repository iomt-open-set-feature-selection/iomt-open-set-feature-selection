# audit/ (Person B)

Checks the data before anyone trusts a delay number. These outputs form contribution 3, the audited benchmark.

| Planned file | Does | Output |
|---|---|---|
| `leakage.py` | Audits the released CSVs: duplicate rows across splits, identifier-like columns, constant columns, label-correlated artefacts | `results/audit/leakage.json` + a one-page summary |
| `splice_classifier.py` | Trains a classifier to find splice points from features near them; reports AUC with CI and power | `results/audit/splice_classifier.json` |
| `autocorr.py` | Measures within-stream autocorrelation on benign windows per device; picks the block size | `results/audit/block_size.json` |

**Done when:** gate items 3 and 4 pass, closed by A. The splice check in `tests/checks/` passes.

Rules:

- If the splice classifier beats chance on a stream group, drop those streams and list them in the JSON. Don't tune features to make it pass.
- `block_size.json` is the only place block size comes from. A's detectors read it; nobody hard-codes a number.
