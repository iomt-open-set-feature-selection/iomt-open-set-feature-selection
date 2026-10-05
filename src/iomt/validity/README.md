# validity/ (Person A)

Checks that the false-alarm rate we claim is the one we get.

| Planned file | Does |
|---|---|
| `run_length.py` | Runs each calibrated detector on benign-only streams; reports measured vs nominal average run length per configuration (detector × selector × k) |

**Outputs:** `results/aggregated/run_length.csv`.

Rules:

- Report every configuration, including those outside tolerance.
- We claim a nominal level with an audited run length, not a guarantee.
