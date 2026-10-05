# experiments/ (Person A)

The headline: delay against feature count.

| Planned file | Does |
|---|---|
| `delay.py` | `measure_delay`: the frozen function in `ARCHITECTURE.md` §4.5. Runs one detector on one feature subset over attack streams; returns delay records |
| `sweep.py` | RQ1. For every selector × held-out family × k × detector × seed, cuts the ranking at k and calls `measure_delay`; logs CPU latency per k |
| `harm.py` | Case study. Detection-before-harm margin on fixed-rate captures that have a measured harm point |

**Outputs:** `results/raw/delay/*.parquet` (not committed); `results/aggregated/delay.csv` with delay inflation (delay at k ÷ delay at all features) and probability of detection within the horizon.

Rules:

- Misses stay in the data as misses. Never drop them to make averages look better.
- Floods are reported separately as a floor.
- RQ5 (lifecycle phases) lives here only if `protocol.extended.rq5_lifecycle_phases` is true.
