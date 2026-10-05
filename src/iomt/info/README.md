# info/ (Person B)

RQ2: is the delay caused by information loss or by unused signal?

| Planned file | Does |
|---|---|
| `kl.py` | Estimates KL(P_attack ‖ P_benign) per family on each top-k subset, with bootstrap intervals over attacks |
| `addback.py` | Adds back the dropped features with the highest KL contribution; calls A's `measure_delay` to check whether delay recovers |

**Outputs:** `results/aggregated/kl.csv`, `results/aggregated/addback.csv`.

Rules:

- KL in many dimensions is noisy. Report intervals and state the estimator.
- Until A's `measure_delay` lands, `addback.py` runs against the stub with the same inputs and outputs.
- No causal claim beyond what the add-back ablation shows.
