# closedset/ (Person B)

Closed-set accuracy at each k: the number the field reports, and the contrast for RQ1.

| Planned file | Does |
|---|---|
| `baselines.py` | Trains LightGBM and an MLP on the top-k features of each ranking; reports window-level accuracy and macro-F1 on a shuffled split |

**Outputs:** `results/aggregated/closedset.csv` with selector, held-out family, k, model, seed, accuracy, macro-F1.

Rules:

- Use the same rankings and k grid as the delay sweep, so RQ1 compares like with like.
- Can start in week 1 on the released CSVs.
