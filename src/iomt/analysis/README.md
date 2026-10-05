# analysis/

| Planned file | Owner | Does |
|---|---|---|
| `stats.py` | A | Mixed-effects model (attack as random effect; k, selector, detector fixed); Wilcoxon signed-rank over attacks with Holm correction; effect sizes with CIs; equivalence test at `protocol.statistics.equivalence_margin` |
| `rq3.py` | B | Compares selectors at matched k on delay inflation |
| `figures.py` | Both | Builds every paper figure from `results/aggregated/` only |

Rules:

- Unit of analysis is the individual attack, nested in its family. Seeds are averaged within an attack.
- Figures read only committed aggregated tables, so anyone can rebuild them.
