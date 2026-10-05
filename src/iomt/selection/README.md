# selection/ (Person B)

Ranks features with three selectors, holding out the family under test.

| Planned file | Does |
|---|---|
| `rank.py` | For each selector × held-out family, ranks all 45 features using the other families only |
| `selectors.py` | Mutual information (multi-class), LightGBM importance, binary mutual information (benign vs attack) |

**Inputs:** released CSVs or re-extracted windows, `protocol.selection`.

**Outputs:** `results/rankings/{selector}__holdout-{family}.json` in the `ARCHITECTURE.md` §4.2 schema. One ranking gives every k.

Rules:

- The held-out family never touches selection. `trained_on_families` lists exactly what was used, and a check in `tests/checks/` enforces it.
- Rankings are full orderings of all features, so A cuts at any k without asking.
- RQ4 (delay-aware selection) lives here too, only if `protocol.extended.rq4_delay_aware_selection` is true.
