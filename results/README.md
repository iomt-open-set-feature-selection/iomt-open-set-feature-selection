# results/

| Folder | Committed | Written by | Read by |
|---|---|---|---|
| `rankings/` | Yes | B (`selection/`) | A (`experiments/`) |
| `audit/` | Yes | B (`audit/`) | A (`detectors/`), reviewers |
| `raw/` | No | A (`experiments/`), B (`info/`) | `analysis/` |
| `aggregated/` | Yes | Both | `analysis/figures.py`, the paper |

Every file records the protocol hash and git SHA it was produced under. A file from an old hash is re-run or labelled.
