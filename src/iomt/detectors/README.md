# detectors/ (Person A)

Three detectors on one benign-only score, all calibrated to the same false-alarm rate.

| Planned file | Does |
|---|---|
| `score.py` | Trains the score model (`protocol.score.model`) on benign windows only, on a given feature subset |
| `conformal_e.py` | Online conformal e-detector, following Bhattacharyya & Ramdas (2026) |
| `cusum.py` | CUSUM on the same score |
| `threshold.py` | Fixed per-window threshold on the same score |
| `calibrate.py` | Sets each detector's threshold so its average run length on held-out benign traffic meets `protocol.detectors.nominal_arl_windows` |

**Inputs:** window streams, a feature subset, `results/audit/block_size.json`.

Rules:

- The score never sees attack traffic, including the family under test.
- Detectors run on blocks of windows sized from `block_size.json`.
- All three share one interface (fit on benign, calibrate, update per block, report alarm), so `experiments/` treats them the same.
- Gate item 5 closes this folder: the e-detector holds its nominal run length on blocked benign traffic.
