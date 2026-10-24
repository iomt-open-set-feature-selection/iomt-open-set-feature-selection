# Gates

Four-week gate, time-boxed to early November 2026. Owner and closer follow the 21 Oct 2026 team split. One planned test file per item. The closer runs it on their own machine and pastes the output into the gate PR.

| Item | Planned test | Owner | Closer | Passes when |
|---|---|---|---|---|
| 1 | `test_gate_1_stream_count.py` | A | B | `streams_manifest.json` lists at least `protocol.gate.min_streams` usable per-device IP streams. Below that, stop and take the fallback. |
| 2 | `test_gate_2_one_stream.py` | A | B | One stream (benign + ARP spoofing) exists end to end; it matches the §4.1 schema; its features were re-extracted from merged packets; one unspliced capture's re-extracted features match its released CSV on matched quantiles (`gate.csv_match_max_quantile_diff`; row-by-row match not reproducible, needs B's ratification) |
| 3 | `test_gate_3_attack_classes.py` | A | B | At least `protocol.gate.min_non_flood_classes` non-flood classes each have at least `protocol.gate.min_attacks_per_class` attacks |
| 4 | `test_gate_4_block_size.py` | A | B | `results/audit/block_size.json` exists; mean absolute ACF at the chosen lag is below `protocol.validity.acf_threshold` on every device |
| 5 | `test_gate_5_run_length.py` | A | B | On blocked benign streams, the e-detector's measured run length ÷ nominal lies within `protocol.validity.run_length_tolerance` (calibration method chosen on the tuning split by `validity/calibration_study.py`), and the theory threshold does not alarm early |
| 6 | `test_gate_6_phases.py` | B | A | Required (RQ5 core since 2026-10-21). Lifecycle phases separate per device above an agreement level fixed in the protocol. |

## Fallback

> Needs re-scoping at the freeze: CICIoT2023 was dropped on 2026-10-20, and the text below still relies on it.

If items 1 to 5 can't all pass by early November: cut-down compression study. CICIoMT2024 plus the CICIoT2023 cross-capture test, the same three selectors, an MLP and LightGBM, hidden-attack detection at a fixed benign false-positive rate, and the add-back ablation. `selection/`, `closedset/` and `info/` carry over unchanged.

Agree before the gate closes which parts of the fallback each person owns.
