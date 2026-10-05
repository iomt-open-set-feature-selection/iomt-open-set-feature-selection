# Gates

Four-week gate, time-boxed to early November 2026. One planned test file per item. The closer runs it on their own machine and pastes the output into the gate PR.

| Item | Planned test | Owner | Closer | Passes when |
|---|---|---|---|---|
| 1 | `test_gate_1_stream_count.py` | A | B | `streams_manifest.json` lists at least `protocol.gate.min_streams` usable per-device IP streams. Below that, stop and take the fallback. |
| 2 | `test_gate_2_one_stream.py` | A | B | One stream (benign + ARP spoofing) exists end to end; it matches the §4.1 schema; its features were re-extracted from merged packets; one unspliced capture's re-extracted features match its released CSV rows |
| 3 | `test_gate_3_attack_classes.py` | B | A | At least `protocol.gate.min_non_flood_classes` non-flood classes each have at least `protocol.gate.min_attacks_per_class` attacks |
| 4 | `test_gate_4_block_size.py` | B | A | `results/audit/block_size.json` exists; mean absolute ACF at the chosen lag is below `protocol.validity.acf_threshold` on every device |
| 5 | `test_gate_5_run_length.py` | A | B | On blocked benign streams, the e-detector's measured run length ÷ nominal lies within `protocol.validity.run_length_tolerance` |
| 6 | `test_gate_6_phases.py` | A | B | RQ5 only. Lifecycle phases separate per device above an agreement level fixed in the protocol. Skipped while RQ5 is off. |

## Fallback

If items 1 to 5 can't all pass by early November: cut-down compression study. CICIoMT2024 plus the CICIoT2023 cross-capture test, the same three selectors, an MLP and LightGBM, hidden-attack detection at a fixed benign false-positive rate, and the add-back ablation. `selection/`, `closedset/` and `info/` carry over unchanged.

Agree before the gate closes which parts of the fallback each person owns.
