# Stage 1 gate report, Person A (2026-10-24)

Protocol SHA-256 (draft, not frozen): `89f215861caf1b133a74e252c2dcc5fec0cbbe985e6747097f922b0bb08770dc`

B closes items 1-5 by re-running `pytest -m gate tests/gates -v` on their machine after rebuilding the artefacts (see RUNBOOK.md).

| Item | Result | Key numbers |
|---|---|---|
| 1 | PASS | 12 usable streams (need 10): broker, Ecobee_Camera, dev_192_168_137_185, dev_192_168_137_210, Blink_Camera, Multifunctional_Pager, Singcall, SenseU, dev_192_168_137_243, M1T_Camera, dev_192_168_137_59, Owltron_Camera |
| 2 | PASS | stream onset__M1T_Camera__attacks~train~Benign_train__attacks~train~ARP_Spoofing_train; deterministic features agree to 0.0018 on matched quantiles (limit 0.01); row-by-row alignment 0.108, not reproducible from the pcap |
| 3 | FAIL | recon: 32; malformed_mqtt: 2; arp_spoofing: 7 |
| 4 | FAIL | block = 10 windows (10.0 s); above threshold: ['Blink_Camera', 'Ecobee_Camera', 'M1T_Camera', 'Multifunctional_Pager', 'Owltron_Camera', 'SenseU', 'Singcall', 'broker', 'dev_192_168_137_210', 'dev_192_168_137_243'] |
| 5 | FAIL | calibration contiguous (chosen on the tuning split); calibrated ratio 0.86 over 409 alarms; theory-threshold ARL 76 vs nominal 180 blocks |

Item 6 (phase separation) is B's; A reviews and closes it once B submits it.

## Handoffs to B

- A1: `results/handoff/A1_devices.csv`, `A1_attack_classes.csv`, `A1_features.json`
- A10: `results/handoff/A10_benign_windows_index.csv` + the `benign__*.parquet` files it lists

## For the protocol freeze

- Every value marked `PROPOSED (A)` in protocol/protocol.yaml.
- Feature set: ciciomt39 (proposed) vs cic45; the k grid tops out at the set size.
- Attacks whose first attacker packet arrives long after the capture starts (see `first_attacker_packet_after_capture_start_s` in results/stage1/attacks.csv): onset at the capture boundary would add that time to every delay.
- Gate 5 calibration study: results/stage1/gate5_calibration_study.json (method choice and the fixed-threshold marginal-shift diagnostic).
- CODEOWNERS: updated to the 21 Oct split on branch a/stage1-gates (B reviews).
