# Stage 1 gate report, Person A (2026-11-11)

Protocol SHA-256 (draft, not frozen): `f5db6416f5c573b457faa6abea42643c27747122c2984d6ee108f2a2f9efc324`

B closes items 1-5 by re-running `pytest -m gate tests/gates -v` on their machine after rebuilding the artefacts (see RUNBOOK.md).

| Item | Result | Key numbers |
|---|---|---|
| 1 | PASS | 11 usable streams (need 10): broker, Ecobee_Camera, dev_192_168_137_185, dev_192_168_137_210, Blink_Camera, Multifunctional_Pager, Singcall, SenseU, M1T_Camera, dev_192_168_137_59, Owltron_Camera |
| 2 | PASS | stream onset__M1T_Camera__attacks~train~Benign_train__attacks~train~ARP_Spoofing_train; deterministic features agree to 0.0018 on matched quantiles (limit 0.01); row-by-row alignment 0.108, not reproducible from the pcap |
| 3 | FAIL | recon: 31; malformed_mqtt: 2; arp_spoofing: 7 |
| 4 | FAIL | block = 10 windows (10.0 s); above threshold: ['Blink_Camera', 'Ecobee_Camera', 'M1T_Camera', 'Multifunctional_Pager', 'Owltron_Camera', 'SenseU', 'Singcall', 'broker', 'dev_192_168_137_210'] |
| 5 | PASS | calibration contiguous (chosen on the tuning split); conformal_e pass (8/10 audited devices pass; failed none; inconclusive ['Singcall', 'dev_192_168_137_210']); pooled calibrated ratio 0.90 with broker, 0.90 without; theory-threshold ARL 82 vs nominal 180 blocks (reported only) |

## Autocorrelation per device

| Device | raw features, mean abs lag-1 ACF (b = 1) | block means, b = 10 | block scores, audit split |
|---|---|---|---|
| Blink_Camera | 0.13 | 0.42 | 0.49 |
| Ecobee_Camera | 0.10 | 0.19 | 0.46 |
| M1T_Camera | 0.30 | 0.26 | 0.38 |
| Multifunctional_Pager | 0.16 | 0.24 | 0.36 |
| Owltron_Camera | 0.12 | 0.18 | 0.52 |
| SenseU | 0.26 | 0.33 | 0.51 |
| Singcall | 0.53 | 0.55 | 0.69 |
| broker | 0.35 | 0.57 | 0.77 |
| dev_192_168_137_185 | 0.09 | 0.09 | 0.09 |
| dev_192_168_137_210 | 0.43 | 0.47 | 0.47 |
| dev_192_168_137_59 | 0.10 | 0.01 | 0.42 |

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
