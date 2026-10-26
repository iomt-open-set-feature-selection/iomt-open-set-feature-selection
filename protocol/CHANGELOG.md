# Protocol changelog

Every change after the freeze gets a line: date, version, what changed, why, who approved, which results it invalidates.

| Date | Version | Change | Why | Approved by | Invalidates |
|---|---|---|---|---|---|
| | 2 | Initial v2 protocol (onset-delay study) | Merged plan replaces v1 | A, B | All v1 results |
| 2026-10-26 | 2 (proposed) | Fallback re-scoped: CICIoT2023 cross-capture test replaced by a within-dataset hidden-family test on IoMT-TrafficData | CICIoT2023 is dropped | pending A, B | none |
| 2026-10-26 | 2 (proposed) | A1, gate 3: a ramp family counts toward the 3 families only if built from >= 5 distinct CICIoMT2024 flood capture files. Onset = timestamp of the first injected attacker packet. Malformed MQTT reported descriptively | Original FAIL, first result 25 Oct (recon 32, arp_spoofing 7, malformed_mqtt 2). ramp_syn_flood and ramp_mqtt_publish_flood are named in protocol.yaml since 8772258 (5 Oct), but base capture and ramp durations were left null, so construction is decided after the failure. Capture files: syn_flood 10, mqtt_publish_flood 4 (A1_attack_classes.csv), so the publish ramp would not count. Counts are provisional until the floods are parsed. Post-hoc | pending A, B | gate 3 result |
| 2026-10-26 | 2 (proposed) | A2, gate 4: descriptive only. Keep b = 10 as a working value with no independence claim. Report raw-feature ACF and block-score ACF per device. The paper does not claim the e-detector's guarantee holds; it claims a nominal level with an audited run length | Original FAIL, first result 25 Oct (lag-1 ACF of block means >= 0.1 at b = 10 on 10 devices). The 10 s heartbeat on dev_59 and dev_185 makes b = 10 look independent (ACF 0.01 at b = 10 and 20, 0.89 at b = 15), so it is not a reason for b = 10. Block-score lag-1 ACF is 0.13-0.89. Post-hoc | pending A, B | gate 4 result |
| 2026-10-26 | 2 (proposed) | A3, gate 5b: drop the theory threshold. Per device, with n audit alarms: pass if the log ratio is within [log 0.8 - 1.96/sqrt(n), log 1.2 + 1.96/sqrt(n)] and n >= 30; fail if outside; inconclusive if inside with n < 30. Any calibration_reached = False fails. Broker excluded from gate 5 with the reason stated; pooled conformal_e ratio reported without broker (0.861) | Original FAIL, first result 25 Oct (theory ARL 75.7 < 144). Calibrated conformal_e per-device ratios 0.62-3.06 (the earlier 0.19-9.2 range mixed in cusum and threshold rows). Broker's e-detector grows on benign traffic and calls hit the 1e9 search cap; raising the cap does not help. Broker is the target of malformed MQTT and the publish ramp, so those lose a per-device baseline unless the ActiveBroker fix gives broker benign data. Tolerance chosen after seeing the 24 Oct ratios. Post-hoc | pending A, B | gate 5 result, pooled 0.864 |
| 2026-10-26 | 2 (proposed) | A4, gate 5a: recalibrate cusum and threshold on the calibration split (never the audit split) and test all three detectors against the tolerance. A detector that cannot be matched is reported as unmatched and left out of delay comparisons | Original: PASS on conformal_e only (first result 25 Oct). Pooled calibrated ratios conformal_e 0.864, cusum 0.682, threshold 0.531; delays at unequal false-alarm rates are not comparable. Post-hoc | pending A, B | gate 5 result, detector comparison |
| 2026-10-26 | 2 (proposed) | A5, gate 5: per-device minimum of 30 audit alarms, tied to the A3 tolerance (below 30 = inconclusive) | validity.min_alarms_for_audit: 30 is PROPOSED (A) and covers pooled alarms only. Applying it to Singcall (6 alarms) per device was new. Post-hoc | pending A, B | gate 5 per-device rows |

All five amendments are post-hoc. Gates 3, 4 and 5b first failed on 25 Oct 2026, and the paper states that.

## Closer review findings (B, PR #2, 25 Oct 2026)

1. requirements.txt had no version pins, so parquet hashes are not reproducible across machines.
2. dev_192_168_137_243 mirrors the camera's traffic in every camera interaction capture (e.g. Ecobee LAN_MIC 38,731 vs 37,404 packets); likely the controlling phone, not an IoMT device (P9).
3. Gate 4: dev_59 and dev_185 show |ACF| near 0 at multiples of 10 and high at odd multiples of 5, a ~10 s heartbeat; b = 10 matches the period rather than showing independence (P4).
4. Gate 5: pooled calibrated ratio 0.864 passes, but per device it ranges 0.62-3.06, so false-alarm rates are not matched per device (P2, mixed-effects model).
5. Singcall: 0 alarms under every calibration candidate.
6. IAT and Rate are excluded from the gate 2 check (gaps 3% and 10%); matters for feature selection if they rank high.
7. profiling/Broker/ActiveBroker (~2M packets) is parsed but produces no benign streams.
