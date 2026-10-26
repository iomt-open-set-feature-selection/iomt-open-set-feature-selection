# Protocol changelog

Every change after the freeze gets a line: date, version, what changed, why, who approved, which results it invalidates.

| Date | Version | Change | Why | Approved by | Invalidates |
|---|---|---|---|---|---|
| | 2 | Initial v2 protocol (onset-delay study) | Merged plan replaces v1 | A, B | All v1 results |
| 2026-10-26 | 2 (proposed) | A1, gate 3: count the SYN-flood and MQTT-publish slow ramps from the attack set; report malformed MQTT descriptively | Original FAIL (recon 32, arp_spoofing 7, malformed_mqtt 2). Ramps were in the pre-stated attack set but the test counted recorded captures only | pending A, B | gate 3 result |
| 2026-10-26 | 2 (proposed) | A2, gate 4: becomes descriptive. Keep b = 10 for every device and report each device's lag-1 ACF of block means; no pass/fail on independence | Original FAIL (lag-1 ACF of block means >= 0.1 at b = 10 on 10 devices). 7 of 12 devices never drop below 0.1 at any b from 1 to 60, so no block size gives independence. Independence was needed for the theory threshold, which A3 drops; contiguous empirical calibration keeps the dependence in the data. b = 10 also matches the ~10 s heartbeat of dev_59 and dev_185 | pending A, B | gate 4 result |
| 2026-10-26 | 2 (proposed) | A3, gate 5b: drop the theory threshold; keep per-device calibration (already in place); report each device's audit ratio with its alarm count; any row with calibration_reached = False fails | Original FAIL (theory ARL 75.7 < 144). Per-device audit ratios range 0.19-9.2 even with per-device thresholds, so tuning-split thresholds do not carry over to the audit split; broker hit the conformal_e search cap (1e9) | pending A, B | gate 5 result, pooled 0.864 |
| 2026-10-26 | 2 (proposed) | A4, gate 5a: check every detector, not only conformal_e | Pooled calibrated ratios: conformal_e 0.864, cusum 0.682, threshold 0.531. Only conformal_e is within 0.2, so the detectors are not matched on false-alarm rate | pending A, B | gate 5 result, detector comparison |
| 2026-10-26 | 2 (proposed) | Fallback re-scoped: CICIoT2023 cross-capture test replaced by a within-dataset hidden-family test on IoMT-TrafficData | CICIoT2023 is dropped | pending A, B | none |
