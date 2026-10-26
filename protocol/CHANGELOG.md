# Protocol changelog

Every change after the freeze gets a line: date, version, what changed, why, who approved, which results it invalidates.

| Date | Version | Change | Why | Approved by | Invalidates |
|---|---|---|---|---|---|
| | 2 | Initial v2 protocol (onset-delay study) | Merged plan replaces v1 | A, B | All v1 results |
| 2026-10-26 | 2 (proposed) | A1, gate 3: count the SYN-flood and MQTT-publish slow ramps from the attack set; report malformed MQTT descriptively | Original FAIL (recon 32, arp_spoofing 7, malformed_mqtt 2). Ramps were in the pre-stated attack set but the test counted recorded captures only | pending A, B | gate 3 result |
| 2026-10-26 | 2 (proposed) | A2, gate 4: test independence on block-level scores, not window lags; a device that still fails gets its own b from its ACF, capped at b = TBD | Original FAIL (mean abs ACF >= 0.1 at b = 10 on 10 devices). dev_59 and dev_185 show a ~10 s heartbeat, so window-lag ACF at b = 10 reflects the period | pending A, B | gate 4 result |
| 2026-10-26 | 2 (proposed) | A3, gate 5b: drop the theory threshold; calibrate empirically per device on held-out benign traffic; any row with calibration_reached = False fails | Original FAIL (theory ARL 75.7 < 144). Per-device ratios 0.62-3.06; broker hit the threshold search cap (1e9), so pooled 0.864 included an uncalibrated device | pending A, B | gate 5 result, pooled 0.864 |
