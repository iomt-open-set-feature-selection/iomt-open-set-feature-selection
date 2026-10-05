# ramps/ (Person B)

Builds slow ramps of SYN flood and MQTT publish flood from attacker-side packets only.

| Planned file | Does |
|---|---|
| `ramp.py` | Takes a fixed-rate flood capture, keeps attacker-sent packets, thins and re-times them so the send rate rises from zero to full over `ramp_seconds` |

**Inputs:** flood captures named in `protocol.attack_set.ramps`.

**Outputs:** ramped packet sequences that `streams/splice.py` places into benign traffic.

Rules:

- Drop device and broker responses. Recorded responses don't match a ramped rate (limitation 2), so ramped streams carry no harm claim.
- Every ramp duration in the protocol gets its own stream set.
