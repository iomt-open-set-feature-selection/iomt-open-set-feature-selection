# replication/ (Person A)

Repeats RQ1 to RQ3 on IoMT-TrafficData's slow attacks (Slowloris, Slow Read, RUDY, ARP spoofing, scanning).

| Planned file | Does |
|---|---|
| `iomt_trafficdata.py` | Builds per-device streams from IoMT-TrafficData in the same §4.1 schema, using its own feature set |

Rules:

- Within-dataset only. Its features differ from CICIoMT2024's, so no cross-dataset transfer.
- Reuses `selection/`, `detectors/` and `experiments/` unchanged; only the stream builder is new.
