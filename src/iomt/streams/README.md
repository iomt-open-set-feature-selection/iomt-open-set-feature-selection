# streams/ (Person A)

Turns CICIoMT2024 packet captures into per-device window streams.

| Planned file | Does |
|---|---|
| `pcap_index.py` | Lists every capture with device, family, start and end time, packet count |
| `device_map.py` | Maps IP and MAC addresses to devices; flags the simulated MQTT fleet as one stream if it shares an address |
| `splice.py` | Joins benign and attack captures only at natural capture boundaries; takes ramps from `ramps/` |
| `extract.py` | Re-extracts the 45 features from merged packets, window by window |
| `build.py` | Runs the above, writes `data/processed/streams/*.parquet` and `streams_manifest.json` |

**Inputs:** `data/raw/` pcaps, `protocol.attack_set`, `protocol.streams.window_seconds`, `protocol.features`.

**Outputs:** window streams in the `ARCHITECTURE.md` §4.1 schema; manifest with one SHA-256 per file.

**Done when:** gate items 1 and 2 pass, closed by B.

Notes:

- Re-extracted features must match the released CSV feature definitions. Check by extracting one unspliced capture and comparing against its released CSV rows.
- Record which capture each window came from, so `audit/` can trace leakage and splice artefacts.
