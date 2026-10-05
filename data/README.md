# data/

Nothing here is committed except two files.

| Path | Committed | Holds |
|---|---|---|
| `raw/` | `CHECKSUMS` only | CICIoMT2024 pcaps and CSVs, IoMT-TrafficData, optional CICIoT2023 |
| `interim/` | No | Parsed packet tables |
| `processed/streams/` | No | Per-device window streams (parquet) |
| `processed/streams_manifest.json` | Yes | SHA-256 per stream file, so both machines can confirm identical streams |

Both of you download independently and compare against `raw/CHECKSUMS` on day one.
