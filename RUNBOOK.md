# Runbook

How to rebuild every Stage 1 artefact from the raw CICIoMT2024 pcaps and re-run the gates.

## 1. Setup

- Python 3.11.9, packages from `requirements.txt`.
- Raw data at `<repo parent>/DATASETS/CICIoMT2024`, or set `IOMT_CICIOMT_ROOT` to its path.
- Check the raw files against `data/raw/CHECKSUMS` before building.

## 2. Full rebuild (Windows PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -File .\finish_stage1.ps1
```

A full run deletes `data/processed` and rebuilds everything from `device_map` onward. `pcap_parse` skips captures it has already parsed. Output is appended to `results/stage1/finish_run.log`.

To resume from a step, keeping `data/processed`:

```powershell
powershell -ExecutionPolicy Bypass -File .\finish_stage1.ps1 -From csv_match
```

## 3. Steps

Run from `src/`, in this order. Each is one step of `finish_stage1.ps1`.

| Step | Command |
|---|---|
| unit | `python -m pytest tests/unit -q` (from the repo root) |
| pcap_parse | `python -m iomt.streams.pcap_parse` |
| device_map | `python -m iomt.streams.device_map` |
| build_benign | `python -m iomt.streams.build benign` |
| build_gate2 | `python -m iomt.streams.build gate2` |
| csv_match | `python -m iomt.streams.csv_match` |
| attack_inventory | `python -m iomt.streams.attack_inventory` |
| autocorr | `python -m iomt.audit.autocorr` |
| calibration_study | `python -m iomt.validity.calibration_study` |
| run_length | `python -m iomt.validity.run_length` |
| handoff | `python -m iomt.handoff` |
| gates | `python -m pytest -m gate tests/gates -v` (from the repo root) |

## 4. Closing a gate

The closer rebuilds from raw pcaps (section 2), runs the unit tests and the gate tests, and posts the commands, environment and output in the gate PR. Neither person closes their own gate.
