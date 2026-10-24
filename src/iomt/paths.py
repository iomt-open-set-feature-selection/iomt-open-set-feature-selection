"""Repository paths. Override the data root with IOMT_CICIOMT_ROOT."""
from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
INTERIM = Path(os.environ.get("IOMT_INTERIM", REPO_ROOT / "data" / "interim"))
PROCESSED = REPO_ROOT / "data" / "processed"
STREAMS = PROCESSED / "streams"
MANIFEST = PROCESSED / "streams_manifest.json"
RESULTS = REPO_ROOT / "results"
STAGE1 = RESULTS / "stage1"          # A's gate artefacts
AUDIT = RESULTS / "audit"            # block_size.json lives here (ARCHITECTURE 4.3)
HANDOFF = RESULTS / "handoff"        # A1, A10 for Person B
AGG = RESULTS / "aggregated"


def ensure(*dirs: Path):
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
