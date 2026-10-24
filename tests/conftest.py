import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iomt import protocol as P  # noqa: E402


def pytest_configure(config):
    config.addinivalue_line("markers", "gate: runs on real data artefacts; skipped when they are missing")


@pytest.fixture(scope="session")
def cfg():
    return P.load()


def load_artifact(path: Path):
    if not path.exists():
        pytest.skip(f"artefact missing: {path.relative_to(ROOT)} (run the stage-1 steps first)")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def assert_current_protocol(art: dict, what: str):
    """Artefacts built under another protocol version are stale."""
    assert art.get("protocol_sha256") == P.sha256(), (
        f"{what} was built under a different protocol.yaml; re-run its step")
