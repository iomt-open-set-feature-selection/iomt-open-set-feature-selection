"""Load protocol/protocol.yaml and read values by dotted path."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PROTOCOL = Path(os.environ.get("IOMT_PROTOCOL", REPO_ROOT / "protocol" / "protocol.yaml"))

_MISSING = object()


def load(path: str | Path | None = None) -> dict:
    with open(path or DEFAULT_PROTOCOL, "r", encoding="utf-8-sig") as f:
        return yaml.safe_load(f)


def get(cfg: dict, dotted: str, default=_MISSING):
    cur = cfg
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            if default is _MISSING:
                raise KeyError(f"protocol has no '{dotted}'")
            return default
        cur = cur[part]
    if cur is None and default is not _MISSING:
        return default
    return cur


def require(cfg: dict, dotted: str):
    v = get(cfg, dotted)
    if v is None:
        raise ValueError(f"protocol '{dotted}' is null; fill it before running this step")
    return v


def sha256(path: str | Path | None = None) -> str:
    """Hash with BOM stripped and CRLF normalised, as scripts/verify_protocol.py does."""
    data = Path(path or DEFAULT_PROTOCOL).read_bytes()
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    data = data.replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()
