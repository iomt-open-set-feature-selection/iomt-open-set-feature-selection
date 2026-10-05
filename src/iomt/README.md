# src/iomt

One package. Each subfolder belongs to one person; the three files at this level belong to both.

| Planned file | Owner | Purpose |
|---|---|---|
| `contracts.py` | Both | The four schemas in `ARCHITECTURE.md` §4: window stream, feature ranking, block size, delay record |
| `protocol.py` | Both | Load `protocol/protocol.yaml`, check its hash, refuse to run on a mismatch |
| `stubs.py` | Both | Synthetic streams, rankings and delay records that pass the contracts. First code PR. |

Rules:

- Every module reads settings from the loaded protocol, never from its own constants.
- Every output file records the protocol hash and git SHA it was made under.
- After the gate, nothing outside `tests/` imports `stubs.py`.
