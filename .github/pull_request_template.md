## What this changes

<!-- One or two lines. -->

## Owner / reviewer

- Author: A / B
- Module(s):

## Checks

- [ ] `scripts/verify_protocol.py` passes
- [ ] Non-gate tests pass (once tests exist)
- [ ] No stub imports outside `tests/` (after the gate)
- [ ] If a contract in `contracts.py` changed: both approved, `ARCHITECTURE.md` section 4 updated
- [ ] If a handoff file changed (`results/rankings/`, `results/audit/`, `streams_manifest.json`): receiver reviewed

## Gate PRs only

Closer fills this in after running the test on their own machine.

- Gate item:
- Command run: `pytest -m gate tests/gates/test_gate_<n>_*.py -v`
- Output (paste):

```
```

- [ ] I am not the owner of this gate
