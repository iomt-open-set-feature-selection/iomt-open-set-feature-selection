# Working agreement

## The one rule

**You do not close your own gate.** The other person runs the gate test and signs the PR. Reading the code and agreeing it looks right does not count.

`main` is protected. Every change goes through a PR with at least one approval.

## Split

| Person A (Rana) | Person B |
|---|---|
| `streams/`: pcaps to per-device streams | `ramps/`, `audit/`: ramps, leakage, splice classifier, block size |
| `detectors/`, `validity/`: e-detector, CUSUM, threshold, run-length audit | `selection/`, `closedset/`: three selectors, closed-set baselines |
| `experiments/`: RQ1 delay curves, harm case study | `info/`: RQ2 KL estimation and add-back |
| `analysis/stats.py`, `replication/` | `analysis/rq3.py` |
| RQ5 if it runs | RQ4 if it runs |

Writing: A drafts the introduction, stream and detector methods, RQ1 results, limitations. B drafts related work, selection and KL methods, RQ2 and RQ3 results, discussion.

Both own `contracts.py`, `protocol.py`, `stubs.py`, `protocol/`. Changes there need both approvals.

## Branches

`a/<topic>` or `b/<topic>`, for example `a/splice-boundaries` or `b/kl-bootstrap`. Gate work uses `gate-<n>`.

## Handoffs

Handoff files (`results/rankings/`, `results/audit/`, `data/processed/streams_manifest.json`) go through PRs like code. The receiving person reviews them.

Before the gate passes, develop against `src/iomt/stubs.py`. After it passes, stubs outside `tests/` block review.

## Protocol

`protocol/protocol.yaml` is frozen together, in one sitting, before any detector touches attack traffic. After the freeze:

1. Any change bumps `version` and records why in `protocol/CHANGELOG.md`.
2. Re-hash with `scripts/verify_protocol.py` and commit the new `protocol.sha256`.
3. Both approve.

Results produced under an old hash are re-run or reported as such.

## Environment

Both work in Linux or WSL2. Mixed shells put CRLF into the protocol file and break the hash. `.gitattributes` and `verify_protocol.py` both normalise line endings, but don't rely on them alone.

## Weekly check, 15 minutes

1. Which gate is open?
2. Has anything landed that the other person's code assumes is different?
