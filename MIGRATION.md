# Moving the v1 repo to this layout

v1 was the ANN + GA study (NSGA-II, open-set harness, stub trainer, gates 00–11). This layout replaces it. Do it in one PR so the history shows a single switch.

Repo: `iomt-open-set-feature-selection/iomt-open-set-feature-selection`

## 1. Tag v1 first

Tag the current `main` as `v1-ga-openset` and push the tag. The old code stays reachable through it.

## 2. On a branch `migrate-v2`, remove

- everything under `src/`
- `tests/test_gate_00.py` to `tests/test_gate_11.py`
- the v1 `protocol/protocol.yaml` and `protocol/protocol.sha256`
- any CI step that runs the v1 gates

## 3. Keep

- `.gitattributes`, `.gitignore` (add the new paths in step 5)
- `scripts/verify_protocol.py`, which hashes any protocol file
- `ENVIRONMENT.md` entries that are still true
- `data/raw/CHECKSUMS`
- anything in `results/aggregated/` you might cite

## 4. Add from this scaffold

Every file here: the root docs, `.github/CODEOWNERS`, the PR template, `protocol/`, and the folder READMEs under `src/iomt/`, `tests/`, `results/`, `data/`, `paper/`.

## 5. `.gitignore` additions

Not committed: `data/processed/streams/`, `results/raw/`, `runs/`, `figures/`.
Committed on purpose: `data/processed/streams_manifest.json`, `results/rankings/`, `results/audit/`, `results/aggregated/`.

## 6. Fix the handles

In `.github/CODEOWNERS`, replace `@person-b` with your partner's GitHub handle and check `@rana-rishith`.

## 7. Open the PR

Title: `Migrate to v2: onset-delay study`. Both approve, then merge.

## 8. Repo settings

Branch protection on `main`: require a PR, one approval, review from code owners. Add the CI status check back once code lands.

The repo name still fits: the study is about feature selection, and the held-out family rule is the open-set part.
