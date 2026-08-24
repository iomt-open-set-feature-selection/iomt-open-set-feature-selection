# The Generalisation Cost of Feature Compression in IoMT Intrusion Detection

Open-set evaluation of multi-objective feature selection on CICIoMT2024.

## What this study asks

Feature selection papers report that compression improves generalisation. They measure that claim closed-set: unseen samples, same attack taxonomy. A clinical IDS has to generalise to unseen *attacks*.

Selection maximises `J(f) = I(f; Y_known)`. Deployment needs `D(f) = |P(f|Y_unknown) - P(f|Y_benign)|`. Nothing forces the two to agree, and features with high J and low D go first under compression.

We treat feature count as the independent variable and open-set detection as the dependent one, then plot the curve.

**RQ1** Does open-set detection degrade faster than closed-set accuracy under compression?
Primary metric: `Δ(k) = Acc_closed(k) − Recall_open(k)`.

**RQ2** Is degradation uniform across attack classes, or concentrated in low-signal ones (Recon, Spoofing)?

**RQ3** Do wrapper methods (GA) degrade open-set performance faster than filters (Fisher, MI, IG) at matched k?

**RQ4** Does a safe operating point exist, or is the tradeoff strict?

Either outcome answers the question. Refutation is a result, not a failure.

## What this is not

- Not a new feature selector. NSGA-II is the instrument.
- Not a new zero-day detection method. MSP scoring is deliberately the weakest reasonable baseline, so any degradation we measure is a lower bound.
- Not cross-dataset. Differing flow extractors make feature correspondence a separate problem.
- Not an argument against feature selection.

## Design

| Axis | Method |
|---|---|
| Compression | NSGA-II over `(−macro-F1, ‖s‖₁)`, Pareto front from ~45 features down to ~8 |
| Open-set | Leave-one-class-out: one attack category held out of selection, training, and threshold calibration |
| Baselines | Fisher score, mutual information, information gain, all at matched k |
| Classifier | Fixed MLP, 128-64, identical across every run except input width |
| Scoring | Maximum softmax probability, threshold calibrated to 5% FPR on known-class validation |

Macro-F1 rather than accuracy throughout. On imbalanced attack traffic a detector can post 99% accuracy while missing reconnaissance entirely.

## Layout

```
protocol/     protocol.yaml, frozen and hashed before any run
data/         raw -> interim -> processed (gitignored except checksums and split indices)
src/          data, models, openset, selection, experiments, analysis
runs/         one directory per (fold, selector, seed)
results/      raw JSON per run, aggregated CSV for writing
tests/        gate checks, one module per stage gate
scripts/      protocol verification and other portable helpers
```

Every run writes a `config.json` with the resolved config, the git commit, the protocol hash, and the machine and GPU that produced it. A result file with no config beside it does not exist.

## Getting started

```sh
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python scripts/verify_protocol.py --write   # first time only, records the hash
```

After that, `python scripts/verify_protocol.py` runs at the top of every experiment script and fails loudly if the protocol changed.

## Stages and gates

Twelve stages, each ending in a gate you check before starting the next. See `docs/implementation_guide.md` for the full text and `CONTRIBUTING.md` for how the two of us run them.

| Stage | Output | Gate lives in |
|---|---|---|
| 0 | Environment, data inventory, protocol freeze | `tests/test_gate_00.py` |
| 1 | Canonical splits, leakage control, scaling | `tests/test_gate_01.py` |
| 2 | Fixed ANN, full-feature closed-set reference | `tests/test_gate_02.py` |
| 3 | Open-set harness, folds, scoring, calibration | `tests/test_gate_03.py` |
| 4 | NSGA-II search, surrogate fidelity check | `tests/test_gate_04.py` |
| 5 | Pareto fronts, consolidated onto the k grid | `tests/test_gate_05.py` |
| 6 | RQ1: the Δ(k) curve | `tests/test_gate_06.py` |
| 7 | RQ2: per-class heatmaps, J-vs-D scatter | `tests/test_gate_07.py` |
| 8 | RQ3: wrapper vs filter at matched k | `tests/test_gate_08.py` |
| 9 | RQ4: safe operating point or exchange rate | `tests/test_gate_09.py` |
| 10 | Paired statistics, Holm-Bonferroni, effect sizes | `tests/test_gate_10.py` |
| 11 | Robustness: scoring, threshold, architecture, multi-class holdout | `tests/test_gate_11.py` |

Stages 0 to 6 are the critical path and produce the contribution. Stage 7 makes it explanatory, 8 actionable, 9 deployable, 11 defensible.

## Three rules that keep the study honest

1. **The test partition never reaches the GA.** The assertion lives inside the fitness function, not in anyone's memory.
2. **The threshold is calibrated on known-class validation data only.** The held-out class contributes nothing. An assertion checks that the calibration tensor and the open probe share no rows.
3. **One canonical split, committed as indices.** Not regenerated per seed, per configuration, or per machine. The 10 seeds vary model initialisation and GA stochasticity, never the data partition.

Every way this study fails silently runs through one of those three.

## Hardware

RTX 3080 Ti (64 GB system RAM) and RTX 3060 (32 GB). The dataset sits in VRAM, so a fitness evaluation is a column-index operation on a resident tensor. Population evaluation runs concurrently across both cards through a work queue, weighted because the 3080 Ti finishes first and a round-robin leaves it idle.

Expect 1 to 2 hours per full GA configuration, 50 to 100 hours for the full run matrix.

## Reproducibility package

Protocol YAML and its hash, pinned environment, split indices, every Pareto front as JSON, aggregated results as CSV, and the analysis scripts that turn those CSVs into the figures.

## Reference

CICIoMT2024, Canadian Institute for Cybersecurity.
NSGA-II: Deb, Pratap, Agarwal and Meyarivan, 2002.
