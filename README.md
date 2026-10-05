# Before the Device Goes Dark

**How feature compression delays attack detection on medical IoT devices**

> Per-device, anytime-valid change detection on IoMT traffic: measuring what feature compression costs **in seconds**, explaining where the cost comes from, and testing whether selection can reduce it.

| | |
|---|---|
| **Status** | Protocol draft. Locks when the four-week gate closes (early November 2026). |
| **Authors** | Person A\*, Person B (Pranava)\*. \*Co-first authors, equal contribution. |
| **Primary data** | CICIoMT2024 packet captures |
| **Secondary data** | IoMT-TrafficData (slow attacks), CICIoT2023 (optional cross-capture) |
| **Target venue** | *Computers & Security* (reach: *IEEE TIFS*). Preprint August 2027. |

---

## Contents

1. [TL;DR](#1-tldr)
2. [Problem statement](#2-problem-statement)
3. [Why compression should cost time](#3-why-compression-should-cost-time)
4. [Research questions](#4-research-questions)
5. [Contributions](#5-contributions)
6. [Positioning against prior work](#6-positioning-against-prior-work)
7. [Data](#7-data)
8. [Method](#8-method)
9. [Metrics](#9-metrics)
10. [Statistics](#10-statistics)
11. [Four-week gate and fallback](#11-four-week-gate-and-fallback)
12. [Pre-committed reporting](#12-pre-committed-reporting)
13. [Team and task division](#13-team-and-task-division)
14. [Timeline](#14-timeline)
15. [Scope and limitations](#15-scope-and-limitations)
16. [Repository layout](#16-repository-layout)
17. [Glossary](#17-glossary)
18. [References](#18-references)
19. [Changelog: what this plan merges](#19-changelog-what-this-plan-merges)

---

## 1. TL;DR

- Hospitals monitor medical IoT devices **passively from the network**, one continuous stream per device. The monitor must fit on a gateway, so designers **cut the feature set**.
- The field justifies that cut with **closed-set, per-window accuracy**. That evaluation cannot see **how long** the monitor takes to raise the alarm.
- Theory says compression can only **increase the minimum detection delay** (Lorden's bound plus the data-processing inequality).
- We measure **delay against feature count k**, per device, at a **matched false-alarm rate**, across selectors and detectors. We then decompose the cost into **information lost** versus **signal the detector fails to use**.

---

## 2. Problem statement

Intrusion detection for medical IoT devices runs on network monitors that must fit on gateways or edge boxes, so designers reduce the feature set. That reduction is justified by closed-set, per-window accuracy: shuffled traffic windows from known attack classes, scored one at a time.

A hospital monitor works differently. It watches each device as a continuous stream, has a false-alarm budget, and must raise the alarm early. Feature selectors keep the features that separate the attacks they were trained on, and closed-set evaluation then tests them on more windows of those same attacks. Two things go unseen:

1. **how long** detection takes after an attack starts;
2. **whether the dropped features carried the signal** that would have caught it early.

A compressed detector can keep 99% window accuracy and still alarm minutes late on a slow attack. Floods hide this, because any detector catches a flood in its first window. Reconnaissance, malformed MQTT, spoofing and slow ramps expose it.

**This work measures detection delay as a function of feature count, on per-device streams, at a matched false-alarm rate. It then explains the delay cost and tests a selection objective designed to reduce it.**

---

## 3. Why compression should cost time

For a sequential detector whose average run length to a false alarm is γ, the smallest achievable worst-case detection delay grows as γ → ∞ like

```
delay*  ≈  log γ / KL(P_attack ‖ P_benign)          (Lorden 1971; Lai 1998)
```

Restricting the detector to a feature subset S cannot increase KL (data-processing inequality):

```
KL_S(P_attack ‖ P_benign)  ≤  KL_full(P_attack ‖ P_benign)
⇒  delay*_S  ≥  delay*_full          at the same false-alarm rate
⇒  delay inflation (bound)  ≈  KL_full / KL_S
```

**How we use this:**
- It is **motivation and an estimable quantity, not a contribution.**
- It is asymptotic, assumes independent observations before and after the change, and assumes a detector that knows P_attack. Our detectors do not know P_attack.
- We therefore use it for **direction and ratios only**, never as an absolute delay target.
- Dependence is controlled by grouping windows into blocks (§8.5).

---

## 4. Research questions

### Core

| RQ | Question | Owner |
|---|---|---|
| **RQ1: Delay cost** | At a matched false-alarm rate, how does time-to-detect change as k shrinks, per attack class? Does closed-set accuracy at the same k predict that change? | A |
| **RQ2: Cause** | Does the delay track **information lost** (KL on the subset S falls) or **unused signal** (KL on S holds but the detector's score loses it)? Does adding back the dropped features with the highest KL contribution recover the delay? | B |
| **RQ3: Selector** | At matched k, do selection methods differ in delay cost? Does a selector that never sees attack labels behave differently from taxonomy-driven selectors? | B |

### Extended (only if the core is complete)

| RQ | Question | Owner |
|---|---|---|
| **RQ4: Delay-aware selection** | Inside the training data, hide each known family in turn and score candidate subsets by how fast they detect it (episodic objective). Does this beat standard selection at matched k? | B |
| **RQ5: Lifecycle phases** | Does a phase-aware detector reduce false alarms across power, idle, active and interaction phases without hiding attacks inside a benign phase? Runs only if gate item 6 passes. **Must use the min-over-phases construction (§8.4).** | A |

---

## 5. Contributions

1. **Delay-cost curves.** The first measurement of time-to-detect against feature count on per-device IoMT streams, at matched false-alarm rates, across four selectors and three detector types.
2. **Information loss vs unused signal.** A decomposition of the delay cost into KL lost on the subset and KL lost by the detector's score, checked by an add-back ablation.
3. **An audited per-device stream benchmark** built from the CICIoMT2024 packet captures. It includes a leakage audit of the released CSVs (including the 10-vs-100-packet window artefact), splice-artefact controls, measured autocorrelation and the chosen block size, with code released.

---

## 6. Positioning against prior work

| Work | What it does | What it does not do (our gap) |
|---|---|---|
| Rehman, Kalakoti & Bahşi, ICISSP 2025 | Feature selection on CICIoMT2024 | Closed-set only; no time axis |
| Doménech et al., *Internet of Things* 32 (2025) | CICIoT2023 ↔ CICIoMT2024 cross-dataset, 44 shared features | No compression axis; closed-set |
| Uddin, Chu & Rafeh, arXiv 2508.10346 (2025) | Leave-one-category-out zero-day detection on CICIoMT2024 (one-class models, Reptile) | Fixed feature set; per-window; no delay |
| Jodayree et al., *Sci Rep* 2026 ⚠️; Sakr et al., MDPI *Computers* 2026 ⚠️ | Leave-one-attack-out evaluation | Fixed features; no delay |
| Sarhan et al., *IJIS* 2023 | Distance between feature distributions explains zero-day detection | Per-window; no compression or delay |
| Tartakovsky et al. (2006 and later) | Changepoint detection for network intrusion, including low-rate attacks | Assumes a known pre-change model; no compression axis |
| Urbina et al., CCS 2016 | Stealthy attacks scored against impact and false-alarm rate (industrial control) | Not IoMT; no feature compression |
| Bhattacharyya & Ramdas, arXiv 2609.27179 (2026) ⚠️ | Optimal conformal change detectors (conformal e-detectors) | Methods paper; not applied to intrusion detection |
| Lorden 1971; Lai 1998 | Lower bounds on detection delay | Theory; no empirical compression study |

⚠️ = verify the citation (authors, year, venue) before writing.

**The claim:** nobody has measured detection delay as a function of feature count on per-device streams at a matched false-alarm rate. Re-verify this immediately before submission.

---

## 7. Data

| Dataset | Role | Notes |
|---|---|---|
| **CICIoMT2024** | Primary; all core RQs | Wi-Fi and MQTT packet captures. About 11 real IP devices plus the simulated MQTT fleet; exact count confirmed at the gate. Features **re-extracted from pcaps** with one uniform window. |
| **IoMT-TrafficData** | Second source of slow attacks | Slowloris, Slow Read, RUDY, ARP spoofing, scanning. Within-dataset only (different features). |
| **CICIoT2023** | Optional cross-capture | Families absent from CICIoMT2024 (Mirai, web-based), on the 44 shared features. Threshold calibrated on CICIoT2023 **benign traffic only**. |

---

## 8. Method

### 8.1 Attack set (fixed now, before any results)

- **Reconnaissance:** ping sweep, vulnerability scan, and the other recon captures
- **Malformed MQTT**
- **ARP spoofing**
- **Slow ramps** of SYN flood and MQTT publish flood, built from **attacker-side packets only**
- **Fixed-rate floods,** reported separately as a floor every method should pass

Every class is reported, whatever the result.

### 8.2 Stream construction (Person A)

- Splice benign and attack traffic **only at natural capture boundaries**.
- Re-extract features from the merged packets, using one uniform window for every class.
- **Ramp handoff:** Person B produces the attacker-side packet schedule for each ramp; Person A splices it into streams. The interface format is fixed at the gate.

### 8.3 Validity controls (Person B, audited by Person A)

- **Splice-point classifier.** It must perform at chance, with a stated power check, or the affected streams are dropped.
- **Autocorrelation and block size.** Measure within-stream autocorrelation and group windows into blocks. Delay grows by about one block length, so blocks are kept as short as the autocorrelation allows.
- **Leakage audit** of the released CSVs: duplicates, overlapping windows, and the window-size artefact.

### 8.4 Detectors (Person A)

All detectors use a **score trained on benign traffic only**, so they never see the attack they are asked to catch.

| Detector | Role |
|---|---|
| Online **conformal e-detector** (Bhattacharyya & Ramdas 2026) | Anytime-valid detector |
| **CUSUM** on the same score | Classical baseline |
| **Fixed threshold** per window on the same score | Per-window baseline |

All three are tuned to the **same false-alarm rate** on held-out benign traffic, **separately at every k**.

**RQ5 only.** A detector calibrated on all phases pooled fires on benign phase changes, so it is invalid. Use per-window e-values equal to the **minimum over phase-specific e-values**, and take that minimum over a **conformal prediction set** of plausible phases. That keeps all evidence on one filtration under one composite null.

### 8.5 Feature selection (Person B)

- k from the full set (45 native features) down to 6.
- The **family under test is held out of selection**, so it never influences which features survive.
- Each ranking gives every k at once.

| Selector | Uses attack labels? | Why it's included |
|---|---|---|
| Mutual information (multiclass) | Yes | Standard filter |
| LightGBM importance | Yes | Standard embedded method |
| Binary-label MI (benign vs attack) | Partly | Attack-agnostic baseline |
| **Label-free selector** (benign-only variance or benign-model ranking) | **No** | Tests whether taxonomy-driven selection causes the delay |

### 8.6 RQ2 decomposition (Person B)

Two KL quantities at each k:

| Quantity | Meaning | Estimation |
|---|---|---|
| **KL_S**: KL between benign and attack on feature subset S | Information **available** | Multivariate estimator with bootstrap intervals. Treated as an **estimate, possibly a lower bound**, never as a certified ceiling. |
| **KL_score**: KL between benign and attack on the detector's 1-D score | Information **used** | 1-D estimate; reliable |

- **Information lost:** KL_S falls as k shrinks.
- **Unused signal:** KL_S holds but KL_score falls.
- **Add-back ablation:** re-insert the dropped features with the highest KL contribution and check whether delay recovers. This is the only causal claim.

```python
import numpy as np
from scipy.stats import gaussian_kde

def kl_1d(score_attack, score_benign, grid=2000, eps=1e-12):
    """KL(P_attack || P_benign) on the 1-D detector score via KDE."""
    lo = min(score_attack.min(), score_benign.min())
    hi = max(score_attack.max(), score_benign.max())
    x = np.linspace(lo, hi, grid)
    p = gaussian_kde(score_attack)(x) + eps
    q = gaussian_kde(score_benign)(x) + eps
    p, q = p / p.sum(), q / q.sum()
    return float(np.sum(p * np.log(p / q)))

def bootstrap_ci(f, a, b, n=500, rng=np.random.default_rng(0)):
    vals = [f(rng.choice(a, len(a)), rng.choice(b, len(b))) for _ in range(n)]
    return np.percentile(vals, [2.5, 97.5])
```

---

## 9. Metrics

| Metric | Role |
|---|---|
| **Delay inflation:** delay at k ÷ delay at full features, at matched false-alarm rate | **Headline** |
| **Absolute delay in seconds** at each k | **Headline** (guards against the ratio flooring at 1 when full-feature detection is in the first block) |
| Probability of detection within a fixed horizon (misses counted, not dropped) | Supporting |
| Closed-set accuracy at the same k | Contrast for RQ1 |
| KL_S and KL_score at each k, with bootstrap intervals | RQ2 |
| False alarms per device-hour | Supporting |
| Measured vs nominal run length | Validity check |
| Detection before harm, on fixed-rate captures with a measured harm point only | Case study |

---

## 10. Statistics

- **Unit of analysis:** the individual attack, nested in its family. Seeds are averaged within an attack.
- **Mixed-effects model:** attack as a random effect; k, selector and detector as fixed effects.
- **Paired tests:** Wilcoxon signed-rank over attacks, Holm correction, effect sizes with confidence intervals.
- **Equivalence test** so a flat result counts as evidence. **Margin (proposed, confirm at lock): delay inflation within ±20% of full-feature delay, or within one block length, whichever is larger.**

---

## 11. Four-week gate and fallback

Time-boxed; ends early November 2026. **Neither person closes their own gate items.**

| # | Gate item | Owner | Closed by |
|---|---|---|---|
| 1 | Download CICIoMT2024 pcaps and count usable per-device IP streams. **Below about 10, stop.** | A | B |
| 2 | Build one stream end to end: benign plus ARP spoofing, features re-extracted | A | B |
| 3 | At least three non-flood attack classes with enough traffic for repeated streams | B | A |
| 4 | Measure within-stream autocorrelation and choose a block size | B | A |
| 5 | The conformal e-detector holds its nominal run length on blocked benign traffic | A | B |
| 6 | *(RQ5 only)* Lifecycle phases separable per device | A | B |

**Fallback if items 1–5 fail:** a cut-down compression study.
- CICIoMT2024 plus the CICIoT2023 cross-capture test
- The same four selectors
- MLP and LightGBM
- Hidden-attack detection at a fixed benign false-positive rate
- The add-back ablation

The feature-selection pipeline carries over unchanged.

---

## 12. Pre-committed reporting

If delay does not grow as k shrinks **and** the equivalence test passes, we report that **feature compression is safe for onset detection on these attacks**, with the evidence. This framing is fixed before seeing results.

---

## 13. Team and task division

Co-first authors, equal contribution. Effort 1–5, novelty 0–3, visibility 1–3.

| Task | Effort | Novelty | Visibility | Owner |
|---|---|---|---|---|
| Stream construction from pcaps (per-device streams, splicing, feature re-extraction) | 5 | 1 | 2 | A |
| Detectors: conformal e-detector, CUSUM, fixed threshold, all at the same false-alarm rate | 4 | 2 | 2 | A |
| Run-length audit | 2 | 0 | 2 | A |
| **RQ1 delay-cost curves** | 3 | 3 | 3 | A |
| Statistics: mixed-effects model, Wilcoxon + Holm, equivalence test | 3 | 0 | 2 | A |
| Harm case study (fixed-rate captures) | 2 | 2 | 2 | A |
| IoMT-TrafficData replication | 3 | 1 | 2 | A |
| Slow ramps of SYN and MQTT publish floods (attacker-side schedules → A) | 2 | 1 | 1 | B |
| Leakage audit of the released CSVs | 2 | 1 | 2 | B |
| Splice-point classifier with power check | 3 | 1 | 2 | B |
| Autocorrelation and block size | 2 | 0 | 1 | B |
| Feature selection: 4 selectors, k from 45 to 6, tested family held out | 3 | 1 | 2 | B |
| Closed-set baselines at each k | 2 | 0 | 2 | B |
| **RQ2 KL decomposition (KL_S and KL_score) with bootstrap** | 4 | 2 | 3 | B |
| RQ2 add-back ablation | 2 | 2 | 2 | B |
| RQ3 selector comparison | 2 | 1 | 2 | B |
| Paper writing | 3 | 0 | 3 | Split by section |
| **Total A** | **22** | **9** | **15** | |
| **Total B** | **22** | **9** | **17** | |

**Critical path:** stream construction (A). While streams are being built, B starts the leakage audit and the selection pipeline on the released CSVs, so no one waits.

**Writing split:** A writes the detectors, RQ1 and validity sections. B writes the theory (§3), RQ2, RQ3 and the related work. Both write the introduction and conclusion.

---

## 14. Timeline

| Period | Output |
|---|---|
| Oct – early Nov 2026 | Gate passed or fallback chosen; protocol locked and date-stamped |
| Nov – Dec 2026 | Full stream benchmark; detectors calibrated; first delay curves for one selector |
| Jan 2027 | RQ1 results on all selectors; research LOR requested |
| Feb – Mar 2027 | RQ2 decomposition and ablation; RQ3 comparison |
| Apr – May 2027 | IoMT-TrafficData replication; RQ4 or RQ5 if time allows |
| Jun – Jul 2027 | Statistics and manuscript |
| Aug 2027 | Preprint posted; submission to *Computers & Security* (reach: *IEEE TIFS*); LOR writers updated with full results |

---

## 15. Scope and limitations

**In scope:** attacks with an identifiable target device or broker; Wi-Fi and MQTT devices; Bluetooth shutdowns as case studies only.

**Out of scope:** payload tampering, automated blocking, multi-class attribution, clinical deployment, edge hardware benchmarks (CPU latency per k is reported instead).

**Limitations:**
1. **Onset is semi-synthetic.** Attack streams come from spliced captures. Splice controls reduce the risk that detectors learn splice artefacts but cannot remove it.
2. **Ramps are synthetic on the attacker side.** Recorded device and broker responses don't match a ramped rate, so they are dropped from ramped streams and **no harm claim is made for ramps**.
3. **The delay bound is asymptotic,** and multivariate KL estimates are noisy and possibly biased low. RQ2 reports intervals and makes no causal claim beyond the add-back ablation.
4. **Few real devices.** About 11 real IP streams limits per-device conclusions. All data comes from lab testbeds.
5. **No anytime-valid guarantee is claimed under dependence.** We claim a nominal false-alarm level with an audited run length.

---

## 16. Repository layout

```
.
├── README.md                 # this plan
├── protocol/                 # locked, date-stamped protocol + gate sign-offs
├── data/                     # download scripts only (no raw data committed)
├── streams/                  # A: pcap parsing, splicing, re-extraction, ramps interface
├── audit/                    # B: leakage audit, splice classifier, autocorrelation
├── selection/                # B: four selectors, held-out-family logic, k sweep
├── detectors/                # A: conformal e-detector, CUSUM, threshold, calibration
├── analysis/
│   ├── rq1_delay/            # A
│   ├── rq2_kl/               # B: KL_S, KL_score, bootstrap, add-back ablation
│   ├── rq3_selectors/        # B
│   └── stats/                # A: mixed-effects, Wilcoxon + Holm, equivalence
└── paper/                    # manuscript, figures
```

---

## 17. Glossary

| Term | Meaning |
|---|---|
| **Per-device stream** | One device's traffic as a continuous sequence of windows over time |
| **Change detection** | Raising an alarm as soon as a stream's behaviour changes, e.g. an attack starts |
| **Average run length (ARL), γ** | Average time between false alarms on benign traffic |
| **Detection delay** | Time from attack onset to alarm |
| **Delay inflation** | Delay at k features ÷ delay at all features |
| **KL divergence** | How far attack traffic sits from benign traffic, per observation |
| **Data-processing inequality** | Removing features can never increase KL |
| **Lorden's bound** | Minimum delay ≈ log γ / KL, as γ grows |
| **KL_S vs KL_score** | Information available in the features vs information the detector's score actually uses |
| **Conformal e-detector** | A distribution-free change detector with a nominal false-alarm guarantee under exchangeability |
| **CUSUM** | Classical cumulative-sum change detector |
| **Block** | A group of consecutive windows used to reduce autocorrelation |
| **Splice artefact** | A pattern created by joining captures, which a detector could learn by mistake |
| **Add-back ablation** | Re-insert dropped features and check whether delay recovers; the causal test |
| **Equivalence test** | A test that can show "no meaningful difference", so a flat result counts |
| **Held-out family** | The attack family kept out of feature selection, so selection never sees it |

---

## 18. References

Verify every entry (authors, year, venue) before citing. ⚠️ marks entries not yet confirmed.

- Dadkhah et al., *CICIoMT2024: A benchmark dataset for multi-protocol security assessment in IoMT*, Internet of Things, 2024.
- Neto et al., *CICIoT2023*, Sensors, 2023.
- Areia et al., *IoMT-TrafficData*, IEEE Access, 2024.
- Doménech et al., *Evaluating and enhancing IDS in IoMT: the importance of domain-specific datasets*, Internet of Things 32, 2025.
- Rehman, Kalakoti & Bahşi, ICISSP 2025.
- Uddin, Chu & Rafeh, *A Hierarchical IDS for Zero-Day Attack Detection in IoMT Networks*, arXiv 2508.10346.
- Jodayree et al., Sci Rep 2026. ⚠️
- Sakr et al., MDPI Computers 2026. ⚠️
- Sarhan et al., *From zero-shot machine learning to zero-day attack detection*, IJIS, 2023.
- Tartakovsky, Rozovskii, Blažek & Kim, *A novel approach to detection of intrusions in computer networks via adaptive sequential and batch-sequential change-point detection methods*, IEEE TSP, 2006.
- Urbina et al., CCS 2016.
- Vovk, *Testing randomness online*, Statistical Science, 2021.
- Shin, Ramdas & Rinaldo, *E-detectors: a nonparametric framework for sequential change detection*.
- Bhattacharyya & Ramdas, *Change detection with conformal martingales: new optimal constructions*, arXiv 2609.27179, 2026. ⚠️ (check author list)
- Choe & Ramdas, *Combining evidence across filtrations*, arXiv 2402.09698 (for RQ5).
- Lorden, *Procedures for reacting to a change in distribution*, Annals of Mathematical Statistics, 1971.
- Lai, *Information bounds and quick detection of parameter changes in stochastic systems*, IEEE Trans. Information Theory, 1998.
- Cover & Thomas, *Elements of Information Theory* (data-processing inequality).

---

## 19. Changelog: what this plan merges

| From | Kept | Dropped or changed |
|---|---|---|
| **"Before the Device Goes Dark"** (per-device onset detection) | Per-device streams, conformal e-detectors, splice controls, harm case study, pre-commitment, gate | The hedged lifecycle detector is no longer the headline: the pooled half fires on benign phase changes. RQ5 is optional and requires the min-over-phases fix. No harm claims for ramps. |
| **"When Closed-Set Accuracy Lies"** (compression and unseen attacks) | Compression axis (k sweep), held-out family excluded from selection, information-loss idea, add-back ablation, episodic objective (now RQ4), CICIoT2023 cross-capture | NSGA-II and wrapper/metaheuristic selection removed in favour of rankings. TV bound replaced by KL/Lorden. Single-window recall replaced by delay. |
| **Review fixes added at lock** | — | KL_score added to RQ2; absolute delay added to headline metrics; label-free selector added; equivalence margin proposed; ramp handoff defined; uncertain citations flagged; co-first authorship recorded. |
