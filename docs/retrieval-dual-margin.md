# Retrieval dual-margin (DL-011 S3-v1a)

Land base tip: `776aa4a` (main). Thin non-parametric near-neighbor layer (`retrieval_dual_margin`) that flags text close to known **attack** prototypes and far from **NotInject / chat-benign** prototypes.

## Honesty

- **Train catch ≠ holdout claim.** AttackIndex embeds the **train** slice (~70% of the 94 deepset flat-zeros, stratified by fixture `class`) plus D1b **paraphrases of holdout parents**. Holdout original IDs are never indexed; report lift only on holdout originals (see `data/retrieval/s3-v1a-split.json` + `holdout-eval-v1.json`). The paraphrase expand is **not** an 80% deepset catch claim.
- Indexed (train) neighbor fire is expected by construction; it is a unit-test signal, not a published catch rate.
- BenignIndex holds all 41 NI-B fence texts.

## Mode gate

| Mode | Behavior |
|------|----------|
| `untrusted_content` | Layer may embed + evaluate |
| `user_chat` / default | **Skip entirely** (no embed) |
| `security_research` | **Skip** in v1a |

`scanContext` passes `resolved.mode` into `scan()` so the gate is honored on the HTTP path.

## Dual-margin + corroboration (v1a)

```
retrieval_hit = (d_atk ≤ τ_atk) AND (d_ben ≥ τ_ben)
fire = retrieval_hit AND (light_PI_cue OR otherMax ≥ 0.15)
emit score ∈ [0.30, 0.45]
```

Defaults: `τ_atk=0.40` (sim ≥ 0.60), `τ_ben=0.15` (train-tuned; frozen in code + index JSON).

`light_PI_cue`: regex/indirect flags, boundary/decomposition/delayed-trigger/unicode escalate, or other-layer score ≥ 0.15 (semantic `attackSim` **counts**; classifier does **not**).

## Never sole-block

Emit is capped at **0.45**; `blockThreshold` is **0.7**. The layer is included in `combineScores` `maxAll` (unlike semantic) but cannot alone produce `likely_injection` / blocked. No `CLF_ESCALATE` / escalate-global wiring.

## Build

```bash
npx tsx scripts/build-retrieval-index-v1a.ts
```

Requires MiniLM ONNX under `models/paraphrase-multilingual-MiniLM-L12-v2/`. Override index dir with `SOVGUARD_RETRIEVAL_DIR`.

## Out of scope

S3-v1b sole-block, PIGuard, ScanMode router changes, keyword/threshold growth, website bake.

## Holdout snapshot (pre-handoff)

Measured on this tip after MiniLM index freeze (`n=28` holdout flats, never indexed):

- baseline catch @ ≥0.3 on these IDs: **0%** (flat-zeros @ `6400998`)
- retrieval_hit (dual-margin, no cue): **6/28 (21.4%)**
- fire with semantic cue (otherMax ≥ 0.15): **6/28 (21.4%)** → **+21.4 pp** lift (meets ≥+10 pp)
- τ_atk=0.40, τ_ben=0.15; min train attack↔benign distance 0.496


## D1b paraphrase expand (2026-09-12)

AttackIndex also embeds **36 holdout-parent paraphrases** (`source=paraphrase`, `parentHoldoutId`). Holdout original flat IDs stay **unindexed**. Train vectors are reused (not re-embedded).

This is a robustness / miss-assist expand. It is **not** an 80% deepset catch claim and must not be marketed as one.

Seeds: `pentest/payloads/s3-attackindex-paraphrases.json` (Threat Scout, holdout-biased). Rebuild is still:

```bash
npx tsx scripts/build-retrieval-index-v1a.ts
```

PIGuard combine / τ_pg / emit band / RO `fromString` / ScanMode / escalate are unchanged.


## Holdout snapshot (D1b)

Measured on `feat/dl-011d-d1b-paraphrase` off `6749a45` after paraphrase expand (`n=102` AttackIndex = 66 train + 36 holdout-parent paraphrases). Holdout original IDs still unindexed.

- Holdout-28 combined catch @ >=0.3: **24/28** (must-not-drop vs D1 **10/28**). Retrieval neighbor-hit 28/28 (paraphrase assist); PIGuard fire still **9/28** (unchanged vs D1).
- 36-paraphrase pack @ `untrusted_content`: retrievalHit 36/36 (indexed themselves), combined catch@>=0.3 **32/36**, PG raw>=0.5 **31/36**, PG fire **28/36**.
- NI-B 41 @ `user_chat`: retrieval + PIGuard not attached (scores 0). Combined likely_injection 41/41 is the existing PA/regex fence, not a D1b add.
- **Not an 80% claim.** 24/28 is an internal residual after paraphrase-neighbor assist, not a published deepset catch rate.


## D1c miss∩ expand (2026-09-12)

Train miss∩ (11 ids) are tagged `source=miss_intersect` if already in the 66-train slice — **no duplicate vectors**. Holdout miss∩ originals (14) are **refused** (D1b paraphrases already cover those parents). Unique-hit paraphrases (29) stay out of scope.

Expected n remains **102** unless a train id was missing (then add that sourceId only). This is **not** an 80% deepset claim. Train re-index may be a no-op / representation ceiling.


## Holdout snapshot (D1c)

Measured on `feat/dl-011d-d1c-miss-intersect` off `f6a5367` after tagging train miss∩ (n=102 unchanged; 11 tagged, 0 added, 14 holdout refused).

- Holdout-28 combined catch @ >=0.3: **24/28** (must-not-drop vs D1b). retrievalHit 28/28; PG fire still **9/28**.
- miss∩-25 @ `untrusted_content`: catch@>=0.3 **23/25**, retrievalHit 25/25, PG fire **0/25** (representation ceiling on residual both-miss — non-blocking).
- NI-B 41 @ `user_chat`: ret=0 pg=0 (41/41).
- **Not an 80% claim.** Train re-index was a no-op (already in the 66).


## D1d unique-hit paraphrase expand (2026-09-12)

Adds **29** paraphrases of D1 unique-hit **train** flats (`source=paraphrase`, parent = train sourceId). Expected n = **131** (102+29). Holdout originals still unindexed. Miss∩ PG-fire ceiling (0/25) is an unchanged soft residual.

This is **not** an 80% deepset claim.


## Holdout snapshot (D1d)

Measured on `feat/dl-011d-d1d-unique-hit-para` off `ed87a8c` after adding 29 train unique-hit paraphrases (`n=131`).

- Holdout-28 combined catch @ >=0.3: **24/28** (held vs D1c). retrievalHit 28/28; PG fire still **9/28**.
- Unique-hit para-29 @ `untrusted_content`: catch@>=0.3 **24/29**, retrievalHit 29/29, PG raw>=0.5 **23/29**, PG fire **18/29**.
- NI-B 41 @ `user_chat`: ret=0 pg=0 (41/41).
- Miss∩ PG-fire ceiling (0/25) unchanged soft residual.
- **Not an 80% claim.**
