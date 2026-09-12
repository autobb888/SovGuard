# Retrieval dual-margin (DL-011 S3-v1a)

Land base tip: `776aa4a` (main). Thin non-parametric near-neighbor layer (`retrieval_dual_margin`) that flags text close to known **attack** prototypes and far from **NotInject / chat-benign** prototypes.

## Honesty

- **Train catch ≠ holdout claim.** AttackIndex embeds only the **train** slice (~70% of the 94 deepset flat-zeros, stratified by fixture `class`). Holdout IDs are never indexed; report lift only on holdout (see `data/retrieval/s3-v1a-split.json` + `holdout-eval-v1.json`).
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
