# D0 — ProtectAI ↔ PIGuard disagreement harness

Measure-only. **Not** wired into `scan()` / combine / escalate. Do **not** mix D1 on this branch.

- Script: `scripts/d0-piguard-disagreement.ts`
- Weights: `models/piguard-onnx/` (gitignored) — ONNX export of [`leolee99/PIGuard`](https://huggingface.co/leolee99/PIGuard). Download: `scripts/download-piguard-onnx.sh`
- ProtectAI: existing `localClassifierScan` / `models/deberta-v3-prompt-injection`
- Packs: 94 deepset flats + 28 S3 holdout subset + 41 NI-B
- Artifact (gitignored): `docs/private/2026-09-12-d0-piguard-disagreement.json`

## Frozen run (2026-09-12, base `faf3c7c`)

| pack | n | note |
| --- | --- | --- |
| flat94 | 94 | all PA-miss at τ=0.15 |
| holdout28 | 28 | subset of flat94 |
| nib41 | 41 | user_chat must-not-block |

- τ_pg = 0.5, τ_block = 0.7
- unique lift on PA-miss flats: **63/94 (67%)** → GO (≥15–20%)
- holdout unique: **12/28**
- NI-B false_block: PA 34 / PG **6** → GO (PG ≤ PA)
- latency mean: PA 140.7 ms, PG 73.5 ms

Weights:

- model.onnx sha256 `5888eb0f407e06efc4aa53c715ccf869cf597c6c8687bfcd220f5e57ed749e80` (ahmedomuharram/piguard-onnx)
- tokenizer.official.json sha256 `5124ef2ead1a10a717703bc436de7f353da76d6340e4587719b42b1693707964` (leolee99/PIGuard)
- artifact sha256 `4c4fd066fd0a27b7f151db3edbe88f9148e68ee1e2ddde2e3cd12252bc275e8d`

Soft residual: unofficial ONNX export + Node tokenizer Metaspace downgrade. Re-run if Defense Lab names a different weights path.
