# DL-011d D1 — PIGuard secondary classifier

Thin second head. **Not** a DeBERTa replacement. **Not** a marketing 80% claim.

## Behaviour

- Layer: `classifier_piguard`
- Runs only when `scan()` `mode === untrusted_content` (no infer on `user_chat` / `security_research`)
- Fire: `score_pg ≥ 0.5` **and** (`pa ≥ 0.15` OR retrieval hit OR light PI cue OR semantic `attackSim ≥ 0.15`)
- Emit `[0.30, 0.45]` — cannot sole-block (`blockThreshold` 0.7)
- Dual-agree block is out of v1 (`classifier_piguard` is excluded from lone-classifier keyword corroboration)
- Fail-open if weights missing (`SOVGUARD_PIGUARD_DIR` or `models/piguard-onnx/`)
- `CLF_ESCALATE` untouched

## Weights (soft residual)

Unofficial ONNX export of official [`leolee99/PIGuard`](https://huggingface.co/leolee99/PIGuard) (InjecGuard rename), HF commit `dd78b24e330193a22d2293ac66922dd4f982f563`.

| File | sha256 |
| --- | --- |
| `models/piguard-onnx/model.onnx` | `5888eb0f407e06efc4aa53c715ccf869cf597c6c8687bfcd220f5e57ed749e80` |
| official `tokenizer.json` | `5124ef2ead1a10a717703bc436de7f353da76d6340e4587719b42b1693707964` |

RO Docker models mount: never write into `PIGUARD_DIR`. Prefer `Tokenizer.fromString` (in-memory Metaspace downgrade). Reuse a readable `tokenizer.compat.json` if present. Fallback write is `SOVGUARD_PIGUARD_TMP` or `os.tmpdir()`, sha-keyed — not the models volume.

Download: `scripts/download-piguard-onnx.sh`. Not in npm `files[]` — self-host must ship the dir or set `SOVGUARD_PIGUARD_DIR`.

## D1.5 / D1.6 eval (2026-09-12, this tip)

- Holdout 28 catch `@score≥0.3`: **10/28 (35.7%)** vs S3-v1a `faf3c7c` 6/28 (21.4%) → **+14.3 pp** (meets ≥+10). PG layer fire 9/28.
- NI-B 41 `@user_chat`: secondary skipped 41/41 (must-not-worsen by construction). Combined score-block 41/41 is the existing PA/regex fence, not a D1 add.

## D1b (2026-09-12)

No combine / τ_pg / emit / RO change. AttackIndex paraphrase expand is retrieval-only; this layer's fire rule is unchanged. Holdout-28 catch@≥0.3 **24/28** (D1 was 10/28); PG fire still 9/28. Expand is not an 80% claim.

## D1c (2026-09-12)

No combine / τ_pg / emit / RO change. Miss∩ expand is retrieval-index only. Holdout-28 catch@≥0.3 **24/28** (held vs D1b). miss∩-25 catch 23/25, PG fire 0/25 (soft ceiling). Not an 80% claim.

## D1d (2026-09-12)

No combine / τ_pg / emit / RO change. Unique-hit paraphrase expand is retrieval-index only. Holdout-28 catch@≥0.3 **24/28** (held). Unique-hit para-29: catch 24/29, PG≥0.5 23/29, fire 18/29. Miss∩ PG ceiling stands. Not an 80% claim.
