# SovGuard Classifier Model-Upgrade Plan

> Follow-on from the 2026-07-11 detection-tuning work. The tuning diagnosis proved the
> English `protectai/deberta-v3-base-prompt-injection` (v1) is the root cause of BOTH
> failure modes — it false-fires on benign trigger-word and non-English prompts (drove
> ~75% of NotInject false-positives) and under-fires on mild/novel injections. Threshold/
> veto tuning has a hard ceiling (exp1 got NotInject FP 51%→47% safely; exp3 got 47%→40%
> but cost a held-out Russian attack — held back). The real fix is a better classifier.

**Goal:** Replace (or A/B and conditionally swap) the English DeBERTa v1 classifier with a
multilingual, self-hostable, low-false-positive injection classifier — validated on OUR
benchmarks before committing — to cut non-English/trigger-word over-defense without losing
attack recall.

**Decision (from 2026-07-11 research):** A/B two candidates, ship whichever wins on our
held-out + NotInject + deepset suite:
1. **Primary — Meta Llama Prompt Guard 2, 86M** (`meta-llama/Llama-Prompt-Guard-2-86M`):
   mDeBERTa-base, multilingual (EN/FR/DE/HI/IT/PT/ES/TH), binary benign/malicious, *designed
   not to fire on trigger words*, ONNX exports exist (~350MB fp32). It is essentially "our
   fine-tune, already done." **Catch: Llama 4 Community License** (attribution "Built with
   Llama" + AUP; separate license only >700M MAU) — needs a legal sign-off since we resell
   detections.
2. **Hedge — fine-tune our own `mDeBERTa-v3-base`** with the PIGuard/InjecGuard **MOF**
   recipe (MIT) + NotInject-style trigger-word hard-negatives + machine-translated injection
   datasets + our own logged benign prompts. MIT-clean, multilingual, our benign data baked
   in. More effort (data assembly is the real work; ~$50–300 GPU, hours).

**Tech stack:** ONNX Runtime (existing), HF `tokenizers` (existing), `optimum` for export,
Node/TS engine. Eval via existing `npm run eval` (held-out), `npm run eval:public`
(NotInject + deepset), and `pentest/eval/diagnose.ts` (per-layer attribution).

---

## Integration reality (from `src/scanner/classifier-local.ts`)

The swap is mechanically small; the *consequences* are large (a new model shifts every score,
so the fusion/veto in `src/scanner/index.ts` must be re-tuned and the WHOLE suite re-run).

Current loader (`classifier-local.ts`): loads `${SOVGUARD_MODEL_DIR}/model.onnx` +
`tokenizer.json`, tokenizes → `input_ids`/`attention_mask` (+ `token_type_ids` if the model
declares it), runs a 2-class ONNX session, `softmax(logits)[1]` = injection prob = layer
score. Flags at >0.5 / >0.8.

What a swap touches:
- **Model dir + files**: PG2-86M ONNX + its `tokenizer.json` under a new dir (e.g.
  `models/prompt-guard-2-86m/`). Add to `scripts/download-model.sh` with a pinned URL + sha256
  (mirror the existing DeBERTa download).
- **Output mapping**: confirm PG2's label order (index for MALICIOUS). DeBERTa v1 is
  `[SAFE, INJECTION]`; PG2-2 is binary benign/malicious — verify which index, don't assume.
- **Tokenizer**: PG2 uses SentencePiece + Meta's adversarial-tokenization hardening — the
  existing `Tokenizer.fromFile(tokenizer.json)` path works; keep `MAX_LENGTH` (PG2 handles 512).
- **token_type_ids**: mDeBERTa may not need them — the loader already branches on
  `session.inputNames`, so this is handled.
- **A model-select seam**: add `SOVGUARD_CLASSIFIER_MODEL=deberta-v1|prompt-guard-2` (or infer
  from model dir) so we can A/B without ripping out v1 — keep v1 as a fallback.
- **Fusion re-tune (the hard part)**: the veto's `BENIGN_CORPUS`/`ATTACK_CORPUS`,
  `SEMANTIC_CORROBORATE=0.6`, `SEMANTIC_VETO_BENIGN_FLOOR=0.45`, and the `classifierScore>0.5`
  gate were all tuned to v1's score distribution. PG2 has different calibration and (by design)
  far fewer trigger-word FPs, so the arbitration may need loosening (PG2 is trustworthy enough
  it may not need the semantic veto as a crutch). Re-derive these against the eval after the swap.

---

## Phased plan (each phase is a decision gate)

### Phase 0 — License decision (BLOCKING, non-engineering)
- [ ] Legal/owner sign-off on the **Llama 4 Community License** for PG2-86M (attribution +
  AUP; we're under 700M MAU). If **rejected → skip PG2, go straight to the fine-tune hedge
  (Phase 3)**. If accepted → Phase 1. Do not integrate PG2 weights before this.

### Phase 1 — Obtain + integrate PG2-86M behind a flag (no behavior change by default)
- [ ] Get a trustworthy ONNX export: prefer exporting from `meta-llama/Llama-Prompt-Guard-2-86M`
  ourselves via `optimum` (fp32) for provenance; the community `gravitee-io/...onnx` mirror is a
  cross-check. **Do NOT use the gravitee dynamic-int8 quant** (accuracy 0.98→0.90); if we want
  int8, do our own QAT and validate.
- [ ] Vendor model + tokenizer under `models/prompt-guard-2-86m/`; add pinned download + sha256
  to `scripts/download-model.sh`; gitignore the weights (as today).
- [ ] Add the model-select seam in `classifier-local.ts` (env or dir-based); verify PG2's
  malicious-class index empirically on 3 known attacks + 3 benign; keep v1 as default.
- [ ] Unit test: model-less path unchanged; with PG2 present, `localClassifierScan` returns a
  sane score on a known injection. `npm test` green both repos.

### Phase 2 — A/B eval on OUR benchmarks (the real test)
- [ ] With PG2 active, run: `npm run eval` (held-out 42/33), `npm run eval:public`
  (NotInject 339 + deepset 662), and `pentest/eval/diagnose.ts`. Capture per-layer attribution.
- [ ] Build a **multilingual attack mini-set** to test the actual selling point: translate ~20
  held-out injections into DE/FR/ES/ZH/RU (the languages PG2 claims) + keep our RU held-out
  item. Measure catch on these — this is where PG2 should beat v1.
- [ ] Compare PG2 vs v1 on: NotInject FP (target: well below 47%), NotInject false-block
  (target: below 12%), held-out catch (target: keep 100% incl. the RU attack v1+exp3 missed),
  held-out false-block (must stay 0%), deepset recall (should rise from 36%).
- **Decision gate:** PG2 ships only if it *strictly dominates or trades favorably* — i.e.
  materially lower FP AND held-out catch ≥ current 100% AND false-block still 0%. Per the
  research, treat PG2's vendor numbers as unproven until measured here (indirect-attack recall
  is poor across all small classifiers — 7-37%; our indirect layer + spotlighting still carry that).

### Phase 3 — Fine-tune hedge (do IF Phase 0 rejected the license, OR Phase 2 shows PG2
underperforms our own benign data)
- [ ] Base `mDeBERTa-v3-base` (MIT). Data: deepset + JasperLS + jackhhao + JailbreakBench +
  wildjailbreak + **NotInject-style trigger-word hard-negatives** + our logged benign prompts;
  machine-translate injection sets into target languages (translation quality = main risk).
- [ ] Train with PIGuard's **MOF / energy loss** (MIT recipe — lifted NotInject 57%→87% in the
  paper). Export to ONNX via `optimum`. Then run the same Phase 2 A/B.
- **Decision gate:** ship our model only if it beats both v1 and (if licensed) PG2 on our suite.

### Phase 4 — Re-tune fusion for the winning model + ship
- [ ] Re-derive the arbitration constants in `src/scanner/index.ts` for the new score
  distribution (the veto may be loosened or partly retired if the new model's precision makes it
  unnecessary). Re-run the full suite; confirm no regression.
- [ ] Port to BOTH repos (SDK + website — shared scanner code), re-run both suites + the eval,
  update `BENCHMARKS.md` with the new honest numbers, and update README/site claims.
- [ ] Keep v1 as a config-selectable fallback for one release. Ship to main; redeploy the
  container (models are mounted read-only — the new model dir must be added to the mount + image).

### Phase 5 (parallel, optional) — the indirect-injection gap
- [ ] No small classifier (PG2 included) catches indirect/agentic tool-output injection well
  (7-37%). If that surface matters, add an **LLM-judge escalation** (LlamaFirewall AlignmentCheck
  style) as a second stage on suspicious/agent-context scans — out of scope for the classifier
  swap, tracked separately.

---

## Risks / honest caveats
- **Every vendor number here is in-distribution.** The 2026 "When Benchmarks Lie" study
  (arxiv 2602.14161) shows ~8pp AUC inflation under distribution shift and poor indirect-attack
  recall across PG2/LlamaGuard/judges. **Nothing ships without passing OUR held-out + NotInject.**
- **A model swap moves ALL numbers** — it invalidates the current fusion tuning and the published
  benchmark; budget a full re-eval + re-tune + BENCHMARKS.md rewrite, not a drop-in.
- **License**: PG2 is Llama-community-licensed, not MIT/Apache. Get sign-off first (Phase 0).
- **Quantization**: don't trust the int8 mirror; validate any quant on our set.
- **Multilingual claim is vendor-evaluated** (aggregate AUC only, no per-language breakdown) —
  our translated-attack mini-set (Phase 2) is how we verify it for real.

## Sources
meta-llama/Llama-Prompt-Guard-2-86M · PurpleLlama MODEL_CARD · gravitee-io ONNX mirror ·
leolee99/PIGuard + arxiv 2410.22770 (MOF/NotInject) · arxiv 2602.14161 (independent 2026 bench) ·
MoritzLaurer/mDeBERTa-v3-base (fine-tune base). Full URLs in the 2026-07-11 research memo.
