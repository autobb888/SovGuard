# SovGuard Classifier Training Runbook (MIT fine-tune path)

> **When to run this:** NOT for launch. The product ships today on the current Apache-2.0
> classifier — this is the "raise the ceiling" project for when you have GPU budget and
> breathing room. Decision made 2026-07-11: go the **MIT fine-tune** route (own weights,
> clean license) rather than adopt Llama Prompt Guard 2 (Llama-community license), to stay
> unencumbered while launching solo without legal.

## Why (the diagnosis, recap)
The current English `protectai/deberta-v3-base-prompt-injection` (Apache-2.0) is
precision-limited: it false-fires on benign trigger-word and non-English prompts (drove ~75%
of our NotInject false-positives, especially Chinese/Cyrillic) and under-fires on mild/novel
injections. Threshold/veto tuning has a hard ceiling (we got NotInject FP 51%→47% safely and
stopped). The only way past it is a better — specifically **multilingual, low-over-defense** —
classifier. Since no MIT-licensed multilingual injection model exists off the shelf, we train one.

## Goal
An MIT-clean, multilingual (SovGuard's ~12 languages: EN/DE/ES/FR/PT/IT/ZH/JA/KO/AR/RU/HI/TR),
binary benign/malicious injection classifier that, on OUR benchmarks, has **lower false-positives
than v1 while keeping held-out catch at 100% and false-block at 0%**.

## Hardware (this is a GPU job — NOT the bigbox host)
The dev box has **no GPU** and OOMs on inference. Train elsewhere:
- **Cheapest:** Google Colab (T4/L4 free-ish) or a spot A10/A100 on Lambda/RunPod/Vast — a
  278M mDeBERTa fine-tune is **a few hours on one mid GPU, ~$5–50 spot / ~$50–300 on-demand**.
- ~12GB VRAM at batch 16 / seq 512 fp16 (gradient-checkpointing if tight). CPU-only training is
  impractical (days–weeks) — don't.

## Base model (MIT/permissive)
- **`microsoft/mDeBERTa-v3-base`** — 12L/768h, pretrained on CC100 (100+ languages), **MIT**.
  First choice (best multilingual + the same DeBERTa family we already run in ONNX).
- Fallback: `xlm-roberta-base` (MIT). Both export to ONNX cleanly via `optimum`.

## Data assembly (THE REAL WORK — model training is the easy part)
Build a labeled binary corpus (`malicious=1` / `benign=0`). Sources:
- **Malicious (injection + jailbreak):** `deepset/prompt-injections`, `JasperLS/prompt-injections`,
  `jackhhao/jailbreak-classifier` data, **JailbreakBench (JBB-Behaviors)**, `allenai/wildjailbreak`,
  `SafeMTData`. Plus our own `pentest/eval/adversarial.json` (attack side).
- **Benign — general:** instruction/chat prompts (`tatsu-lab/alpaca`, `databricks/dolly-15k`,
  `OpenAssistant/oasst1` user turns), plus everyday requests. This teaches "normal traffic."
- **Benign — HARD NEGATIVES (the over-defense fix):** trigger-word-laden benign prompts. Generate
  a few thousand in the style of NotInject (benign prompts containing "ignore/uncensored/act as/
  developer mode/system/bypass" in innocent contexts) — the PIGuard paper shows these are what
  lift NotInject over-defense from ~57% to ~87%. **Do NOT put the actual NotInject set in TRAIN**
  (it's our honest eval set — see splits).
- **Our own logged benign prompts** (once we have production traffic) — the highest-value
  domain-specific hard negatives.
- **Multilingual:** machine-translate the English malicious + benign + hard-negative sets into the
  target languages with **NLLB-200** (`facebook/nllb-200-distilled-600M`, CC-BY-NC — fine for
  generating TRAINING DATA; the resulting weights aren't a derivative) or a translation API.
  **Translation quality is the #1 risk** — spot-check, and prefer native-sourced multilingual
  benign/attack where available.

### Splits (protects honest evaluation)
- **TEST (never trained on):** our held-out `pentest/eval/` (42/33), the full **NotInject** (339),
  and a held-out slice of deepset. These stay the honest yardstick — training on them would make
  `BENCHMARKS.md` a lie.
- **VAL:** a stratified slice (incl. some trigger-word hard negatives + non-English) for early stopping.
- **TRAIN:** everything else, class-balanced (or loss-weighted).

## Training recipe
- Standard `AutoModelForSequenceClassification`, `num_labels=2`, seq 512.
- **PIGuard "MOF" (Mitigating Over-defense for Free) idea** (MIT, arxiv 2410.22770): augment the
  loss so hard-negative benign (trigger-word) examples are explicitly pushed toward the benign
  class — an auxiliary term / heavier weight on the hard-negative bucket. This is the lever that
  buys low over-defense without killing recall. (Start simple: oversample + higher loss weight on
  hard negatives; add the energy-loss refinement if needed.)
- Hyperparams to start: lr 2e-5, batch 16–32, 3–5 epochs, warmup 0.06, weight decay 0.01, fp16,
  early-stop on VAL over-defense + recall jointly (not accuracy alone — accuracy hides the tradeoff).
- Watch **both** VAL curves: malicious recall AND benign-hard-negative FP. Stop where FP is low
  and recall ≥ v1.

### Turnkey script skeleton (`train.py`, runs on the GPU box)
```python
# pip install "transformers>=4.44" datasets accelerate evaluate optimum[onnxruntime] scikit-learn
from transformers import (AutoTokenizer, AutoModelForSequenceClassification,
                          TrainingArguments, Trainer, DataCollatorWithPadding)
from datasets import load_dataset  # or load your assembled JSONL: {"text","label"}
import numpy as np, evaluate

BASE = "microsoft/mdeberta-v3-base"
tok = AutoTokenizer.from_pretrained(BASE)
ds = load_dataset("json", data_files={"train":"train.jsonl","val":"val.jsonl"})
def prep(b): return tok(b["text"], truncation=True, max_length=512)
ds = ds.map(prep, batched=True)

model = AutoModelForSequenceClassification.from_pretrained(BASE, num_labels=2)
# MOF-lite: pass class/sample weights via a custom Trainer.compute_loss that up-weights
# hard-negative benign rows (add a "is_hard_neg" column and scale their loss ~2-3x).

f1 = evaluate.load("f1")
def metrics(p):
    pred = np.argmax(p.predictions, axis=1)
    return {"f1": f1.compute(predictions=pred, references=p.label_ids)["f1"]}

args = TrainingArguments(output_dir="out", learning_rate=2e-5, per_device_train_batch_size=16,
    num_train_epochs=4, fp16=True, eval_strategy="epoch", save_strategy="epoch",
    load_best_model_at_end=True, metric_for_best_model="f1", warmup_ratio=0.06, weight_decay=0.01)
Trainer(model, args, train_dataset=ds["train"], eval_dataset=ds["val"],
        tokenizer=tok, data_collator=DataCollatorWithPadding(tok),
        compute_metrics=metrics).train()
model.save_pretrained("out/best"); tok.save_pretrained("out/best")
```

## Export to ONNX (so it drops into our runtime)
```bash
optimum-cli export onnx --model out/best --task text-classification models/sovguard-injection-ml/
# produces model.onnx + tokenizer.json — the exact files classifier-local.ts loads
```
Validate parity: run a few known attacks/benign through both the HF model and the ONNX to confirm
identical scores. Do NOT ship an int8 quant without validating (PG2's int8 dropped 0.98→0.90).

## Integration (small — see classifier-local.ts)
- Drop the ONNX + tokenizer into a new `models/sovguard-injection-ml/` dir; add pinned download +
  sha256 to `scripts/download-model.sh`; keep weights gitignored.
- Add a model-select seam (`SOVGUARD_CLASSIFIER_MODEL`) so v1 stays as a fallback for one release.
- Verify the malicious-class output index empirically (don't assume `[safe, injection]`).

## Evaluate + decide (use our existing infra)
Run against the TEST sets that were never trained on:
- `npm run eval` (held-out 42/33) — **catch must stay 100%, false-block 0%** (incl. the RU attack v1 missed).
- `npm run eval:public` (NotInject 339 + deepset 662) — NotInject FP must drop well below 47%; deepset recall should rise from 36%.
- `pentest/eval/diagnose.ts` — confirm the classifier is no longer the top FP driver.
- A translated-attack mini-set (DE/FR/ES/ZH/RU) — the multilingual payoff.
- **Ship only if it strictly beats v1 on our suite.** Then re-tune the fusion/veto in
  `src/scanner/index.ts` for the new score distribution (the veto may be loosened/retired if the
  new model's precision makes it unnecessary), port to BOTH repos, rewrite `BENCHMARKS.md` with the
  new honest numbers, and update README/site claims.

## Risks / honest caveats
- **Translation quality** is the main data risk — bad MT poisons the multilingual signal.
- **Don't train on NotInject / held-out** — keep them as honest TEST or the benchmark becomes theater.
- **In-distribution ≠ real** — validate on our sets + adversarial spot-checks; the 2026 "When
  Benchmarks Lie" study (arxiv 2602.14161) shows guardrail AUC inflates ~8pp under distribution shift.
- **Indirect/agentic tool-output injection stays hard** — no small classifier (ours or PG2) catches
  it well (7–37%); our indirect-heuristic layer + spotlighting still carry that surface. An LLM-judge
  escalation is the separate long-term answer there.
- **Effort is front-loaded on data, not compute** — budget most of the time for corpus assembly +
  translation QA, not the ~few-hour train.

## Sources
mDeBERTa-v3-base (MIT) · PIGuard/InjecGuard MOF recipe (leolee99/PIGuard, arxiv 2410.22770) ·
NLLB-200 for translation · optimum ONNX export · JailbreakBench / wildjailbreak / deepset datasets ·
independent bench arxiv 2602.14161. Full URLs in the 2026-07-11 research memo and the model-upgrade plan.
