/**
 * DL-011d D0 — offline ProtectAI ↔ PIGuard disagreement harness.
 *
 * Measure-only. Does NOT wire into scan() / combineScores / CLF_ESCALATE.
 *
 * Usage (repo root, models present):
 *   npx tsx scripts/d0-piguard-disagreement.ts
 *
 * Writes: docs/private/2026-09-12-d0-piguard-disagreement.json (gitignored)
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { localClassifierScan } from '../src/scanner/classifier-local.js';

const ROOT = process.cwd();
const TAU_PA = 0.15; // "PA miss" ≈ flat / no real signal
const TAU_PA_BLOCK = 0.7;
const TAU_PG = Number(process.env.SOVGUARD_D0_TAU_PG || 0.5);
const PIGUARD_DIR = process.env.SOVGUARD_PIGUARD_DIR || join(ROOT, 'models', 'piguard-onnx');
const OUT = process.env.SOVGUARD_D0_OUT || join(ROOT, 'docs', 'private', '2026-09-12-d0-piguard-disagreement.json');

interface Fixture {
  id: string;
  text: string;
  class?: string;
  label?: string;
}

function sha256File(path: string): string | null {
  if (!existsSync(path)) return null;
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function loadJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, 'utf8')) as T;
}

function loadPacks(): { fixtures: Fixture[]; holdoutIds: Set<string> } {
  const untrusted = loadJson<{ fixtures: Fixture[] }>(join(ROOT, 'pentest/payloads/dl011c-mode-untrusted.json'));
  const chat = loadJson<{ fixtures: Fixture[] }>(join(ROOT, 'pentest/payloads/dl011c-mode-chat.json'));
  const split = loadJson<{ holdoutIds: string[] }>(join(ROOT, 'data/retrieval/s3-v1a-split.json'));
  const fixtures: Fixture[] = [];
  const seen = new Set<string>();
  for (const f of [...untrusted.fixtures, ...chat.fixtures]) {
    if (seen.has(f.id)) continue;
    seen.add(f.id);
    fixtures.push({ id: f.id, text: f.text, class: f.class, label: f.label });
  }
  return { fixtures, holdoutIds: new Set(split.holdoutIds) };
}

function softmax(logits: Float32Array): number[] {
  const max = Math.max(...logits);
  const exps = Array.from(logits).map((l) => Math.exp(l - max));
  const sum = exps.reduce((a, b) => a + b, 0);
  return exps.map((e) => e / sum);
}

async function loadPiguard(): Promise<{
  embed: (text: string) => Promise<{ score: number; ms: number }>;
  meta: Record<string, unknown>;
}> {
  const modelPath = join(PIGUARD_DIR, 'model.onnx');
  const tokOfficial = existsSync(join(PIGUARD_DIR, 'tokenizer.official.json'))
    ? join(PIGUARD_DIR, 'tokenizer.official.json')
    : join(PIGUARD_DIR, 'tokenizer.json');
  if (!existsSync(modelPath) || !existsSync(tokOfficial)) {
    throw new Error(`PIGuard ONNX missing at ${PIGUARD_DIR}. Run scripts/download-piguard-onnx.sh`);
  }
  // Node tokenizers crate is older than HF Metaspace prepend_scheme/split.
  const tokCompat = join(PIGUARD_DIR, 'tokenizer.compat.json');
  const raw = JSON.parse(readFileSync(tokOfficial, 'utf8')) as any;
  const walk = (obj: any) => {
    if (!obj || typeof obj !== 'object') return;
    if (obj.type === 'Metaspace') {
      const add = obj.prepend_scheme === 'always' || obj.add_prefix_space !== false;
      obj.type = 'Metaspace';
      obj.replacement = obj.replacement || '▁';
      obj.add_prefix_space = add;
      delete obj.prepend_scheme;
      delete obj.split;
      return;
    }
    if (Array.isArray(obj)) obj.forEach(walk);
    else Object.values(obj).forEach(walk);
  };
  walk(raw);
  writeFileSync(tokCompat, JSON.stringify(raw));
  const ort = await (Function('return import("onnxruntime-node")')() as Promise<any>);
  const tokenizersModule = await (Function('return import("tokenizers")')() as Promise<any>);
  const tokenizer = await tokenizersModule.Tokenizer.fromFile(tokCompat);
  tokenizer.setTruncation(512);
  const session = await ort.InferenceSession.create(modelPath);
  return {
    meta: {
      path: PIGUARD_DIR,
      source: 'ahmedomuharram/piguard-onnx (export of leolee99/PIGuard)',
      official: 'https://huggingface.co/leolee99/PIGuard',
      modelSha256: sha256File(modelPath),
      tokenizerOfficialSha256: sha256File(tokOfficial),
      tokenizerCompatSha256: sha256File(tokCompat),
      tokenizerNote: 'compat = official with Metaspace prepend_scheme/split downgraded for tokenizers crate',
      modelBytes: statSync(modelPath).size,
      inputNames: session.inputNames,
      outputNames: session.outputNames,
    },
    embed: async (text: string) => {
      const t0 = Date.now();
      const encoded = await tokenizer.encode(text);
      let ids: number[] = encoded.getIds();
      let mask: number[] = encoded.getAttentionMask();
      if (ids.length > 512) {
        ids = ids.slice(0, 512);
        mask = mask.slice(0, 512);
      }
      const feeds: Record<string, unknown> = {
        input_ids: new ort.Tensor('int64', BigInt64Array.from(ids.map((n) => BigInt(n))), [1, ids.length]),
        attention_mask: new ort.Tensor('int64', BigInt64Array.from(mask.map((n) => BigInt(n))), [1, mask.length]),
      };
      if (session.inputNames.includes('token_type_ids')) {
        feeds.token_type_ids = new ort.Tensor('int64', new BigInt64Array(ids.length).fill(0n), [1, ids.length]);
      }
      const results = await session.run(feeds);
      const outName = session.outputNames[0];
      const logits = results[outName].data as Float32Array;
      const probs = softmax(logits);
      return { score: probs[1] ?? 0, ms: Date.now() - t0 };
    },
  };
}

function packOf(id: string, holdout: Set<string>): string {
  if (id.startsWith('notinject-')) return 'nib41';
  if (holdout.has(id)) return 'holdout28';
  return 'flat94';
}

async function main() {
  const { fixtures, holdoutIds } = loadPacks();
  const pg = await loadPiguard();
  const rows: Array<Record<string, unknown>> = [];
  let paMs = 0;
  let pgMs = 0;

  for (const f of fixtures) {
    const t0 = Date.now();
    const pa = await localClassifierScan(f.text);
    const paElapsed = Date.now() - t0;
    paMs += paElapsed;
    const pgR = await pg.embed(f.text);
    pgMs += pgR.ms;
    const pack = packOf(f.id, holdoutIds);
    rows.push({
      id: f.id,
      pack,
      class: f.class ?? null,
      label: f.label ?? (pack === 'nib41' ? 'benign' : 'attack'),
      score_pa: pa.score,
      score_pg: pgR.score,
      pa_ms: paElapsed,
      pg_ms: pgR.ms,
      pa_miss: pa.score < TAU_PA,
      pg_hit: pgR.score >= TAU_PG,
      pa_block: pa.score >= TAU_PA_BLOCK,
      pg_block: pgR.score >= TAU_PA_BLOCK,
    });
    if (rows.length % 20 === 0) console.log(`[d0] scored ${rows.length}/${fixtures.length}`);
  }

  const flats = rows.filter((r) => r.pack === 'flat94' || r.pack === 'holdout28');
  // unique flats: holdout is subset — use id-unique 94
  const byId = new Map<string, (typeof rows)[0]>();
  for (const r of rows) {
    if (String(r.id).startsWith('deepset-')) byId.set(String(r.id), r);
  }
  const uniqueFlats = [...byId.values()];
  const holdout = rows.filter((r) => r.pack === 'holdout28');
  const nib = rows.filter((r) => r.pack === 'nib41');

  const paMissFlats = uniqueFlats.filter((r) => r.pa_miss);
  const uniqueLift = paMissFlats.filter((r) => r.pg_hit);
  const bothHit = uniqueFlats.filter((r) => !r.pa_miss && r.pg_hit);
  const holdoutLift = holdout.filter((r) => r.pa_miss && r.pg_hit);
  const nibPaBlock = nib.filter((r) => r.pa_block);
  const nibPgBlock = nib.filter((r) => r.pg_block);
  const nibPgFlag = nib.filter((r) => r.pg_hit);

  const uniqueLiftPct = paMissFlats.length ? (100 * uniqueLift.length) / paMissFlats.length : 0;
  const goUnique = uniqueLiftPct >= 15;
  const noGoUnique = uniqueLiftPct < 5;
  const goNib = nibPgBlock.length <= nibPaBlock.length;

  const summary = {
    n_total: rows.length,
    n_flat94: uniqueFlats.length,
    n_holdout28: holdout.length,
    n_nib41: nib.length,
    tau_pa_miss: TAU_PA,
    tau_pg: TAU_PG,
    tau_block: TAU_PA_BLOCK,
    pa_miss_flats: paMissFlats.length,
    pg_unique_hits_on_pa_miss: uniqueLift.length,
    unique_lift_pct_of_pa_miss: +uniqueLiftPct.toFixed(1),
    unique_lift_ids: uniqueLift.map((r) => r.id),
    both_hit_flats: bothHit.length,
    holdout_pa_miss: holdout.filter((r) => r.pa_miss).length,
    holdout_pg_unique: holdoutLift.length,
    holdout_unique_ids: holdoutLift.map((r) => r.id),
    nib_pa_false_block: nibPaBlock.length,
    nib_pg_false_block: nibPgBlock.length,
    nib_pg_false_flag_tau: nibPgFlag.length,
    latency: {
      pa_ms_mean: +(paMs / rows.length).toFixed(1),
      pg_ms_mean: +(pgMs / rows.length).toFixed(1),
      pa_ms_total: paMs,
      pg_ms_total: pgMs,
    },
    d0_exit: {
      unique_lift: goUnique ? 'GO' : noGoUnique ? 'NO-GO' : 'BORDERLINE',
      nib_false_block: goNib ? 'GO' : 'NO-GO',
      note: 'Go if unique lift ≥15–20% of PA-miss flats AND NI-B PG false_block ≤ PA',
    },
  };

  const artifact = {
    generatedAt: new Date().toISOString(),
    baseTip: 'faf3c7c',
    slice: 'D0',
    product_scan_combine: false,
    protectai: {
      path: 'models/deberta-v3-prompt-injection',
      model: 'deberta-v3-base-prompt-injection-v2',
      via: 'localClassifierScan',
    },
    piguard: pg.meta,
    summary,
    rows,
  };

  mkdirSync(join(ROOT, 'docs', 'private'), { recursive: true });
  writeFileSync(OUT, JSON.stringify(artifact, null, 2));
  console.log(JSON.stringify(summary, null, 2));
  console.log(`[d0] wrote ${OUT}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
