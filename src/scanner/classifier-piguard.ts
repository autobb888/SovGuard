/**
 * DL-011d D1 — PIGuard secondary classifier layer.
 *
 * Orthogonal head under mode=untrusted_content only. Never sole-block
 * (emit band 0.30–0.45). No chat-path inference. Does not replace DeBERTa.
 * Does not wire CLF_ESCALATE. Dual-agree block is out of v1.
 *
 * Weights: unofficial ONNX export of leolee99/PIGuard
 *   models/piguard-onnx/model.onnx
 *   sha256 5888eb0f407e06efc4aa53c715ccf869cf597c6c8687bfcd220f5e57ed749e80
 * Tokenizer: official HF tokenizer.json with Metaspace prepend_scheme/split
 * downgraded for the Node tokenizers crate (tokenizer.compat.json).
 */

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { LayerResult } from '../types.js';
import type { ScanMode } from './scan-mode.js';
import { inferenceGate } from './inference-gate.js';

export const LAYER_NAME = 'classifier_piguard' as const;
export const TAU_PG = 0.5;
export const EMIT_MIN = 0.30;
export const EMIT_MAX = 0.45;
export const EXPECTED_MODEL_SHA256 =
  '5888eb0f407e06efc4aa53c715ccf869cf597c6c8687bfcd220f5e57ed749e80';

export interface PiguardScanOpts {
  mode: ScanMode | string;
  /** ProtectAI / primary classifier score. */
  pa?: number;
  /** True when retrieval_dual_margin fired this scan. */
  retrievalHit?: boolean;
  /** Same light PI cue as S3 (regex/indirect/unicode/otherMax≥0.15). */
  lightPiCue?: boolean;
  /** Semantic attackSim (layer score or details.attackSim). */
  attackSim?: number;
  /** Injectable score (unit tests). */
  scoreFn?: (text: string) => Promise<number>;
  /** Injectable availability (unit tests). undefined = probe disk. */
  available?: boolean;
}

let ort: any = null;
let session: any = null;
let tokenizer: any = null;
let modelLoaded = false;
let loadError: string | null = null;

function piguardDir(): string {
  return process.env.SOVGUARD_PIGUARD_DIR || join(process.cwd(), 'models', 'piguard-onnx');
}

function sha256File(path: string): string | null {
  if (!existsSync(path)) return null;
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function downgradeMetaspace(obj: any): void {
  if (!obj || typeof obj !== 'object') return;
  if (obj.type === 'Metaspace') {
    const add = obj.prepend_scheme === 'always' || obj.add_prefix_space !== false;
    obj.replacement = obj.replacement || '▁';
    obj.add_prefix_space = add;
    delete obj.prepend_scheme;
    delete obj.split;
    return;
  }
  if (Array.isArray(obj)) obj.forEach(downgradeMetaspace);
  else Object.values(obj).forEach(downgradeMetaspace);
}


/**
 * Docker models volume is :ro. Never write into PIGUARD_DIR.
 * Prefer in-memory JSON (Tokenizer.fromString). Reuse a readable
 * tokenizer.compat.json if already present. tmpdir write is fallback only.
 */
export type CompatSource =
  | { kind: 'file'; path: string }
  | { kind: 'json'; json: string };

export function resolveCompatTokenizer(
  dir: string,
  io: {
    existsSync?: typeof existsSync;
    readFileSync?: typeof readFileSync;
  } = {},
): CompatSource {
  const exists = io.existsSync ?? existsSync;
  const read = io.readFileSync ?? readFileSync;
  const existing = join(dir, 'tokenizer.compat.json');
  if (exists(existing)) return { kind: 'file', path: existing };

  const official = exists(join(dir, 'tokenizer.official.json'))
    ? join(dir, 'tokenizer.official.json')
    : join(dir, 'tokenizer.json');
  const raw = JSON.parse(read(official, 'utf8'));
  downgradeMetaspace(raw);
  return { kind: 'json', json: JSON.stringify(raw) };
}

/** @deprecated D1.10 prefers resolveCompatTokenizer + fromString (no write). */
export function prepareCompatTokenizer(
  dir: string,
  io: {
    existsSync?: typeof existsSync;
    readFileSync?: typeof readFileSync;
    writeFileSync?: typeof writeFileSync;
    tmpdir?: () => string;
  } = {},
): { path: string | null; json?: string; wrote: boolean } {
  const src = resolveCompatTokenizer(dir, io);
  if (src.kind === 'file') return { path: src.path, wrote: false };
  return { path: null, json: src.json, wrote: false };
}

async function ensureModel(): Promise<boolean> {
  if (modelLoaded) return true;
  if (loadError) return false;

  const dir = piguardDir();
  const modelPath = join(dir, 'model.onnx');
  const tokOfficial = existsSync(join(dir, 'tokenizer.official.json'))
    ? join(dir, 'tokenizer.official.json')
    : join(dir, 'tokenizer.json');
  if (!existsSync(modelPath) || !existsSync(tokOfficial)) {
    loadError = `PIGuard ONNX missing at ${dir}`;
    return false;
  }

  try {
    const src = resolveCompatTokenizer(dir);

    ort = await (Function('return import("onnxruntime-node")')() as Promise<any>);
    const tokenizersModule = await (Function('return import("tokenizers")')() as Promise<any>);
    if (src.kind === 'file') {
      tokenizer = await tokenizersModule.Tokenizer.fromFile(src.path);
    } else {
      try {
        tokenizer = tokenizersModule.Tokenizer.fromString(src.json);
      } catch {
        const sha = createHash('sha256').update(src.json).digest('hex').slice(0, 16);
        const dest = join(
          process.env.SOVGUARD_PIGUARD_TMP || tmpdir(),
          `sovguard-piguard-${sha}.compat.json`,
        );
        if (!existsSync(dest)) writeFileSync(dest, src.json);
        tokenizer = await tokenizersModule.Tokenizer.fromFile(dest);
      }
    }
    tokenizer.setTruncation(512);
    tokenizer.setPadding(null);
    session = await ort.InferenceSession.create(modelPath);
    modelLoaded = true;
    console.log(
      `[classifier-piguard] PIGuard ONNX loaded (${Math.round(statSync(modelPath).size / 1024 / 1024)}MB)`,
    );
    return true;
  } catch (err) {
    loadError = err instanceof Error ? err.message : 'Unknown error loading PIGuard ONNX';
    console.error('[classifier-piguard] Failed to load model:', loadError);
    return false;
  }
}

function softmax(logits: Float32Array): number[] {
  const max = Math.max(...logits);
  const exps = Array.from(logits).map((l) => Math.exp(l - max));
  const sum = exps.reduce((a, b) => a + b, 0);
  return exps.map((e) => e / sum);
}

async function inferPg(text: string): Promise<number> {
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
  const results = await inferenceGate.run<any>(() => session.run(feeds));
  const outName = session.outputNames[0];
  const logits = results[outName].data as Float32Array;
  const probs = softmax(logits);
  return probs[1] ?? 0;
}

/** Map PG score into the corroboration emit band [0.30, 0.45]. */
export function scoreFromPg(pg: number, tau = TAU_PG): number {
  if (pg < tau) return 0;
  const strength = Math.min(1, (pg - tau) / Math.max(1 - tau, 1e-9));
  return EMIT_MIN + (EMIT_MAX - EMIT_MIN) * strength;
}

export function evaluatePiguardFire(opts: {
  pg: number;
  pa?: number;
  retrievalHit?: boolean;
  lightPiCue?: boolean;
  attackSim?: number;
  tau?: number;
}): boolean {
  if (opts.pg < (opts.tau ?? TAU_PG)) return false;
  return (
    (opts.pa ?? 0) >= 0.15 ||
    !!opts.retrievalHit ||
    !!opts.lightPiCue ||
    (opts.attackSim ?? 0) >= 0.15
  );
}

/** Test helper: drop loaded session between tests. */
export function resetPiguardCache(): void {
  ort = null;
  session = null;
  tokenizer = null;
  modelLoaded = false;
  loadError = null;
}

export function isPiguardModelAvailable(): boolean {
  const dir = piguardDir();
  return existsSync(join(dir, 'model.onnx')) && (
    existsSync(join(dir, 'tokenizer.official.json')) || existsSync(join(dir, 'tokenizer.json'))
  );
}

export function piguardModelSha256(): string | null {
  return sha256File(join(piguardDir(), 'model.onnx'));
}

export async function piguardScan(text: string, opts: PiguardScanOpts): Promise<LayerResult> {
  if (opts.mode !== 'untrusted_content') {
    return {
      layer: LAYER_NAME,
      score: 0,
      flags: [],
      details: { skipped: true, reason: 'mode', mode: opts.mode },
    };
  }

  const available = opts.available ?? (opts.scoreFn ? true : isPiguardModelAvailable());
  if (!available) {
    return {
      layer: LAYER_NAME,
      score: 0,
      flags: [],
      details: { skipped: true, reason: 'model_missing' },
    };
  }

  let pg: number;
  try {
    if (opts.scoreFn) {
      pg = await opts.scoreFn(text);
    } else {
      const ready = await ensureModel();
      if (!ready) {
        return {
          layer: LAYER_NAME,
          score: 0,
          flags: [],
          details: { skipped: true, reason: 'model_missing', message: loadError },
        };
      }
      pg = await inferPg(text);
    }
  } catch (err) {
    return {
      layer: LAYER_NAME,
      score: 0,
      flags: [],
      details: {
        skipped: true,
        reason: 'infer_error',
        error: err instanceof Error ? err.message : 'infer failed',
      },
    };
  }

  const fire = evaluatePiguardFire({
    pg,
    pa: opts.pa,
    retrievalHit: opts.retrievalHit,
    lightPiCue: opts.lightPiCue,
    attackSim: opts.attackSim,
  });
  const score = fire ? scoreFromPg(pg) : 0;

  return {
    layer: LAYER_NAME,
    score,
    flags: fire ? [LAYER_NAME] : [],
    details: {
      available: true,
      provider: 'piguard-onnx',
      official: 'leolee99/PIGuard',
      pg,
      tau: TAU_PG,
      fire,
      cue: {
        pa: opts.pa ?? 0,
        retrievalHit: !!opts.retrievalHit,
        lightPiCue: !!opts.lightPiCue,
        attackSim: opts.attackSim ?? 0,
      },
    },
  };
}
