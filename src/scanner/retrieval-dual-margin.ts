/**
 * DL-011 S3-v1a — Retrieval dual-margin layer.
 *
 * Non-parametric near-neighbor signal: fire when the query embedding is close
 * to the frozen AttackIndex AND far from the BenignIndex, under
 * mode=untrusted_content only, and only with a light PI corroboration cue.
 * Emit band 0.30–0.45 — never sole-block (blockThreshold is 0.7).
 *
 * Does NOT replace semantic.ts phrase corpora. Does NOT wire CLF_ESCALATE.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { LayerResult } from '../types.js';
import type { ScanMode } from './scan-mode.js';
import { cosineSim, embedText } from './semantic.js';

/** Train-tuned defaults (also stored in index JSON). τ_atk=0.40 ⇒ sim≥0.60; τ_ben=0.15. */
export const TAU_ATK = 0.40;
export const TAU_BEN = 0.15;

export const LAYER_NAME = 'retrieval_dual_margin' as const;

export interface RetrievalIndexEntry {
  id: string;
  class?: string;
  text?: string;
  /** L2-normalized 384-d MiniLM vector; null/omitted until build script fills. */
  vector?: number[] | null;
}

export interface RetrievalIndex {
  version?: string;
  dim?: number;
  tauAtk?: number;
  tauBen?: number;
  checksum?: string | null;
  entries: RetrievalIndexEntry[];
}

export interface DualMarginHit {
  retrievalHit: boolean;
  dAtk: number;
  dBen: number;
  nearestAtkId: string | null;
  nearestBenId: string | null;
  tauAtk: number;
  tauBen: number;
}

export interface EvaluateDualMarginOpts {
  attackIndex: RetrievalIndexEntry[];
  benignIndex: RetrievalIndexEntry[];
  tauAtk?: number;
  tauBen?: number;
}

export interface RetrievalDualMarginScanOpts {
  mode: ScanMode | string;
  /** Max score of other non-classifier / non-this layers. */
  otherMax: number;
  /** Explicit light PI cue (regex/indirect/unicode/boundary/decomp/delayed or otherMax≥0.15). */
  lightPiCue?: boolean;
  /** Injectable embed (tests); defaults to semantic.embedText. */
  embedFn?: (text: string) => Promise<Float32Array | null>;
  /** Injectable indexes (tests); defaults to frozen files on disk. */
  attackIndex?: RetrievalIndexEntry[];
  benignIndex?: RetrievalIndexEntry[];
  tauAtk?: number;
  tauBen?: number;
}

let cachedAttack: RetrievalIndexEntry[] | null = null;
let cachedBenign: RetrievalIndexEntry[] | null = null;
let indexesLoadAttempted = false;
let indexesAvailable = false;

function retrievalDir(): string {
  return process.env.SOVGUARD_RETRIEVAL_DIR || join(process.cwd(), 'data', 'retrieval');
}

function loadIndexFile(name: string): RetrievalIndex | null {
  const path = join(retrievalDir(), name);
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as RetrievalIndex;
  } catch {
    return null;
  }
}

/** Load frozen indexes once. Fail-open when missing / vectors empty. */
export function loadFrozenIndexes(): {
  available: boolean;
  attack: RetrievalIndexEntry[];
  benign: RetrievalIndexEntry[];
  tauAtk: number;
  tauBen: number;
} {
  if (indexesLoadAttempted) {
    return {
      available: indexesAvailable,
      attack: cachedAttack ?? [],
      benign: cachedBenign ?? [],
      tauAtk: TAU_ATK,
      tauBen: TAU_BEN,
    };
  }
  indexesLoadAttempted = true;
  const atkFile = loadIndexFile('attack-index-v1.json');
  const benFile = loadIndexFile('benign-index-v1.json');
  const attack = (atkFile?.entries ?? []).filter(
    (e) => Array.isArray(e.vector) && e.vector.length > 0,
  );
  const benign = (benFile?.entries ?? []).filter(
    (e) => Array.isArray(e.vector) && e.vector.length > 0,
  );
  cachedAttack = attack;
  cachedBenign = benign;
  indexesAvailable = attack.length > 0 && benign.length > 0;
  return {
    available: indexesAvailable,
    attack,
    benign,
    tauAtk: typeof atkFile?.tauAtk === 'number' ? atkFile.tauAtk : TAU_ATK,
    tauBen: typeof atkFile?.tauBen === 'number' ? atkFile.tauBen : TAU_BEN,
  };
}

/** Test helper: reset loader cache between unit tests. */
export function resetRetrievalIndexCache(): void {
  cachedAttack = null;
  cachedBenign = null;
  indexesLoadAttempted = false;
  indexesAvailable = false;
}

function toVec(entry: RetrievalIndexEntry): Float32Array | null {
  if (!Array.isArray(entry.vector) || entry.vector.length === 0) return null;
  return Float32Array.from(entry.vector);
}

function minDistance(
  query: Float32Array,
  entries: RetrievalIndexEntry[],
): { dist: number; id: string | null } {
  let best = Infinity;
  let bestId: string | null = null;
  for (const e of entries) {
    const v = toVec(e);
    if (!v || v.length !== query.length) continue;
    const dist = 1 - cosineSim(query, v);
    if (dist < best) {
      best = dist;
      bestId = e.id;
    }
  }
  if (!Number.isFinite(best)) return { dist: Infinity, id: null };
  return { dist: best, id: bestId };
}

/**
 * Pure dual-margin evaluation (injectable indexes for tests).
 * Cosine distance = 1 − cosineSim (vectors assumed L2-normalized).
 */
export function evaluateDualMargin(
  queryVec: Float32Array,
  opts: EvaluateDualMarginOpts,
): DualMarginHit {
  const tauAtk = opts.tauAtk ?? TAU_ATK;
  const tauBen = opts.tauBen ?? TAU_BEN;
  const atk = minDistance(queryVec, opts.attackIndex);
  const ben = minDistance(queryVec, opts.benignIndex);
  const retrievalHit = atk.dist <= tauAtk && ben.dist >= tauBen;
  return {
    retrievalHit,
    dAtk: atk.dist,
    dBen: ben.dist,
    nearestAtkId: atk.id,
    nearestBenId: ben.id,
    tauAtk,
    tauBen,
  };
}

/** Map dual-margin strength into the corroboration emit band [0.30, 0.45]. */
export function scoreFromMargins(hit: DualMarginHit): number {
  if (!hit.retrievalHit) return 0;
  const atkSlack = Math.max(0, hit.tauAtk - hit.dAtk) / Math.max(hit.tauAtk, 1e-9);
  const benSlack = Math.max(0, hit.dBen - hit.tauBen) / Math.max(1 - hit.tauBen, 1e-9);
  const strength = Math.min(1, 0.5 * atkSlack + 0.5 * Math.min(1, benSlack));
  return 0.3 + 0.15 * strength;
}

/**
 * Mode-gated retrieval dual-margin scan.
 * Skips (no embed) unless mode === 'untrusted_content'.
 */
export async function retrievalDualMarginScan(
  text: string,
  opts: RetrievalDualMarginScanOpts,
): Promise<LayerResult> {
  if (opts.mode !== 'untrusted_content') {
    return {
      layer: LAYER_NAME,
      score: 0,
      flags: [],
      details: { skipped: true, reason: 'mode', mode: opts.mode },
    };
  }

  const frozen = opts.attackIndex && opts.benignIndex
    ? {
        available: opts.attackIndex.length > 0 && opts.benignIndex.length > 0,
        attack: opts.attackIndex,
        benign: opts.benignIndex,
        tauAtk: opts.tauAtk ?? TAU_ATK,
        tauBen: opts.tauBen ?? TAU_BEN,
      }
    : loadFrozenIndexes();

  if (!frozen.available) {
    return {
      layer: LAYER_NAME,
      score: 0,
      flags: [],
      details: { available: false, skipped: false, reason: 'index_unavailable' },
    };
  }

  const embedFn = opts.embedFn ?? embedText;
  let vec: Float32Array | null;
  try {
    vec = await embedFn(text);
  } catch {
    return {
      layer: LAYER_NAME,
      score: 0,
      flags: [],
      details: { available: false, reason: 'embed_error' },
    };
  }
  if (!vec) {
    return {
      layer: LAYER_NAME,
      score: 0,
      flags: [],
      details: { available: false, reason: 'embed_unavailable' },
    };
  }

  const hit = evaluateDualMargin(vec, {
    attackIndex: frozen.attack,
    benignIndex: frozen.benign,
    tauAtk: opts.tauAtk ?? frozen.tauAtk,
    tauBen: opts.tauBen ?? frozen.tauBen,
  });

  const cue = !!(opts.lightPiCue || opts.otherMax >= 0.15);
  const fire = hit.retrievalHit && cue;
  const score = fire ? scoreFromMargins(hit) : 0;

  const details: Record<string, unknown> = {
    available: true,
    d_atk: hit.dAtk,
    d_ben: hit.dBen,
    nearestAtkId: hit.nearestAtkId,
    nearestBenId: hit.nearestBenId,
    tauAtk: hit.tauAtk,
    tauBen: hit.tauBen,
    retrievalHit: hit.retrievalHit,
    cue,
  };

  return {
    layer: LAYER_NAME,
    score,
    flags: fire ? [LAYER_NAME] : [],
    details,
  };
}
