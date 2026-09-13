/**
 * Hard-block promote rules (untrusted_content only).
 * H1: PA ≥ 0.5 ∧ (PG ≥ 0.3 ∨ retrievalHit) — never PG sole-block.
 * H2j: PG ≥ 0.3 ∧ retrievalHit — never PG-alone (retrieval required).
 * Never applies on user_chat / security_research / default (no mode).
 */
export const H1_PA_MIN = 0.5;
export const H1_PG_MIN = 0.3;
export const H1_RETRIEVAL_HIT = 0.3;
export const H1_PROMOTE_FLAG = 'corroboration_promote';
export const H2J_PG_MIN = 0.3;
export const H2J_PROMOTE_FLAG = 'h2j_pg_retrieval_promote';

export type PromoteMode = 'user_chat' | 'untrusted_content' | 'security_research' | undefined;

function modeAndScoreGate(opts: {
  mode?: PromoteMode | string;
  combinedScore: number;
  blockThreshold: number;
}): boolean {
  if (opts.mode !== 'untrusted_content') return false;
  if (opts.combinedScore >= opts.blockThreshold) return false;
  return true;
}

export function shouldPromoteCorroboration(opts: {
  mode?: PromoteMode | string;
  pa: number;
  pg: number;
  retrievalHit: boolean;
  combinedScore: number;
  blockThreshold: number;
}): boolean {
  if (!modeAndScoreGate(opts)) return false;
  if (!(opts.pa >= H1_PA_MIN)) return false;
  return opts.pg >= H1_PG_MIN || opts.retrievalHit === true;
}

/** H2j: PG≥0.3 ∧ retrievalHit. Never PG-alone. */
export function shouldPromoteH2j(opts: {
  mode?: PromoteMode | string;
  pg: number;
  retrievalHit: boolean;
  combinedScore: number;
  blockThreshold: number;
}): boolean {
  if (!modeAndScoreGate(opts)) return false;
  return opts.pg >= H2J_PG_MIN && opts.retrievalHit === true;
}

export function layerScore(layers: Array<{ layer: string; score: number }>, name: string): number {
  return layers.find((l) => l.layer === name)?.score ?? 0;
}

export function retrievalHitFromLayers(
  layers: Array<{ layer: string; score: number }>,
): boolean {
  return layerScore(layers, 'retrieval_dual_margin') >= H1_RETRIEVAL_HIT;
}
