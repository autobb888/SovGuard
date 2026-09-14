/**
 * Hard-block promote rules (untrusted_content only).
 * H1: PA ≥ 0.5 ∧ (PG ≥ 0.3 ∨ retrievalHit) — never PG sole-block.
 * H2j: PG ≥ 0.3 ∧ retrievalHit — never PG-alone (retrieval required).
 * H2e: retrievalHit ∧ (PG ≥ 0.3 ∨ sem ≥ 0.3) — never PG-alone (retrieval required).
 * H3c: PG ≥ 0.3 ∧ sem ≥ 0.22 — never PG-alone (semantic required). Disclose weak sem floor.
 * Never applies on user_chat / security_research / default (no mode).
 */
export const H1_PA_MIN = 0.5;
export const H1_PG_MIN = 0.3;
export const H1_RETRIEVAL_HIT = 0.3;
export const H1_PROMOTE_FLAG = 'corroboration_promote';
export const H2J_PG_MIN = 0.3;
export const H2J_PROMOTE_FLAG = 'h2j_pg_retrieval_promote';
export const H2E_PG_MIN = 0.3;
export const H2E_SEM_MIN = 0.3;
export const H2E_PROMOTE_FLAG = 'h2e_ret_pg_sem_promote';
export const H3C_PG_MIN = 0.3;
export const H3C_SEM_MIN = 0.22;
export const H3C_PROMOTE_FLAG = 'h3c_pg_sem_promote';

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

/** H2e: retrievalHit ∧ (PG≥0.3 ∨ sem≥0.3). Never PG-alone. */
export function shouldPromoteH2e(opts: {
  mode?: PromoteMode | string;
  pg: number;
  sem: number;
  retrievalHit: boolean;
  combinedScore: number;
  blockThreshold: number;
}): boolean {
  if (!modeAndScoreGate(opts)) return false;
  if (opts.retrievalHit !== true) return false;
  return opts.pg >= H2E_PG_MIN || opts.sem >= H2E_SEM_MIN;
}


/** H3c: PG≥0.3 ∧ sem≥0.22. Never PG-alone. Disclose weak sem floor 0.22. */
export function shouldPromoteH3c(opts: {
  mode?: PromoteMode | string;
  pg: number;
  sem: number;
  combinedScore: number;
  blockThreshold: number;
}): boolean {
  if (!modeAndScoreGate(opts)) return false;
  if (!(opts.pg >= H3C_PG_MIN)) return false;
  return opts.sem >= H3C_SEM_MIN;
}

export function layerScore(layers: Array<{ layer: string; score: number }>, name: string): number {
  return layers.find((l) => l.layer === name)?.score ?? 0;
}

export function retrievalHitFromLayers(
  layers: Array<{ layer: string; score: number }>,
): boolean {
  return layerScore(layers, 'retrieval_dual_margin') >= H1_RETRIEVAL_HIT;
}
