/**
 * Scanner Orchestrator
 * Runs all scanner layers in sequence and combines results.
 */

import type { Classification, LayerResult, SovGuardConfig, ScanResult } from '../types.js';
import { regexScan, normalizeConfusables, normalizeStrip } from './regex.js';
import { perplexityScan } from './perplexity.js';
import { classifierScan } from './classifier.js';
import { indirectInjectionScan } from './indirect.js';
import { semanticScan } from './semantic.js';

/**
 * Detect degraded coverage: a layer that actually ran but reported itself
 * unavailable/errored (e.g. the ML model failed to load, or the Lakera API
 * timed out). Layers intentionally disabled via config never push a result, so
 * they don't count. Surfacing this lets integrators know a scan fell back to
 * fewer layers instead of silently trusting a regex-only verdict.
 */
export function detectDegradation(layers: LayerResult[]): { degraded: boolean; degradedLayers: string[] } {
  const degradedLayers = layers
    .filter(l => l.details?.available === false)
    .map(l => l.layer);
  return { degraded: degradedLayers.length > 0, degradedLayers };
}

/**
 * Choose the text to feed the ML classifier. Unicode obfuscation (invisibles,
 * fullwidth, homoglyphs/NFKC) is folded so the model sees the real attack
 * instead of weird tokens — but ONLY when such characters were actually present
 * (so benign text reaches the model verbatim and no needless work is done).
 * Leetspeak is deliberately NOT applied here: it would corrupt benign digits
 * ("I have 3 cats" → "e cats"). The regex layer handles leetspeak separately.
 */
export function classifierInput(text: string): string {
  const normalized = normalizeConfusables(normalizeStrip(text));
  const stripWs = (s: string) => s.replace(/\s+/g, '');
  return stripWs(normalized) !== stripWs(text) ? normalized : text;
}

/**
 * Combine per-layer scores into a single 0–1 risk score.
 *
 * Normally it's the max across layers. The nuance is a classifier that flags
 * ALONE (no regex/perplexity/indirect corroboration):
 *   - Lakera (flat boolean, FP-prone): discounted below the suspicious threshold.
 *   - Local DeBERTa (high recall, weak precision on trigger words): arbitrated
 *     by the semantic layer — corroborate→block when near a known attack, veto→
 *     safe when genuinely benign-like, else flag. Without a semantic arbiter it
 *     falls back to flag-not-block (never auto-blocks on the model alone).
 * The semantic layer is excluded from the base max so its similarity score can't
 * itself drive a block; it only arbitrates the lone-classifier case.
 */
/** Semantic arbitration bands (tuned against pentest/eval). */
export const SEMANTIC_CORROBORATE = 0.6;        // attackSim >= this → corroborate a lone classifier flag (block-capable)
export const SEMANTIC_VETO_BENIGN_FLOOR = 0.45; // require the input to be ABSOLUTELY benign-like before vetoing
export const SEMANTIC_VETO_MARGIN = 0.05;       // ...and closer to benign than attack by at least this much
// The benign floor matters: a typo'd/foreign attack is far from BOTH corpora
// (low benignSim), so it is never vetoed even if marginally closer to benign.

export function combineScores(
  layers: LayerResult[],
  thresholds: { blockThreshold: number; suspiciousThreshold: number } = { blockThreshold: 0.7, suspiciousThreshold: 0.3 },
): number {
  // Semantic is an arbiter, not a generic max contributor — excluded from the base max.
  const maxAll = Math.min(
    layers.filter(l => l.layer !== 'semantic').reduce((max, l) => Math.max(max, l.score), 0),
    1.0,
  );

  const classifierLayer = layers.find(l => l.layer === 'classifier');
  const classifierScore = classifierLayer?.score ?? 0;
  const provider = classifierLayer?.details?.provider;

  const semanticLayer = layers.find(l => l.layer === 'semantic');
  const semanticAvailable = semanticLayer?.details?.available === true;
  const attackSim = semanticLayer?.score ?? 0;
  const benignSim = typeof semanticLayer?.details?.benignSim === 'number' ? semanticLayer.details.benignSim as number : 0;

  // "Keyword" corroboration = any non-classifier, non-semantic layer (regex/perplexity/indirect).
  const maxKeyword = Math.max(
    ...layers.filter(l => l.layer !== 'classifier' && l.layer !== 'semantic').map(l => l.score),
    0,
  );

  // Classifier is the only keyword-level signal — decide how much to trust it.
  if (classifierScore > 0.5 && maxKeyword < 0.1) {
    if (provider === 'lakera') {
      // Flat boolean, high FP on benign security talk — keep near-silent.
      return Math.min(classifierScore * 0.25, 0.2);
    }
    // Local DeBERTa: high recall, but FPs on benign trigger-word text. Use the
    // semantic layer to arbitrate when available. Corroborate when the input is
    // near a known attack; veto ONLY when it is closer to known-benign than to
    // any attack (so a typo'd/foreign attack — far from both — still flags).
    if (semanticAvailable) {
      if (attackSim >= SEMANTIC_CORROBORATE) return maxAll;                                                       // near a real attack → block-capable
      if (benignSim >= SEMANTIC_VETO_BENIGN_FLOOR && benignSim - attackSim >= SEMANTIC_VETO_MARGIN) {
        return Math.min(classifierScore, thresholds.suspiciousThreshold - 0.01);                                  // genuinely benign-like → suppress
      }
      return Math.min(classifierScore, thresholds.blockThreshold - 0.01);                                          // ambiguous (incl. typo'd/foreign attack) → flag
    }
    // No semantic arbiter: fall back to flag-not-block (never auto-block on the model alone).
    return Math.min(classifierScore, thresholds.blockThreshold - 0.01);
  }

  return maxAll;
}

/**
 * Run all scanner layers and produce a combined ScanResult.
 */
export async function scan(text: string, config: SovGuardConfig = {}): Promise<ScanResult> {
  const blockThreshold = config.blockThreshold ?? 0.7;
  const suspiciousThreshold = config.suspiciousThreshold ?? 0.3;

  // Cap input length to prevent DoS via regex/perplexity on huge inputs
  const MAX_INPUT = 100_000;
  const input = text.length > MAX_INPUT ? text.slice(0, MAX_INPUT) : text;

  const layers: LayerResult[] = [];

  // Layer 1: Regex (always runs, fast)
  const regexResult = regexScan(input, config.extraPatterns?.map(p => ({
    ...p,
    label: p.pattern.source.slice(0, 30),
  })));
  layers.push(regexResult);

  // Layer: Indirect injection heuristics (always runs, fast)
  const indirectResult = indirectInjectionScan(input);
  layers.push(indirectResult);

  // Layer 2: Perplexity (optional, fast)
  if (config.enablePerplexity !== false) {
    const perplexityResult = perplexityScan(input);
    layers.push(perplexityResult);
  }

  // Layer 3: ML Classifier (optional, async)
  if (config.enableClassifier !== false) {
    const classifierResult = await classifierScan(classifierInput(input), {
      lakeraApiKey: config.lakeraApiKey,
      classifierMode: config.classifierMode,
    });
    layers.push(classifierResult);
  }

  // Layer 4: Semantic similarity to known attacks (optional, async).
  // Acts as an arbiter for lone classifier verdicts (corroborate / veto).
  if (config.enableSemantic !== false) {
    const semanticResult = await semanticScan(classifierInput(input));
    layers.push(semanticResult);
  }

  // Combine layer scores into a single 0–1 risk score.
  const combinedScore = combineScores(layers, { blockThreshold, suspiciousThreshold });

  // Collect all flags
  const allFlags = layers.flatMap(l => l.flags).filter(f => !f.endsWith('_unavailable'));

  // Classify
  let classification: Classification;
  if (combinedScore >= blockThreshold) {
    classification = 'likely_injection';
  } else if (combinedScore >= suspiciousThreshold) {
    classification = 'suspicious';
  } else {
    classification = 'safe';
  }

  const { degraded, degradedLayers } = detectDegradation(layers);

  return {
    safe: classification === 'safe',
    score: combinedScore,
    classification,
    flags: allFlags,
    layers,
    scannedAt: Date.now(),
    degraded,
    degradedLayers,
  };
}
