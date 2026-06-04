/**
 * Scanner Orchestrator
 * Runs all scanner layers in sequence and combines results.
 */

import type { Classification, LayerResult, SovGuardConfig, ScanResult } from '../types.js';
import { normalizeConfusables, normalizeStrip } from './regex.js';
import { classifierScan } from './classifier.js';
import { semanticScan } from './semantic.js';
import { scanPool } from './scan-pool.js';
import { runJsLayersSync } from './js-layers.js';

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
 *
 * The full input is always scanned — there is no truncation. Large inputs run on
 * the model-free worker pool (off the event loop); small inputs run inline. The
 * ONNX layers run on main.
 *
 * @throws {ScanPoolSaturatedError} when the worker pool's bounded queue is full
 *   (backpressure under overload). It never returns an unscanned "safe" verdict —
 *   servers map this to HTTP 503; direct SDK callers should treat it as
 *   "scanner busy, retry".
 */
export async function scan(text: string, config: SovGuardConfig = {}): Promise<ScanResult> {
  const blockThreshold = config.blockThreshold ?? 0.7;
  const suspiciousThreshold = config.suspiciousThreshold ?? 0.3;

  // H3: scan the FULL input — no truncation. Length is handled by running off the
  // main thread (large inputs go to the worker pool), never by scanning less.
  const input = text;
  const enablePerplexity = config.enablePerplexity !== false;
  const extraPatterns = config.extraPatterns?.map((p) => ({
    ...p,
    label: p.pattern.source.slice(0, 30),
  }));

  // JS layers (regex/indirect/perplexity): inline for small inputs or when custom
  // patterns are supplied (RegExp doesn't cross the worker boundary cleanly);
  // otherwise on the model-free worker pool. Either path scans 100% of the input.
  const jsInline = (extraPatterns != null && extraPatterns.length > 0) || input.length <= scanPool.threshold;
  const jsLayersPromise: Promise<LayerResult[]> = jsInline
    ? Promise.resolve(runJsLayersSync(input, enablePerplexity, extraPatterns))
    : scanPool.runJsLayers(input, enablePerplexity);

  // ML layers (classifier + semantic) stay on main — already off-loop natively and
  // bounded by the M9 inference-gate. Run them concurrently with the JS layers.
  const mlLayersPromise = runMlLayers(input, config);

  const [jsLayers, mlLayers] = await Promise.all([jsLayersPromise, mlLayersPromise]);
  const layers: LayerResult[] = [...jsLayers, ...mlLayers];

  const combinedScore = combineScores(layers, { blockThreshold, suspiciousThreshold });
  const allFlags = layers.flatMap((l) => l.flags).filter((f) => !f.endsWith('_unavailable'));

  let classification: Classification;
  if (combinedScore >= blockThreshold) classification = 'likely_injection';
  else if (combinedScore >= suspiciousThreshold) classification = 'suspicious';
  else classification = 'safe';

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

/** ML layers run on main (ONNX is native-async + M9-gated). Preserves layer order. */
async function runMlLayers(input: string, config: SovGuardConfig): Promise<LayerResult[]> {
  const layers: LayerResult[] = [];
  if (config.enableClassifier !== false) {
    layers.push(await classifierScan(classifierInput(input), {
      lakeraApiKey: config.lakeraApiKey,
      classifierMode: config.classifierMode,
    }));
  }
  if (config.enableSemantic !== false) {
    layers.push(await semanticScan(classifierInput(input)));
  }
  return layers;
}
