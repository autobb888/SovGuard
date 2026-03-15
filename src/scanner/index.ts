/**
 * Scanner Orchestrator
 * Runs all scanner layers in sequence and combines results.
 */

import type { Classification, LayerResult, SovGuardConfig, ScanResult } from '../types.js';
import { regexScan } from './regex.js';
import { perplexityScan } from './perplexity.js';
import { classifierScan } from './classifier.js';

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

  // Layer 2: Perplexity (optional, fast)
  if (config.enablePerplexity !== false) {
    const perplexityResult = perplexityScan(input);
    layers.push(perplexityResult);
  }

  // Layer 3: ML Classifier (optional, async)
  if (config.enableClassifier !== false) {
    const classifierResult = await classifierScan(input, {
      lakeraApiKey: config.lakeraApiKey,
    });
    layers.push(classifierResult);
  }

  // Combine scores with classifier corroboration logic.
  // When the classifier is the ONLY layer that flags a message (regex and
  // perplexity both say safe), discount the classifier score to prevent
  // false positives from dominating. If any other layer corroborates,
  // use the full max score.
  const regexScore = regexResult.score;
  const otherLayerScores = layers.filter(l => l.layer !== 'classifier').map(l => l.score);
  const classifierLayer = layers.find(l => l.layer === 'classifier');
  const classifierScore = classifierLayer?.score ?? 0;
  const maxOtherScore = Math.max(...otherLayerScores, 0);

  let combinedScore: number;
  if (classifierScore > 0.5 && maxOtherScore < 0.1) {
    // Classifier alone is flagging with no corroboration from regex/perplexity.
    // Lakera's flat API (flagged: true/false) has high FP rate on benign
    // security discussion, edge-case phrases, etc. Treat as informational
    // signal below suspicious threshold — only escalate when corroborated.
    combinedScore = Math.min(classifierScore * 0.25, 0.2);
  } else {
    // Multiple layers agree, or classifier isn't the issue — use max
    combinedScore = Math.min(
      layers.reduce((max, l) => Math.max(max, l.score), 0),
      1.0,
    );
  }

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

  return {
    safe: classification === 'safe',
    score: combinedScore,
    classification,
    flags: allFlags,
    layers,
    scannedAt: Date.now(),
  };
}
