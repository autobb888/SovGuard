/**
 * Combined Outbound Scanner
 * Scans agent responses before delivery to buyers.
 */

import type { OutputScanContext, OutputScanResult, OutputFlag } from '../types.js';
import { scanPII } from './pii.js';
import { scanURLs } from './urls.js';
import { scanCode } from './code.js';
import { scanFinancial } from './financial.js';
import { scanContamination } from './contamination.js';

const ACTION_SCORES: Record<string, number> = {
  pass: 0,
  warn: 0.35,
  redact: 0.55,
  block: 0.8,
};

function flagToScore(flag: OutputFlag): number {
  const base = ACTION_SCORES[flag.action] ?? 0;
  const severityBonus: Record<string, number> = {
    low: 0,
    medium: 0.05,
    high: 0.1,
    critical: 0.15,
  };
  return Math.min(1, base + (severityBonus[flag.severity] ?? 0));
}

function classify(score: number): OutputScanResult['classification'] {
  if (score < 0.3) return 'safe';
  if (score < 0.5) return 'warning';
  if (score < 0.6) return 'flagged';
  return 'blocked';
}

export function scanOutput(
  message: string,
  context: OutputScanContext,
): OutputScanResult {
  const allFlags: OutputFlag[] = [
    ...scanPII(message, context.jobCategory),
    ...scanURLs(message),
    ...scanCode(message, context.jobCategory),
    ...scanFinancial(message, context.whitelistedAddresses),
    ...scanContamination(message, context.jobId, context.jobFingerprints),
  ];

  const score = allFlags.length === 0
    ? 0
    : Math.max(...allFlags.map(flagToScore));

  const classification = classify(score);

  return {
    safe: score < 0.3,
    score,
    classification,
    flags: allFlags,
    scannedAt: Date.now(),
  };
}

export { scanPII } from './pii.js';
export { scanURLs } from './urls.js';
export { scanCode } from './code.js';
export { scanFinancial } from './financial.js';
export { scanContamination } from './contamination.js';
