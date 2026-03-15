/**
 * Outbound Cross-Contamination Scanner
 * Detects when an agent leaks identifiers from other jobs.
 */

import { createHash } from 'node:crypto';
import type { OutputFlag } from '../types.js';
import { EMAIL_RE, URL_RE } from './patterns.js';

const FILE_PATH_RE = /(?:\/[\w.-]+){2,}|[A-Za-z]:\\(?:[\w.-]+\\)+[\w.-]+|(?:\.\.[\\/])+[\w.\\/-]+/g;
// Simple name heuristic: capitalized word pairs
const NAME_RE = /\b[A-Z][a-z]{2,}\s+[A-Z][a-z]{2,}\b/g;

function hashId(id: string): string {
  return createHash('sha256').update(id.toLowerCase().trim()).digest('hex');
}

function extractIdentifiers(text: string): string[] {
  const ids: string[] = [];
  for (const re of [EMAIL_RE, URL_RE, FILE_PATH_RE, NAME_RE]) {
    const regex = new RegExp(re.source, re.flags);
    let m: RegExpExecArray | null;
    while ((m = regex.exec(text)) !== null) {
      ids.push(m[0]);
    }
  }
  return ids;
}

export function scanContamination(
  message: string,
  currentJobId: string,
  jobFingerprints?: Map<string, Set<string>>,
): OutputFlag[] {
  if (!jobFingerprints || jobFingerprints.size === 0) return [];

  const ids = extractIdentifiers(message);
  if (ids.length === 0) return [];

  const flags: OutputFlag[] = [];
  let matchCount = 0;

  for (const id of ids) {
    const h = hashId(id);
    for (const [jobId, fingerprints] of jobFingerprints) {
      if (jobId === currentJobId) continue;
      if (fingerprints.has(h)) {
        matchCount++;
        if (matchCount <= 3) {
          // P1-OUT-1: Never include other job IDs or raw identifiers in flag output
          // These are buyer-facing — leaking them IS the cross-contamination we're preventing
          flags.push({
            type: 'cross_contamination',
            severity: matchCount === 1 ? 'medium' : 'high',
            detail: 'Potential cross-job data detected in response',
            evidence: '(redacted)',
            action: matchCount >= 2 ? 'block' : 'warn',
          });
        }
      }
    }
  }

  // Bulk contamination
  if (matchCount > 3) {
    flags.push({
      type: 'cross_contamination',
      severity: 'critical',
      detail: `${matchCount} cross-job identifiers detected — likely data leak`,
      evidence: `(${matchCount} matches)`,
      action: 'block',
    });
  }

  return flags;
}

export { hashId, extractIdentifiers };
