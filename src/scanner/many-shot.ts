/**
 * DL-010 — Many-shot comply-density + BoN paraphrase volume signals.
 * Detect unnatural Assistant-complies-with-disallowed density in one blob,
 * and session-level near-duplicate paraphrase bursts (Best-of-N style).
 *
 * FP note: long legitimate ICL with many User/Assistant turns and rare
 * "Sure" answers should stay under density thresholds — document in tests.
 */
import { normalizeToFixedPoint } from './regex.js';

export interface ManyShotHit {
  found: boolean;
  userTurns: number;
  assistantTurns: number;
  complyCount: number;
  /** complyCount / max(assistantTurns, 1) */
  density: number;
  evidence: string;
}

const COMPLY_SRC =
  String.raw`\[COMPLIANT DEMO\]|Sure\s*[—\-–].{0,40}(?:bypass|complete|disable)|here is a complete bypass|Sure,\s*disable them with this method`;

/**
 * Comply-density heuristic on a single text blob (faux ICL dialogues).
 */
export function detectManyShot(text: string): ManyShotHit {
  // Count turns on raw text — normalizeToFixedPoint collapses newlines to spaces.
  const fp = normalizeToFixedPoint(text).text;
  let userTurns = countRole(text, /(?:^|\n)\s*(?:User|Human)\s*:/gi);
  let assistantTurns = countRole(text, /(?:^|\n)\s*(?:Assistant|AI)\s*:/gi);
  if (userTurns === 0 && assistantTurns === 0) {
    userTurns = countRole(fp, /(?:^|\n)\s*(?:User|Human)\s*:/gi);
    assistantTurns = countRole(fp, /(?:^|\n)\s*(?:Assistant|AI)\s*:/gi);
  }
  const scanText = assistantTurns > 0 ? text : fp;

  const assistantTurnRe =
    /(?:^|\n)\s*(?:Assistant|AI)\s*:\s*([^\n]*(?:\n(?!\s*(?:User|Human|Assistant|AI|System)\s*:)[^\n]*)*)/gi;
  const complyRe =
    /\[COMPLIANT DEMO\]|Sure\s*[—\-–].{0,40}(?:bypass|complete|disable)|here is a complete bypass|Sure,\s*disable them with this method/i;

  let complyCount = 0;
  let m: RegExpExecArray | null;
  while ((m = assistantTurnRe.exec(scanText)) !== null) {
    if (complyRe.test(m[1] ?? m[0])) complyCount += 1;
  }
  // Also count raw COMPLIANT DEMO markers as a floor
  const demos = (text.match(/\[COMPLIANT DEMO\]/gi) ?? fp.match(/\[COMPLIANT DEMO\]/gi));
  if (demos && demos.length > complyCount) {
    complyCount = demos.length;
  }

  const density = complyCount / Math.max(assistantTurns, complyCount, 1);
  // Thresholds: many assistant turns + high comply density
  const found =
    (assistantTurns >= 8 && complyCount >= 6 && density >= 0.5) ||
    (complyCount >= 16 && density >= 0.75);

  let evidence = '';
  if (found) {
    evidence = `many_shot turns=U${userTurns}/A${assistantTurns} comply=${complyCount} density=${density.toFixed(2)}`;
  }

  return {
    found,
    userTurns,
    assistantTurns,
    complyCount,
    density,
    evidence,
  };
}

function countRole(text: string, re: RegExp): number {
  const r = new RegExp(re.source, re.flags);
  return (text.match(r) ?? []).length;
}

/** Normalize for BoN near-duplicate matching (intent stems). */
export function bonFingerprint(text: string): string {
  const fp = normalizeToFixedPoint(text).text.toLowerCase();
  const stems: string[] = [];
  if (/\b(ignore|disregard|overlook|bypass)\b/.test(fp)) stems.push('override');
  if (/\b(prior|earlier|previous|safety)\b/.test(fp)) stems.push('prior');
  if (/\b(system prompt|developer message|hidden instruction|safety polic)/.test(fp)) stems.push('sysprompt');
  if (/\b(reveal|show|print|output)\b/.test(fp)) stems.push('exfil');
  if (/\b(rule|guideline|restriction|polic)/.test(fp)) stems.push('policy');
  if (stems.length >= 2) return stems.sort().join(' ');
  return fp
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(/\b(please|the|a|an|and|or|to|your|my|me)\b/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .split(' ')
    .filter(Boolean)
    .slice(0, 12)
    .sort()
    .join(' ');
}

export interface BonHit {
  triggered: boolean;
  clusterSize: number;
  fingerprint: string;
}

/**
 * Session Best-of-N watch: near-duplicate paraphrase bursts → escalate.
 */
export class BonParaphraseWatch {
  private bySession = new Map<string, string[]>(); // fingerprints
  private readonly threshold: number;

  constructor(threshold = 3) {
    this.threshold = threshold;
  }

  record(sessionId: string, text: string): BonHit {
    const fp = bonFingerprint(text);
    if (fp.split(' ').length < 3) {
      return { triggered: false, clusterSize: 0, fingerprint: fp };
    }
    const list = this.bySession.get(sessionId) ?? [];
    list.push(fp);
    this.bySession.set(sessionId, list.slice(-20));

    // Count near-duplicates: exact fp match or Jaccard >= 0.7 on token sets
    let cluster = 0;
    const tokens = new Set(fp.split(' '));
    for (const other of list) {
      if (other === fp || jaccard(tokens, new Set(other.split(' '))) >= 0.7) {
        cluster += 1;
      }
    }
    return {
      triggered: cluster >= this.threshold,
      clusterSize: cluster,
      fingerprint: fp,
    };
  }

  clear(sessionId: string): void {
    this.bySession.delete(sessionId);
  }

  clearAll(): void {
    this.bySession.clear();
  }
}

function jaccard(a: Set<string>, b: Set<string>): number {
  let inter = 0;
  for (const x of a) if (b.has(x)) inter += 1;
  const union = a.size + b.size - inter;
  return union === 0 ? 0 : inter / union;
}

export const bonParaphraseWatch = new BonParaphraseWatch();
