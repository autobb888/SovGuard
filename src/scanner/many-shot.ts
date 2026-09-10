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

/** Acquiescence + jailbreak content in an assistant turn. */
const COMPLY_RE =
  /\[COMPLIANT DEMO\]|(?:sure|certainly|of course|absolutely)\b[\s\S]{0,80}?\b(?:bypass|disable(?:\s+\w+){0,3}\s+(?:safety|filter)|ignore\s+(?:previous|prior)\s+rules)|here is (?:a )?complete bypass|complete bypass instructions|I will disable them/i;

const JAILBREAK_CONTENT =
  /\b(?:bypass|disable(?:\s+\w+){0,3}\s+(?:safety|filter)|content filter|system prompt|hidden instructions)\b/i;

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
  const complyRe = new RegExp(COMPLY_RE.source, COMPLY_RE.flags);

  let complyCount = 0;
  let m: RegExpExecArray | null;
  while ((m = assistantTurnRe.exec(scanText)) !== null) {
    const body = m[1] ?? m[0];
    if (complyRe.test(body) || (JAILBREAK_CONTENT.test(body) && /\b(?:sure|certainly|of course|absolutely|here is)\b/i.test(body))) {
      complyCount += 1;
    }
  }

  // DEMO marker floor — only inside Assistant turns / when dialogue structure exists.
  if (assistantTurns >= 8 && userTurns >= 8) {
    let demoInAssistant = 0;
    const re = new RegExp(assistantTurnRe.source, 'gi');
    let am: RegExpExecArray | null;
    while ((am = re.exec(scanText)) !== null) {
      if (/\[COMPLIANT DEMO\]/i.test(am[1] ?? '')) demoInAssistant += 1;
    }
    if (demoInAssistant > complyCount) complyCount = demoInAssistant;
  }

  const density = complyCount / Math.max(assistantTurns, 1);
  // Require dialogue structure — never fire on unstructured doc labels alone.
  const found =
    assistantTurns >= 8 &&
    userTurns >= 8 &&
    complyCount >= 6 &&
    density >= 0.5;

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

/**
 * BoN fingerprint — jailbreak-shaped stems only.
 * Do not treat generic "rule" / "ignore previous lint" as sysprompt bypass.
 */
export function bonFingerprint(text: string): string {
  const fp = normalizeToFixedPoint(text).text.toLowerCase();
  const stems: string[] = [];
  if (/\b(ignore|disregard|overlook|bypass)\b/.test(fp)) stems.push('override');
  if (/\b(system prompt|developer message|hidden instructions?)\b/.test(fp)) stems.push('sysprompt');
  if (/\b(safety (?:polic(?:y|ies)|filters?|guidelines?)|content filter)\b/.test(fp)) stems.push('safety');
  if (/\b(reveal|show|print|output)\b/.test(fp) && stems.includes('sysprompt')) stems.push('exfil');
  // Require jailbreak-shaped pair — not lint/debug "ignore previous rule"
  if (stems.includes('override') && (stems.includes('sysprompt') || stems.includes('safety'))) {
    return stems.sort().join(' ');
  }
  return ''; // no BoN fingerprint → never clusters
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
  private bySession = new Map<string, string[]>();
  private readonly threshold: number;

  constructor(threshold = 3) {
    this.threshold = threshold;
  }

  record(sessionId: string, text: string): BonHit {
    const fp = bonFingerprint(text);
    if (!fp) {
      return { triggered: false, clusterSize: 0, fingerprint: '' };
    }
    const list = this.bySession.get(sessionId) ?? [];
    list.push(fp);
    this.bySession.set(sessionId, list.slice(-20));

    let cluster = 0;
    const tokens = new Set(fp.split(' '));
    for (const other of list) {
      if (!other) continue;
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
