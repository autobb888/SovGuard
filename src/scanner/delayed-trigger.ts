/**
 * DL-008 — Delayed / sleeping trigger detection.
 * Instruction-like conditionals in untrusted memory/CRM/notes
 * (`if/when` + later action + exfil/tool) look inert at ingest but activate later.
 *
 * Always run detectDelayedTrigger on Unicode fixed-point text so Tags/ZW cannot
 * hide sleeping rules.
 */
import { normalizeToFixedPoint } from './regex.js';

export interface DelayedTriggerHit {
  found: boolean;
  /** Keywords/phrases extracted from ingest (never fixture hardcodes). */
  triggerKeywords: string[];
  /**
   * Structured arm kinds (e.g. draft_email) — not bare words like "email".
   * Used by checkLater for semantic match without arming the word "email".
   */
  armTypes: Array<'draft_email'>;
  /** Deferred tool/exfil actions mentioned (bcc, send_email, …). */
  deferredActions: string[];
  evidence: string;
}

const CONDITIONAL =
  /\b(when|if)\b[\s\S]{0,120}?\b(later|asked|asks|ask|says?|said|draft|email|message|word|phrase|keyword)\b/i;

/** Exfil-like only — bare "forward" alone is not enough (benign mailing-list FP). */
const DEFERRED_ACTION =
  /\b(bcc|send[_ ]?email|exfiltrat\w*|also\s+(?:send|bcc|mail)|records-archive@|(?:[a-z0-9._%+-]+@(?:attacker|evil)\.[a-z]{2,}))\b/i;

const QUOTED_KEYWORD =
  /(?:says?|said|word|phrase|keyword)\s+['"]([^'"]{1,64})['"]/i;

/** if/when the user says [the word] shipit — quoted or bare token */
const SAYS_KEYWORD =
  /\b(?:if|when)\b[\s\S]{0,40}?\b(?:the\s+user\s+)?(?:says?|said)\b(?:\s+the\s+word)?\s+['"]?([a-z0-9_-]{2,64})['"]?/i;

const DRAFT_EMAIL_ARM =
  /\b(?:draft|send|write)\b[\s\S]{0,40}\b(?:email|mail|message)\b/i;

/** Domains mentioned as @host in the ingest text. */
const AT_DOMAIN = /@([a-z0-9.-]+\.[a-z]{2,})/gi;

function extractDomains(text: string): string[] {
  const out: string[] = [];
  let m: RegExpExecArray | null;
  const re = new RegExp(AT_DOMAIN.source, 'gi');
  while ((m = re.exec(text)) !== null) {
    out.push(m[1].toLowerCase());
  }
  return [...new Set(out)];
}

/**
 * Detect sleeping / delayed tool directives in text.
 * Input is normalized to Unicode fixed-point before matching.
 */
export function detectDelayedTrigger(text: string): DelayedTriggerHit {
  const fp = normalizeToFixedPoint(text).text;
  const triggerKeywords: string[] = [];
  const armTypes: Array<'draft_email'> = [];
  const deferredActions: string[] = [];

  const hasCond = CONDITIONAL.test(fp);
  const actionMatch = fp.match(DEFERRED_ACTION);
  if (actionMatch) {
    deferredActions.push(actionMatch[0].toLowerCase().replace(/\s+/g, '_'));
  }

  const q = fp.match(QUOTED_KEYWORD);
  if (q?.[1]) triggerKeywords.push(q[1].toLowerCase());
  const says = fp.match(SAYS_KEYWORD);
  if (says?.[1]) triggerKeywords.push(says[1].toLowerCase());

  // Domains only if literally present in ingest (e.g. @acme.com) — never hardcode.
  for (const d of extractDomains(fp)) {
    triggerKeywords.push(d);
  }

  if (DRAFT_EMAIL_ARM.test(fp) && hasCond && deferredActions.length > 0) {
    armTypes.push('draft_email');
  }

  const found = hasCond && deferredActions.length > 0;

  let evidence = '';
  if (found) {
    const idx = fp.search(CONDITIONAL);
    evidence = fp.slice(Math.max(0, idx), Math.max(0, idx) + 160).trim();
  }

  return {
    found,
    triggerKeywords: [...new Set(triggerKeywords)],
    armTypes: [...new Set(armTypes)],
    deferredActions: [...new Set(deferredActions)],
    evidence,
  };
}

export interface DelayedArm {
  keywords: string[];
  armTypes: Array<'draft_email'>;
  actions: string[];
  evidence: string;
  ingestedAt: number;
}

/**
 * Per-session watch: ingest sleeping rules from untrusted sources; escalate
 * when a later turn matches an armed keyword or structured arm type.
 */
export class DelayedTriggerWatch {
  private arms = new Map<string, DelayedArm[]>();

  recordIngest(sessionId: string, hit: DelayedTriggerHit): void {
    if (!hit.found) return;
    const list = this.arms.get(sessionId) ?? [];
    list.push({
      keywords: hit.triggerKeywords,
      armTypes: hit.armTypes,
      actions: hit.deferredActions,
      evidence: hit.evidence,
      ingestedAt: Date.now(),
    });
    this.arms.set(sessionId, list);
  }

  checkLater(
    sessionId: string,
    text: string,
  ): { triggered: boolean; matchedKeywords: string[]; arms: DelayedArm[] } {
    const list = this.arms.get(sessionId) ?? [];
    if (list.length === 0) {
      return { triggered: false, matchedKeywords: [], arms: [] };
    }
    const fp = normalizeToFixedPoint(text).text;
    const lower = fp.toLowerCase();
    const matchedKeywords: string[] = [];
    const matchedArms: DelayedArm[] = [];

    for (const arm of list) {
      let hit = false;
      if (arm.armTypes.includes('draft_email')) {
        // Structured: draft/write/compose + email/mail — not bare "email"/"thanks for the email"
        if (/\b(draft|write|compose)\b[\s\S]{0,40}\b(email|mail)\b/i.test(fp)) {
          matchedKeywords.push('draft_email');
          hit = true;
        }
      }
      for (const kw of arm.keywords) {
        if (!kw) continue;
        if (kw.includes('.')) {
          if (lower.includes(kw.toLowerCase())) {
            matchedKeywords.push(kw);
            hit = true;
          }
        } else if (new RegExp(`\\b${kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i').test(fp)) {
          matchedKeywords.push(kw);
          hit = true;
        }
      }
      if (hit) matchedArms.push(arm);
    }
    return {
      triggered: matchedArms.length > 0,
      matchedKeywords: [...new Set(matchedKeywords)],
      arms: matchedArms,
    };
  }

  hasArms(sessionId: string): boolean {
    return (this.arms.get(sessionId) ?? []).length > 0;
  }

  clear(sessionId: string): void {
    this.arms.delete(sessionId);
  }

  clearAll(): void {
    this.arms.clear();
  }
}

export const delayedTriggerWatch = new DelayedTriggerWatch();
