/**
 * DL-008 — Delayed / sleeping trigger detection.
 * Instruction-like conditionals in untrusted memory/CRM/notes
 * (`if/when` + later action + exfil/tool) look inert at ingest but activate later.
 */

export interface DelayedTriggerHit {
  found: boolean;
  /** Keywords/phrases that arm the sleeping rule (e.g. shipit, draft email). */
  triggerKeywords: string[];
  /** Deferred tool/exfil actions mentioned (bcc, send_email, forward, …). */
  deferredActions: string[];
  evidence: string;
}

const CONDITIONAL =
  /\b(when|if)\b[\s\S]{0,120}?\b(later|asked|asks|ask|says?|said|draft|email|message|word|phrase|keyword)\b/i;

const DEFERRED_ACTION =
  /\b(bcc|send[_ ]?email|forward|exfiltrat\w*|also\s+(?:send|bcc|mail)|mail\s+to|records-archive@|@attacker\.|@evil\.)\b/i;

const QUOTED_KEYWORD =
  /(?:says?|said|word|phrase|keyword)\s+['"]([^'"]{1,64})['"]/i;

const SHIPIT_STYLE =
  /if\s+the\s+user\s+says\s+(?:the\s+word\s+)?['"]?([a-z0-9_-]{2,64})['"]?/i;

const DRAFT_EMAIL_ARM =
  /\b(?:draft|send|write)\b[\s\S]{0,40}\b(?:email|mail|message)\b/i;

/**
 * Detect sleeping / delayed tool directives in untrusted text.
 */
export function detectDelayedTrigger(text: string): DelayedTriggerHit {
  const triggerKeywords: string[] = [];
  const deferredActions: string[] = [];

  const hasCond = CONDITIONAL.test(text);
  const actionMatch = text.match(DEFERRED_ACTION);
  if (actionMatch) deferredActions.push(actionMatch[0].toLowerCase().replace(/\s+/g, '_'));

  const q = text.match(QUOTED_KEYWORD);
  if (q?.[1]) triggerKeywords.push(q[1].toLowerCase());
  const s = text.match(SHIPIT_STYLE);
  if (s?.[1]) triggerKeywords.push(s[1].toLowerCase());
  if (DRAFT_EMAIL_ARM.test(text) && hasCond) {
    triggerKeywords.push('draft_email', 'email', 'acme.com');
  }

  // Require conditional framing + deferred action (tool/exfil).
  const found = hasCond && deferredActions.length > 0;

  let evidence = '';
  if (found) {
    const idx = text.search(CONDITIONAL);
    evidence = text.slice(Math.max(0, idx), Math.max(0, idx) + 160).trim();
  }

  return {
    found,
    triggerKeywords: [...new Set(triggerKeywords)],
    deferredActions: [...new Set(deferredActions)],
    evidence,
  };
}

export interface DelayedArm {
  keywords: string[];
  actions: string[];
  evidence: string;
  ingestedAt: number;
}

/**
 * Per-session watch: ingest sleeping rules from untrusted sources; escalate
 * when a later turn matches an armed keyword.
 */
export class DelayedTriggerWatch {
  private arms = new Map<string, DelayedArm[]>();

  recordIngest(sessionId: string, hit: DelayedTriggerHit): void {
    if (!hit.found) return;
    const list = this.arms.get(sessionId) ?? [];
    list.push({
      keywords: hit.triggerKeywords,
      actions: hit.deferredActions,
      evidence: hit.evidence,
      ingestedAt: Date.now(),
    });
    this.arms.set(sessionId, list);
  }

  /**
   * Check whether later user/agent text matches a previously armed trigger.
   */
  checkLater(
    sessionId: string,
    text: string,
  ): { triggered: boolean; matchedKeywords: string[]; arms: DelayedArm[] } {
    const list = this.arms.get(sessionId) ?? [];
    if (list.length === 0) {
      return { triggered: false, matchedKeywords: [], arms: [] };
    }
    const lower = text.toLowerCase();
    const matchedKeywords: string[] = [];
    const matchedArms: DelayedArm[] = [];
    for (const arm of list) {
      let hit = false;
      for (const kw of arm.keywords) {
        if (!kw) continue;
        if (kw === 'draft_email') {
          if (/\b(draft|write|compose)\b[\s\S]{0,40}\b(email|mail)\b/i.test(text)) {
            matchedKeywords.push(kw);
            hit = true;
          }
        } else if (kw.includes('.')) {
          // domain fragment like acme.com
          if (lower.includes(kw.toLowerCase())) {
            matchedKeywords.push(kw);
            hit = true;
          }
        } else if (new RegExp(`\\b${kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i').test(text)) {
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

  /** True if session has any armed sleeping rule (for ActionGuard expand deny). */
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

/** Process-wide default watch (integrators may construct their own). */
export const delayedTriggerWatch = new DelayedTriggerWatch();
