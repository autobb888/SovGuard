/**
 * DL-008 — Delayed / sleeping trigger detection (+ ExplosivePrompt widen).
 * Instruction-like conditionals in untrusted memory/CRM/notes
 * (`if/when` + later action + deferred state-changing tool) look inert at ingest
 * but activate later (esp. benign conversational closings).
 *
 * EP thin land: detect **conditional structure** (shapes > phrase lists) —
 * natural closings (thanks/bye/goodbye/finish) + deferred tools beyond Crowdstrike
 * send_email/bcc lexicon. Preserve CRM BCC baseline.
 *
 * Always run detectDelayedTrigger on Unicode fixed-point text so Tags/ZW cannot
 * hide sleeping rules.
 */
import { normalizeToFixedPoint } from './regex.js';

/** Structured arm kinds — draft_email plus EP deferred tool kinds. */
export type DelayedArmType =
  | 'draft_email'
  | 'send_email'
  | 'transfer_funds'
  | 'create_pr'
  | 'send_message'
  | 'state_changing_tool';

export interface DelayedTriggerHit {
  found: boolean;
  /** Keywords/phrases extracted from ingest (never fixture hardcodes). */
  triggerKeywords: string[];
  /**
   * Structured arm kinds (e.g. draft_email) — not bare words like "email".
   * Used by checkLater for semantic match without arming the word "email".
   */
  armTypes: DelayedArmType[];
  /** Deferred tool/exfil actions mentioned (bcc, send_email, transfer_funds, …). */
  deferredActions: string[];
  evidence: string;
  /**
   * True when the conditional uses a natural conversational closing as the
   * trigger (thanks / bye / goodbye / finish / ends). EP diagnostic.
   */
  naturalClosing?: boolean;
}

/**
 * Conditional structure: if/when + deferred/trigger cue.
 * Includes natural closings (EP) — not Crowdstrike phrase-list-only.
 */
const CONDITIONAL =
  /\b(when|if)\b[\s\S]{0,180}?\b(later|asked|asks|ask|says?|said|draft|email|message|word|phrase|keyword|thanks|thank\s+you|bye|goodbye|good[\s-]?bye|finish(?:es|ed)?|ends?|ending|closing|conversation|done|complete|polite)\b/i;

/**
 * Deferred state-changing / exfil actions.
 * Structure: exfil lexicon OR named state-changing tools OR "use the X tool".
 * Not bare "forward" alone (benign mailing-list FP).
 */
const DEFERRED_ACTION =
  /\b(bcc|send[_ ]?email|exfiltrat\w*|also\s+(?:send|bcc|mail)|records-archive@|(?:[a-z0-9._%+-]+@(?:attacker|evil)\.[a-z]{2,})|transfer[_ ]?funds?|create[_ ]?pr|send[_ ]?message|wire[_ ]?transfer|messaging(?:\s+api)?)\b/i;

/** "use / call / invoke the <tool> tool" — structure, not fixed phrase list. */
const USE_TOOL =
  /\b(?:use|call|invoke|run|execute)\s+(?:the\s+)?([a-z][a-z0-9_]{1,64})(?:\s+tool)?\b/i;

/** via <tool> / with <tool> */
const VIA_TOOL =
  /\b(?:via|with|using)\s+(?:the\s+)?(send[_ ]?email|transfer[_ ]?funds?|create[_ ]?pr|send[_ ]?message|draft[_ ]?email)\b/i;

const QUOTED_KEYWORD =
  /(?:says?|said|word|phrase|keyword)\s+['"]([^'"]{1,64})['"]/i;

/** if/when the user says [the word] shipit — quoted or bare token */
const SAYS_KEYWORD =
  /\b(?:if|when)\b[\s\S]{0,40}?\b(?:the\s+user\s+)?(?:says?|said)\b(?:\s+the\s+word)?\s+['"]?([a-z0-9_-]{2,64})['"]?/i;

const DRAFT_EMAIL_ARM =
  /\b(?:draft|send|write)\b[\s\S]{0,40}\b(?:email|mail|message)\b/i;

/** Natural conversational closings used as EP triggers. */
const NATURAL_CLOSING =
  /\b(thanks|thank\s+you|bye|goodbye|good[\s-]?bye|finish(?:es|ed)?|ends?(?:\s+with)?|closing|polite\s+goodbye)\b/i;

const CLOSING_KEYWORD_EXTRACT =
  /\b(thanks|thank\s+you|bye|goodbye|good[\s-]?bye|finish|shipit)\b/gi;

/** Domains mentioned as @host in the ingest text. */
const AT_DOMAIN = /@([a-z0-9.-]+\.[a-z]{2,})/gi;

/** Known state-changing tool name normalizer. */
const TOOL_ALIASES: Record<string, DelayedArmType> = {
  send_email: 'send_email',
  sendemail: 'send_email',
  'send email': 'send_email',
  draft_email: 'draft_email',
  transfer_funds: 'transfer_funds',
  transferfunds: 'transfer_funds',
  'transfer funds': 'transfer_funds',
  create_pr: 'create_pr',
  createpr: 'create_pr',
  'create pr': 'create_pr',
  send_message: 'send_message',
  sendmessage: 'send_message',
  'send message': 'send_message',
  messaging: 'send_message',
  messaging_api: 'send_message',
  wire_transfer: 'transfer_funds',
};

function extractDomains(text: string): string[] {
  const out: string[] = [];
  let m: RegExpExecArray | null;
  const re = new RegExp(AT_DOMAIN.source, 'gi');
  while ((m = re.exec(text)) !== null) {
    out.push(m[1].toLowerCase());
  }
  return [...new Set(out)];
}

function normalizeToolToken(raw: string): string {
  return raw.toLowerCase().replace(/\s+/g, '_').replace(/-/g, '_');
}

function armTypeForTool(token: string): DelayedArmType | null {
  const n = normalizeToolToken(token);
  if (TOOL_ALIASES[n]) return TOOL_ALIASES[n];
  if (TOOL_ALIASES[token.toLowerCase()]) return TOOL_ALIASES[token.toLowerCase()];
  // Unknown but tool-shaped identifier after "use the X tool"
  if (/^[a-z][a-z0-9_]{2,64}$/.test(n) && !BENIGN_TOOL_WORDS.has(n)) {
    return 'state_changing_tool';
  }
  return null;
}

/** Words that appear after "use the X" but are not state-changing tools. */
const BENIGN_TOOL_WORDS = new Set([
  'word',
  'phrase',
  'keyword',
  'following',
  'above',
  'below',
  'same',
  'next',
  'previous',
  'user',
  'assistant',
  'system',
  'context',
  'summary',
  'note',
  'notes',
  'format',
  'style',
  'tone',
  'template',
]);

function extractDeferredTools(fp: string): string[] {
  const out: string[] = [];
  const actionMatch = fp.match(DEFERRED_ACTION);
  if (actionMatch) {
    out.push(normalizeToolToken(actionMatch[0]));
  }
  const use = fp.match(USE_TOOL);
  if (use?.[1]) {
    const t = normalizeToolToken(use[1]);
    if (!BENIGN_TOOL_WORDS.has(t)) out.push(t);
  }
  const via = fp.match(VIA_TOOL);
  if (via?.[1]) {
    out.push(normalizeToolToken(via[1]));
  }
  return [...new Set(out)];
}

/**
 * Detect sleeping / delayed tool directives in text.
 * Input is normalized to Unicode fixed-point before matching.
 * Detects **conditional structure** (if/when + deferred state-changing tool),
 * including natural closings — not phrase-list-only.
 */
export function detectDelayedTrigger(text: string): DelayedTriggerHit {
  const fp = normalizeToFixedPoint(text).text;
  const triggerKeywords: string[] = [];
  const armTypes: DelayedArmType[] = [];
  const deferredActions: string[] = [];

  const hasCond = CONDITIONAL.test(fp);
  const tools = extractDeferredTools(fp);
  for (const t of tools) deferredActions.push(t);

  const q = fp.match(QUOTED_KEYWORD);
  if (q?.[1]) triggerKeywords.push(q[1].toLowerCase());
  const says = fp.match(SAYS_KEYWORD);
  if (says?.[1]) {
    const kw = says[1].toLowerCase();
    // Avoid treating closings captured by SAYS_KEYWORD as fake "says X" when
    // the utterance is the closing itself — still record as keyword.
    if (!['the', 'a', 'an', 'to'].includes(kw)) triggerKeywords.push(kw);
  }

  // Natural closing triggers (EP) — arm the closing words as keywords
  const naturalClosing = hasCond && NATURAL_CLOSING.test(fp);
  if (naturalClosing) {
    let cm: RegExpExecArray | null;
    const cre = new RegExp(CLOSING_KEYWORD_EXTRACT.source, 'gi');
    while ((cm = cre.exec(fp)) !== null) {
      const kw = cm[1].toLowerCase().replace(/\s+/g, ' ');
      // Normalize thank you → thanks for matching short closings
      if (kw === 'thank you') triggerKeywords.push('thanks');
      else if (kw === 'good bye' || kw === 'good-bye') triggerKeywords.push('goodbye');
      else triggerKeywords.push(kw === 'goodbye' ? 'goodbye' : kw);
    }
  }

  // Domains only if literally present in ingest (e.g. @acme.com) — never hardcode.
  for (const d of extractDomains(fp)) {
    triggerKeywords.push(d);
  }

  if (DRAFT_EMAIL_ARM.test(fp) && hasCond && deferredActions.length > 0) {
    armTypes.push('draft_email');
  }
  for (const t of deferredActions) {
    const at = armTypeForTool(t);
    if (at && at !== 'draft_email') armTypes.push(at);
    else if (at === 'draft_email' && !armTypes.includes('draft_email')) {
      armTypes.push('draft_email');
    }
    // Also map bcc/exfil-ish to send_email arm when draft_email already present
    if (/^bcc$|^exfil|^also_send|^records-archive@|@attacker\.|@evil\./i.test(t)) {
      if (!armTypes.includes('send_email') && !armTypes.includes('draft_email')) {
        armTypes.push('send_email');
      }
    }
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
    naturalClosing: found && !!naturalClosing,
  };
}

export interface DelayedArm {
  keywords: string[];
  armTypes: DelayedArmType[];
  actions: string[];
  evidence: string;
  ingestedAt: number;
  /**
   * Source trust at plant ingest. Untrusted plants bind at ActionGuard;
   * user / user_confirmed / HITL do not (G4 ALLOW).
   */
  sourceTrust?: string;
}

/** Trust labels that clear / skip plant-provenance bind (user-authored / HITL). */
export function isTrustedPlantSource(sourceTrust: string | undefined): boolean {
  if (!sourceTrust) return false;
  const s = sourceTrust.toLowerCase();
  return (
    s === 'user' ||
    s === 'user_confirmed' ||
    s === 'user_chat' ||
    s === 'trusted' ||
    s === 'hitl' ||
    s === 'explicit_confirm'
  );
}

/**
 * Per-session watch: ingest sleeping rules from untrusted sources; escalate
 * when a later turn matches an armed keyword or structured arm type.
 * EP: natural closings + plant-provenance arms for ActionGuard bind.
 */
export class DelayedTriggerWatch {
  private arms = new Map<string, DelayedArm[]>();

  recordIngest(
    sessionId: string,
    hit: DelayedTriggerHit,
    opts?: { sourceTrust?: string },
  ): void {
    if (!hit.found) return;
    // G4: user-authored / HITL conditionals do not arm plant bind
    if (isTrustedPlantSource(opts?.sourceTrust)) return;
    const list = this.arms.get(sessionId) ?? [];
    list.push({
      keywords: hit.triggerKeywords,
      armTypes: hit.armTypes,
      actions: hit.deferredActions,
      evidence: hit.evidence,
      ingestedAt: Date.now(),
      sourceTrust: opts?.sourceTrust ?? 'untrusted',
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
        } else if (
          new RegExp(
            `\\b${kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`,
            'i',
          ).test(fp)
        ) {
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

  /** Arms recorded for a session (plant provenance for AG bind). */
  getArms(sessionId: string): DelayedArm[] {
    return [...(this.arms.get(sessionId) ?? [])];
  }

  hasArms(sessionId: string): boolean {
    return (this.arms.get(sessionId) ?? []).length > 0;
  }

  /**
   * True when proposed tool name matches any armed deferred action / armType
   * from an untrusted plant (EP act-bind).
   */
  matchesDeferredTool(sessionId: string, toolName: string): DelayedArm[] {
    const list = this.arms.get(sessionId) ?? [];
    const n = normalizeToolToken(toolName);
    const matched: DelayedArm[] = [];
    for (const arm of list) {
      if (isTrustedPlantSource(arm.sourceTrust)) continue;
      const actionHit = arm.actions.some((a) => {
        const an = normalizeToolToken(a);
        return an === n || an.includes(n) || n.includes(an);
      });
      const typeHit = arm.armTypes.some((t) => t === n || normalizeToolToken(t) === n);
      if (actionHit || typeHit) matched.push(arm);
    }
    return matched;
  }

  clear(sessionId: string): void {
    this.arms.delete(sessionId);
  }

  clearAll(): void {
    this.arms.clear();
  }
}

export const delayedTriggerWatch = new DelayedTriggerWatch();

/**
 * EP plant-provenance bind helper (used by ActionGuard).
 * Proposed tool matching armed deferred action from untrusted ingest → DENY.
 * Closing utterance alone is insufficient (caller still needs tool fire).
 * Open TrustedPlan does not clear the bind — return deny reason.
 * User / HITL SourceTrust → null (ALLOW).
 */
export function denyDelayedPlantBind(
  toolName: string,
  opts: {
    watch?: DelayedTriggerWatch;
    sessionId?: string;
    /** Explicit arms (tests / host without session wiring). */
    plantArms?: DelayedArm[];
    /** Act-time SourceTrust / HITL confirm — clears bind. */
    SourceTrust?: string;
    sourceTrust?: string;
    hitlConfirm?: boolean;
  },
): string | null {
  const trust = opts.SourceTrust ?? opts.sourceTrust;
  if (opts.hitlConfirm === true || isTrustedPlantSource(trust)) {
    return null;
  }
  const arms =
    opts.plantArms ??
    (opts.watch && opts.sessionId ? opts.watch.getArms(opts.sessionId) : []);
  if (!arms.length) return null;

  const n = normalizeToolToken(toolName);
  for (const arm of arms) {
    if (isTrustedPlantSource(arm.sourceTrust)) continue;
    const actionHit = arm.actions.some((a) => {
      const an = normalizeToolToken(a);
      return an === n || an.includes(n) || n.includes(an.replace(/^also_/, ''));
    });
    const typeHit = arm.armTypes.some(
      (t) => t === n || normalizeToolToken(String(t)) === n,
    );
    // Also: draft_email arm binds send_email / draft_email tool fire
    const draftBind =
      arm.armTypes.includes('draft_email') &&
      (n === 'send_email' || n === 'draft_email');
    if (actionHit || typeHit || draftBind) {
      return `delayed_plant_bind: tool "${toolName}" matches untrusted delayed-trigger plant (actions=[${arm.actions.join(',')}]) — DENY / escalate (open TrustedPlan insufficient; closing alone insufficient)`;
    }
  }
  return null;
}
