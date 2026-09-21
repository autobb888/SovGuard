/**
 * PMPA MemoryWriteGate (thin land) — durable preference/rule persist from
 * untrusted content requires explicit user confirm.
 *
 * A: MemoryWriteGate — mid-doc remember/store-in-memory alone → NO_DURABLE_WRITE
 * B: PreferenceRule provenance — {sourceSession, contentTrust, origin}; recall → untrusted for AG/KPI-C
 * C: Side-recipient bind composed in action-guard (invitees/cc/bcc/sync ⊆ argAllowlist)
 *
 * KPI = durable write-gate + post-retrieve egress. Not deepset 80%.
 * Not lexicon-primary. Compose CPE SourceTrust; keep GhostSplice/Deadbugz/Loopjacking no-worsen.
 * Soft residual: host must wire memory-write hook.
 */

import { randomUUID } from 'node:crypto';

/** Provenance stamped on every durable PreferenceRule. */
export interface PreferenceRuleProvenance {
  /** Session that originated the write attempt / confirm. */
  sourceSession?: string;
  /**
   * Trust of the content that proposed the rule.
   * `untrusted` → recall path treats as untrusted for AG/KPI-C.
   * `user_confirmed` → written via explicit user confirm API.
   */
  contentTrust: 'untrusted' | 'user_confirmed' | 'user' | 'trusted';
  /** Origin channel (user | external_doc | mcp_result | …). */
  origin: string;
}

export interface PreferenceRule {
  id: string;
  text: string;
  provenance: PreferenceRuleProvenance;
  createdAt: number;
}

export type MemoryWriteGateVerdict =
  | 'NO_DURABLE_WRITE'
  | 'NO_TRIP'
  | 'ALLOW_AFTER_CONFIRM'
  | 'PENDING_CONFIRM';

export interface MemoryWriteAttempt {
  /** Session id for provenance. */
  sessionId?: string;
  /** Role of the content proposing the write (user | untrusted_content | …). */
  role?: string;
  /** Raw text that may contain a memory-write request. */
  text: string;
  /**
   * Host declares the operator explicitly confirmed "save this preference".
   * Required for durable write — mid-doc remember alone never suffices.
   */
  explicitConfirm?: boolean;
  /** Optional rule text override (defaults to full attempt text). */
  ruleText?: string;
  /** Optional origin override (defaults from role). */
  origin?: string;
}

export interface MemoryWriteGateResult {
  verdict: MemoryWriteGateVerdict;
  /** True only when a PreferenceRule was persisted. */
  durableWrite: boolean;
  rule?: PreferenceRule;
  reason?: string;
  /** True when text looks like a memory-write / preference-save attempt. */
  writeIntent: boolean;
  /** Detected write-intent labels (shapes only; not lexicon-primary defense). */
  signals: string[];
}

/** Side-recipient arg names that must ⊆ TrustedPlan argAllowlist under untrusted preference recall. */
export const SIDE_RECIPIENT_ARGS = [
  'invitees',
  'cc',
  'bcc',
  'sync',
  'syncTargets',
  'sync_targets',
  'shareWith',
  'share_with',
  'attendees',
] as const;

const SIDE_RECIPIENT_SET = new Set<string>(
  SIDE_RECIPIENT_ARGS.map((s) => s.toLowerCase()),
);

export function isSideRecipientArg(name: string): boolean {
  return SIDE_RECIPIENT_SET.has(name.toLowerCase());
}

/**
 * Soft write-intent detectors — classify gate trips vs NO_TRIP only.
 * Defense is the confirm gate, NOT lexicon expand (acceptance: not lexicon-primary).
 */
const WRITE_INTENT_PATTERNS: Array<{ re: RegExp; label: string }> = [
  { re: /\bremember\s+this\s+requirement\b/i, label: 'remember_requirement' },
  { re: /\bremember\s+this\b/i, label: 'remember_this' },
  { re: /\bstore\s+(this\s+)?in\s+(the\s+|your\s+)?memory\b/i, label: 'store_in_memory' },
  { re: /\badd\s+to\s+(your\s+|the\s+)?long[-\s]?term\s+memory\b/i, label: 'add_long_term_memory' },
  { re: /\bsave\s+this\s+preference\b/i, label: 'save_preference' },
  { re: /\bplease\s+save\s+this\s+preference\b/i, label: 'please_save_preference' },
  { re: /\bpersist\s+(this\s+)?(preference|rule)\b/i, label: 'persist_preference' },
];

export function detectMemoryWriteIntent(text: string): { writeIntent: boolean; signals: string[] } {
  const signals: string[] = [];
  for (const { re, label } of WRITE_INTENT_PATTERNS) {
    if (re.test(text)) signals.push(label);
  }
  return { writeIntent: signals.length > 0, signals };
}

function isUserRole(role: string | undefined): boolean {
  if (!role) return false;
  const r = role.toLowerCase();
  return r === 'user' || r === 'operator' || r === 'trusted_user';
}

function defaultOrigin(role: string | undefined, origin?: string): string {
  if (origin) return origin;
  if (isUserRole(role)) return 'user';
  if (!role || role === 'untrusted_content') return 'external_doc';
  return role;
}

/**
 * Decide whether a proposed durable preference write may persist.
 * Mid-doc remember from untrusted → NO_DURABLE_WRITE (no confirm).
 * Explicit user save + confirm → ALLOW_AFTER_CONFIRM + persist.
 * No write-intent → NO_TRIP (no false gate).
 */
export function memoryWriteGate(
  attempt: MemoryWriteAttempt,
  store?: PreferenceRuleStore,
): MemoryWriteGateResult {
  const { writeIntent, signals } = detectMemoryWriteIntent(attempt.text);

  if (!writeIntent) {
    return {
      verdict: 'NO_TRIP',
      durableWrite: false,
      writeIntent: false,
      signals: [],
      reason: 'no memory-write verb — gate does not trip',
    };
  }

  // ONLY durable-write when role=user AND explicitConfirm=true.
  if (!(isUserRole(attempt.role) && attempt.explicitConfirm === true)) {
    return {
      verdict: 'NO_DURABLE_WRITE',
      durableWrite: false,
      writeIntent: true,
      signals,
      reason:
        'durable preference/rule from untrusted or unconfirmed source — explicit user confirm required; mid-doc remember alone → no write',
    };
  }

  const provenance: PreferenceRuleProvenance = {
    sourceSession: attempt.sessionId,
    contentTrust: 'user_confirmed',
    origin: defaultOrigin(attempt.role, attempt.origin),
  };

  const rule: PreferenceRule = {
    id: randomUUID(),
    text: (attempt.ruleText ?? attempt.text).trim(),
    provenance,
    createdAt: Date.now(),
  };

  if (store) {
    store.put(rule);
  }

  return {
    verdict: 'ALLOW_AFTER_CONFIRM',
    durableWrite: true,
    rule,
    writeIntent: true,
    signals,
    reason: 'explicit user save preference — confirm path ALLOW',
  };
}

/**
 * On recall into the act path: PreferenceRules with untrusted / non-user_confirmed
 * contentTrust are untrusted origin for AG/KPI-C (compose CPE SourceTrust).
 */
export function preferenceRuleActTrust(
  rule: PreferenceRule | PreferenceRuleProvenance,
): {
  contentTrust: string;
  untrustedForAct: boolean;
  /** Suggested ActionGuard / CPE source tag. */
  actSource: string;
} {
  const p: PreferenceRuleProvenance =
    'provenance' in rule ? rule.provenance : rule;
  const ct = p.contentTrust;
  const untrustedForAct =
    ct === 'untrusted' ||
    (ct !== 'user_confirmed' && ct !== 'user' && ct !== 'trusted');
  return {
    contentTrust: ct,
    untrustedForAct,
    actSource: untrustedForAct
      ? `preference_rule:${p.origin || 'external_doc'}`
      : 'user',
  };
}

/** In-memory PreferenceRule store (host may swap durable backend). */
export class PreferenceRuleStore {
  private rules = new Map<string, PreferenceRule>();

  put(rule: PreferenceRule): void {
    this.rules.set(rule.id, rule);
  }

  get(id: string): PreferenceRule | undefined {
    return this.rules.get(id);
  }

  /** Inject a forced-poison rule for tests / harness (stamps provenance as-given). */
  inject(
    rule: Omit<PreferenceRule, 'id' | 'createdAt'> & { id?: string; createdAt?: number },
  ): PreferenceRule {
    const full: PreferenceRule = {
      id: rule.id ?? randomUUID(),
      text: rule.text,
      provenance: rule.provenance,
      createdAt: rule.createdAt ?? Date.now(),
    };
    this.put(full);
    return full;
  }

  list(): PreferenceRule[] {
    return [...this.rules.values()];
  }

  /** Rules recalled for a session act path (host may filter). */
  recall(): PreferenceRule[] {
    return this.list();
  }

  clear(): void {
    this.rules.clear();
  }

  size(): number {
    return this.rules.size;
  }
}

/**
 * Collect side-recipient values present on proposed tool args.
 * Used by ActionGuard side-recipient bind (C).
 */
export function collectSideRecipients(
  args: Record<string, unknown> | undefined,
): Array<{ arg: string; values: string[] }> {
  if (!args) return [];
  const out: Array<{ arg: string; values: string[] }> = [];
  for (const [k, v] of Object.entries(args)) {
    if (!isSideRecipientArg(k)) continue;
    const values: string[] = [];
    if (typeof v === 'string') values.push(v);
    else if (Array.isArray(v)) {
      for (const el of v) {
        if (typeof el === 'string') values.push(el);
      }
    }
    out.push({ arg: k, values });
  }
  return out;
}
