/**
 * PersistentBillable thin land B — D1 TokenMassBound.
 *
 * Bound retained tool-return + prompt token mass across turns.
 * Trip → compress harder / HITL / DENY further retention.
 *
 * Compose with ToolCallBudgetStore (volume ≠ mass) and PreReingestionGate.
 * Soft C-DoS owned on PersistentBillable track. Escalate BLOCK. Not deepset 80%.
 * Shapes only — no DoW PoC/kit.
 */

export type TokenMassVerdict =
  | 'ALLOW'
  | 'COMPRESS_HARDER'
  | 'HITL'
  | 'DENY_FURTHER_RETENTION';

export type TokenMassGateId =
  | 'D1TokenMass.ALLOW'
  | 'D1TokenMass.COMPRESS_HARDER'
  | 'D1TokenMass.HITL'
  | 'D1TokenMass.DENY_FURTHER_RETENTION'
  | 'D1TokenMass.DENY_bad_input';

export interface TokenMassBoundConfig {
  /** Max retained tool-return tokens across turns (default 8192). */
  maxRetainedToolTokens?: number;
  /** Max prompt token mass (prompt + retained) across turns (default 32768). */
  maxPromptTokenMass?: number;
  /** Soft trip ratio (0–1) before HITL (default 0.85). */
  softTripRatio?: number;
  /** Escalate (HITL/compress) before hard DENY (default true). */
  escalateBeforeDeny?: boolean;
}

export interface TokenMassRecordInput {
  sessionId: string;
  /** Estimated tokens from retained tool returns this turn. */
  retainedToolTokens: number;
  /** Estimated total prompt tokens this turn (incl. retained). */
  promptTokenMass: number;
}

export interface TokenMassCheckInput {
  sessionId: string;
  /** Proposed additional retained tool tokens this turn. */
  proposedRetainedToolTokens: number;
  /** Proposed total prompt token mass after fold. */
  proposedPromptTokenMass: number;
  config?: TokenMassBoundConfig;
}

export interface TokenMassCheckResult {
  verdict: TokenMassVerdict;
  gate: TokenMassGateId;
  retainedToolTokens: number;
  promptTokenMass: number;
  maxRetainedToolTokens: number;
  maxPromptTokenMass: number;
  reason?: string;
  escalate: boolean;
}

export interface SessionTokenMassStats {
  retainedToolTokens: number;
  promptTokenMass: number;
  /** Peak prompt mass observed. */
  peakPromptTokenMass: number;
  turns: number;
  escalations: number;
}

const DEFAULT_CONFIG: Required<TokenMassBoundConfig> = {
  maxRetainedToolTokens: 8192,
  maxPromptTokenMass: 32768,
  softTripRatio: 0.85,
  escalateBeforeDeny: true,
};

function mergeConfig(c?: TokenMassBoundConfig): Required<TokenMassBoundConfig> {
  return { ...DEFAULT_CONFIG, ...c };
}

/**
 * Per-session retained tool-return + prompt token mass counters (D1).
 * Orthogonal to ToolCallBudgetStore same-tool volume.
 */
export class TokenMassBoundStore {
  private stats = new Map<string, SessionTokenMassStats>();

  get(sessionId: string): SessionTokenMassStats {
    return (
      this.stats.get(sessionId) ?? {
        retainedToolTokens: 0,
        promptTokenMass: 0,
        peakPromptTokenMass: 0,
        turns: 0,
        escalations: 0,
      }
    );
  }

  /** Record after ALLOW / COMPRESS_HARDER applied retention. */
  record(input: TokenMassRecordInput): SessionTokenMassStats {
    const cur = this.get(input.sessionId);
    cur.retainedToolTokens += Math.max(0, input.retainedToolTokens);
    cur.promptTokenMass = Math.max(0, input.promptTokenMass);
    cur.peakPromptTokenMass = Math.max(cur.peakPromptTokenMass, cur.promptTokenMass);
    cur.turns += 1;
    this.stats.set(input.sessionId, cur);
    return { ...cur };
  }

  /** Replace retained mass after compress/tombstone (shrink). */
  setRetained(sessionId: string, retainedToolTokens: number, promptTokenMass: number): SessionTokenMassStats {
    const cur = this.get(sessionId);
    cur.retainedToolTokens = Math.max(0, retainedToolTokens);
    cur.promptTokenMass = Math.max(0, promptTokenMass);
    cur.peakPromptTokenMass = Math.max(cur.peakPromptTokenMass, cur.promptTokenMass);
    this.stats.set(sessionId, cur);
    return { ...cur };
  }

  markEscalated(sessionId: string): SessionTokenMassStats {
    const cur = this.get(sessionId);
    cur.escalations += 1;
    this.stats.set(sessionId, cur);
    return { ...cur };
  }

  clear(sessionId?: string): void {
    if (!sessionId) {
      this.stats.clear();
      return;
    }
    this.stats.delete(sessionId);
  }

  size(): number {
    return this.stats.size;
  }
}

/**
 * Check D1 token mass bound. Does NOT mutate store.
 * Trip → COMPRESS_HARDER / HITL / DENY_FURTHER_RETENTION.
 */
export function checkTokenMassBound(
  store: TokenMassBoundStore,
  input: TokenMassCheckInput,
): TokenMassCheckResult {
  if (!input?.sessionId) {
    return {
      verdict: 'DENY_FURTHER_RETENTION',
      gate: 'D1TokenMass.DENY_bad_input',
      retainedToolTokens: 0,
      promptTokenMass: 0,
      maxRetainedToolTokens: DEFAULT_CONFIG.maxRetainedToolTokens,
      maxPromptTokenMass: DEFAULT_CONFIG.maxPromptTokenMass,
      escalate: true,
      reason: 'sessionId required for D1 token mass bound',
    };
  }

  const cfg = mergeConfig(input.config);
  const cur = store.get(input.sessionId);
  const retained =
    cur.retainedToolTokens + Math.max(0, input.proposedRetainedToolTokens);
  const promptMass = Math.max(0, input.proposedPromptTokenMass);
  const softRetained = cfg.maxRetainedToolTokens * cfg.softTripRatio;
  const softPrompt = cfg.maxPromptTokenMass * cfg.softTripRatio;

  const overHard =
    retained > cfg.maxRetainedToolTokens || promptMass > cfg.maxPromptTokenMass;
  const overSoft =
    retained > softRetained || promptMass > softPrompt;

  if (!overSoft && !overHard) {
    return {
      verdict: 'ALLOW',
      gate: 'D1TokenMass.ALLOW',
      retainedToolTokens: retained,
      promptTokenMass: promptMass,
      maxRetainedToolTokens: cfg.maxRetainedToolTokens,
      maxPromptTokenMass: cfg.maxPromptTokenMass,
      escalate: false,
    };
  }

  const reason = overHard
    ? `D1 token mass hard trip: retained=${retained}/${cfg.maxRetainedToolTokens} prompt=${promptMass}/${cfg.maxPromptTokenMass}`
    : `D1 token mass soft trip: retained=${retained} prompt=${promptMass} (ratio>${cfg.softTripRatio})`;

  if (cfg.escalateBeforeDeny && cur.escalations === 0) {
    return {
      verdict: overHard ? 'HITL' : 'COMPRESS_HARDER',
      gate: overHard ? 'D1TokenMass.HITL' : 'D1TokenMass.COMPRESS_HARDER',
      retainedToolTokens: retained,
      promptTokenMass: promptMass,
      maxRetainedToolTokens: cfg.maxRetainedToolTokens,
      maxPromptTokenMass: cfg.maxPromptTokenMass,
      reason: `${reason} → compress harder / HITL`,
      escalate: true,
    };
  }

  if (cfg.escalateBeforeDeny && cur.escalations === 1 && !overHard) {
    return {
      verdict: 'HITL',
      gate: 'D1TokenMass.HITL',
      retainedToolTokens: retained,
      promptTokenMass: promptMass,
      maxRetainedToolTokens: cfg.maxRetainedToolTokens,
      maxPromptTokenMass: cfg.maxPromptTokenMass,
      reason: `${reason} → HITL after prior compress`,
      escalate: true,
    };
  }

  return {
    verdict: 'DENY_FURTHER_RETENTION',
    gate: 'D1TokenMass.DENY_FURTHER_RETENTION',
    retainedToolTokens: retained,
    promptTokenMass: promptMass,
    maxRetainedToolTokens: cfg.maxRetainedToolTokens,
    maxPromptTokenMass: cfg.maxPromptTokenMass,
    reason: `${reason} → DENY further retention`,
    escalate: true,
  };
}

/**
 * Check then record on ALLOW; markEscalated on COMPRESS_HARDER/HITL;
 * DENY does not grow retention counters.
 */
export function gateTokenMassBound(
  store: TokenMassBoundStore,
  input: TokenMassCheckInput & {
    /** When ALLOW, record these (default = proposed). */
    recordRetainedToolTokens?: number;
    recordPromptTokenMass?: number;
  },
): TokenMassCheckResult {
  const check = checkTokenMassBound(store, input);
  if (check.verdict === 'ALLOW') {
    store.record({
      sessionId: input.sessionId,
      retainedToolTokens:
        input.recordRetainedToolTokens ?? input.proposedRetainedToolTokens,
      promptTokenMass: input.recordPromptTokenMass ?? input.proposedPromptTokenMass,
    });
  } else if (
    check.verdict === 'COMPRESS_HARDER' ||
    check.verdict === 'HITL'
  ) {
    store.markEscalated(input.sessionId);
  }
  return check;
}

/** Rough char→token estimate (≈4 chars/token) for hosts without a tokenizer. */
export function estimateTokensFromChars(chars: number): number {
  return Math.ceil(Math.max(0, chars) / 4);
}
