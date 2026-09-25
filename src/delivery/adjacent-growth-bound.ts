/**
 * PersistentBillable thin land C — D2 AdjacentGrowthBound (Δp).
 *
 * Bound adjacent prompt-growth; delayed / stealth padding still trips.
 *
 * Compose with D1 TokenMassBound and PreReingestionGate.
 * Soft C-DoS owned on PersistentBillable track. Escalate BLOCK. Not deepset 80%.
 * Shapes only — no DoW PoC/kit.
 */

export type AdjacentGrowthVerdict = 'ALLOW' | 'HITL' | 'DENY_GROWTH';

export type AdjacentGrowthGateId =
  | 'D2AdjacentGrowth.ALLOW'
  | 'D2AdjacentGrowth.HITL'
  | 'D2AdjacentGrowth.DENY_GROWTH'
  | 'D2AdjacentGrowth.DENY_bad_input';

export interface AdjacentGrowthConfig {
  /** Max absolute Δp tokens between adjacent turns (default 2048). */
  maxDeltaTokens?: number;
  /** Max Δp as ratio of prior prompt mass (default 0.5). */
  maxDeltaRatio?: number;
  /** Escalate HITL before hard DENY (default true). */
  escalateBeforeDeny?: boolean;
  /**
   * When true (default), delayed/stealth growth still trips — evaluate Δp
   * against last *observed* prompt mass even if growth was spread over turns.
   */
  tripDelayedStealth?: boolean;
}

export interface AdjacentGrowthCheckInput {
  sessionId: string;
  /** Prompt token mass this turn. */
  promptTokenMass: number;
  /**
   * Explicit delayed/stealth signal from host morph/padding detector.
   * When set, forces evaluation even if absolute Δp looks small this turn
   * (cumulative stealth still trips via store baseline).
   */
  delayedOrStealthSignal?: boolean;
  /** Optional morph signal (representation change) — still trips Δp. */
  representationChanged?: boolean;
  config?: AdjacentGrowthConfig;
}

export interface AdjacentGrowthCheckResult {
  verdict: AdjacentGrowthVerdict;
  gate: AdjacentGrowthGateId;
  deltaTokens: number;
  deltaRatio: number;
  priorPromptTokenMass: number;
  promptTokenMass: number;
  delayedOrStealthTripped: boolean;
  reason?: string;
  escalate: boolean;
}

export interface SessionAdjacentGrowthStats {
  lastPromptTokenMass: number;
  /** Earliest / baseline mass for stealth cumulative Δp. */
  baselinePromptTokenMass: number;
  turns: number;
  escalations: number;
  /** Cumulative positive growth from baseline (stealth catch). */
  cumulativeGrowthFromBaseline: number;
}

const DEFAULT_CONFIG: Required<AdjacentGrowthConfig> = {
  maxDeltaTokens: 2048,
  maxDeltaRatio: 0.5,
  escalateBeforeDeny: true,
  tripDelayedStealth: true,
};

function mergeConfig(c?: AdjacentGrowthConfig): Required<AdjacentGrowthConfig> {
  return { ...DEFAULT_CONFIG, ...c };
}

/** Per-session adjacent Δp counters (D2). */
export class AdjacentGrowthBoundStore {
  private stats = new Map<string, SessionAdjacentGrowthStats>();

  get(sessionId: string): SessionAdjacentGrowthStats {
    return (
      this.stats.get(sessionId) ?? {
        lastPromptTokenMass: 0,
        baselinePromptTokenMass: 0,
        turns: 0,
        escalations: 0,
        cumulativeGrowthFromBaseline: 0,
      }
    );
  }

  record(sessionId: string, promptTokenMass: number): SessionAdjacentGrowthStats {
    const cur = this.get(sessionId);
    if (cur.turns === 0) {
      cur.baselinePromptTokenMass = Math.max(0, promptTokenMass);
      cur.lastPromptTokenMass = cur.baselinePromptTokenMass;
    } else {
      const growth = Math.max(0, promptTokenMass - cur.lastPromptTokenMass);
      cur.cumulativeGrowthFromBaseline = Math.max(
        0,
        promptTokenMass - cur.baselinePromptTokenMass,
      );
      cur.lastPromptTokenMass = Math.max(0, promptTokenMass);
      void growth;
    }
    cur.turns += 1;
    this.stats.set(sessionId, cur);
    return { ...cur };
  }

  markEscalated(sessionId: string): SessionAdjacentGrowthStats {
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
 * Check D2 adjacent prompt-growth (Δp). Delayed/stealth padding still trips
 * via cumulative growth from baseline and/or explicit stealth signals.
 */
export function checkAdjacentGrowthBound(
  store: AdjacentGrowthBoundStore,
  input: AdjacentGrowthCheckInput,
): AdjacentGrowthCheckResult {
  if (!input?.sessionId) {
    return {
      verdict: 'DENY_GROWTH',
      gate: 'D2AdjacentGrowth.DENY_bad_input',
      deltaTokens: 0,
      deltaRatio: 0,
      priorPromptTokenMass: 0,
      promptTokenMass: 0,
      delayedOrStealthTripped: false,
      escalate: true,
      reason: 'sessionId required for D2 adjacent growth bound',
    };
  }

  const cfg = mergeConfig(input.config);
  const cur = store.get(input.sessionId);
  const mass = Math.max(0, input.promptTokenMass);
  const prior = cur.turns === 0 ? mass : cur.lastPromptTokenMass;
  const deltaTokens = Math.max(0, mass - prior);
  const deltaRatio = prior > 0 ? deltaTokens / prior : deltaTokens > 0 ? 1 : 0;

  // Stealth / delayed: cumulative from baseline OR explicit signal.
  const cumulative =
    cur.turns === 0 ? 0 : Math.max(0, mass - cur.baselinePromptTokenMass);
  const stealthSignal =
    !!input.delayedOrStealthSignal || !!input.representationChanged;
  const delayedOrStealthTripped =
    cfg.tripDelayedStealth &&
    (stealthSignal ||
      cumulative > cfg.maxDeltaTokens ||
      (cur.baselinePromptTokenMass > 0 &&
        cumulative / cur.baselinePromptTokenMass > cfg.maxDeltaRatio));

  const overAdjacent =
    deltaTokens > cfg.maxDeltaTokens || deltaRatio > cfg.maxDeltaRatio;
  const over = overAdjacent || delayedOrStealthTripped;

  if (!over) {
    return {
      verdict: 'ALLOW',
      gate: 'D2AdjacentGrowth.ALLOW',
      deltaTokens,
      deltaRatio,
      priorPromptTokenMass: prior,
      promptTokenMass: mass,
      delayedOrStealthTripped: false,
      escalate: false,
    };
  }

  const reason = delayedOrStealthTripped && !overAdjacent
    ? `D2 delayed/stealth growth trip: cumulativeΔ=${cumulative} from baseline ${cur.baselinePromptTokenMass}` +
      (stealthSignal ? ' (explicit morph/delay signal)' : '')
    : `D2 adjacent Δp trip: Δ=${deltaTokens} ratio=${deltaRatio.toFixed(2)} (max ${cfg.maxDeltaTokens}/${cfg.maxDeltaRatio})`;

  if (cfg.escalateBeforeDeny && cur.escalations === 0) {
    return {
      verdict: 'HITL',
      gate: 'D2AdjacentGrowth.HITL',
      deltaTokens: Math.max(deltaTokens, cumulative),
      deltaRatio,
      priorPromptTokenMass: prior,
      promptTokenMass: mass,
      delayedOrStealthTripped,
      reason: `${reason} → HITL`,
      escalate: true,
    };
  }

  return {
    verdict: 'DENY_GROWTH',
    gate: 'D2AdjacentGrowth.DENY_GROWTH',
    deltaTokens: Math.max(deltaTokens, cumulative),
    deltaRatio,
    priorPromptTokenMass: prior,
    promptTokenMass: mass,
    delayedOrStealthTripped,
    reason: `${reason} → DENY growth`,
    escalate: true,
  };
}

/** Check then record on ALLOW; markEscalated on HITL; DENY does not advance baseline unfairly (still records mass for continuity). */
export function gateAdjacentGrowthBound(
  store: AdjacentGrowthBoundStore,
  input: AdjacentGrowthCheckInput,
): AdjacentGrowthCheckResult {
  const check = checkAdjacentGrowthBound(store, input);
  if (check.verdict === 'ALLOW') {
    store.record(input.sessionId, input.promptTokenMass);
  } else if (check.verdict === 'HITL') {
    store.markEscalated(input.sessionId);
    // Still record mass so delayed stealth continues to track.
    store.record(input.sessionId, input.promptTokenMass);
  }
  return check;
}
