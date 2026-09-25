/**
 * PersistentBillable thin land F — Polymorphic / stealth trip.
 *
 * Representation-changing or delayed-growth padding must still trip
 * growth (D2) or spend (D4). Helper forces D2/D4 evaluation on morph/delay signals.
 *
 * Compose with AdjacentGrowthBoundStore + CumulativeSpendStore.
 * Soft C-DoS owned on PersistentBillable track. Escalate BLOCK. Not deepset 80%.
 * Shapes only — no DoW PoC/kit / no polymorphic payload recipes.
 */

import {
  AdjacentGrowthBoundStore,
  checkAdjacentGrowthBound,
  gateAdjacentGrowthBound,
  type AdjacentGrowthCheckResult,
  type AdjacentGrowthConfig,
} from './adjacent-growth-bound.js';
import {
  CumulativeSpendStore,
  checkCumulativeSpend,
  gateCumulativeSpend,
  type CumulativeSpendCheckResult,
  type CumulativeSpendConfig,
} from './cumulative-spend.js';

export type PolymorphicStealthVerdict =
  | 'ALLOW'
  | 'TRIP_GROWTH'
  | 'TRIP_SPEND'
  | 'TRIP_BOTH'
  | 'HITL';

export type PolymorphicStealthGateId =
  | 'PolymorphicStealth.ALLOW'
  | 'PolymorphicStealth.TRIP_GROWTH'
  | 'PolymorphicStealth.TRIP_SPEND'
  | 'PolymorphicStealth.TRIP_BOTH'
  | 'PolymorphicStealth.HITL'
  | 'PolymorphicStealth.DENY_bad_input';

export interface PolymorphicStealthSignal {
  /** Representation-changing padding (encoding / morph / rewrite). */
  representationChanged?: boolean;
  /** Delayed-growth padding spread across turns. */
  delayedGrowth?: boolean;
  /** Host morph detector fired (shape-level). */
  morphDetected?: boolean;
}

export interface PolymorphicStealthTripInput {
  sessionId: string;
  promptTokenMass: number;
  proposedSpend: number;
  signal: PolymorphicStealthSignal;
  growthConfig?: AdjacentGrowthConfig;
  spendConfig?: CumulativeSpendConfig;
  /** When true (default), mutate stores via gate*; else check-only. */
  applyGates?: boolean;
}

export interface PolymorphicStealthTripResult {
  verdict: PolymorphicStealthVerdict;
  gate: PolymorphicStealthGateId;
  growth: AdjacentGrowthCheckResult;
  spend: CumulativeSpendCheckResult;
  /** True when morph/delay signal forced D2/D4 evaluation. */
  forcedEvaluation: boolean;
  reason?: string;
  escalate: boolean;
}

/**
 * Force D2/D4 evaluation when representation-changing or delayed-growth
 * signals are present. Exact-string match on prior padding form is NOT required —
 * morph still trips via signal + mass/spend counters.
 */
export function tripPolymorphicStealth(
  growthStore: AdjacentGrowthBoundStore,
  spendStore: CumulativeSpendStore,
  input: PolymorphicStealthTripInput,
): PolymorphicStealthTripResult {
  if (!input?.sessionId) {
    const emptyGrowth = checkAdjacentGrowthBound(growthStore, {
      sessionId: '',
      promptTokenMass: 0,
    });
    const emptySpend = checkCumulativeSpend(spendStore, {
      sessionId: '',
      proposedSpend: 0,
    });
    return {
      verdict: 'HITL',
      gate: 'PolymorphicStealth.DENY_bad_input',
      growth: emptyGrowth,
      spend: emptySpend,
      forcedEvaluation: false,
      escalate: true,
      reason: 'sessionId required for polymorphic/stealth trip',
    };
  }

  const sig = input.signal ?? {};
  const morph =
    !!sig.representationChanged || !!sig.delayedGrowth || !!sig.morphDetected;
  const apply = input.applyGates !== false;

  const growthInput = {
    sessionId: input.sessionId,
    promptTokenMass: input.promptTokenMass,
    delayedOrStealthSignal: !!sig.delayedGrowth || !!sig.morphDetected,
    representationChanged: !!sig.representationChanged || !!sig.morphDetected,
    config: input.growthConfig,
  };

  const spendInput = {
    sessionId: input.sessionId,
    proposedSpend: input.proposedSpend,
    config: input.spendConfig,
  };

  const growth = apply
    ? gateAdjacentGrowthBound(growthStore, growthInput)
    : checkAdjacentGrowthBound(growthStore, growthInput);
  const spend = apply
    ? gateCumulativeSpend(spendStore, spendInput)
    : checkCumulativeSpend(spendStore, spendInput);

  const growthTripped =
    growth.verdict === 'HITL' ||
    growth.verdict === 'DENY_GROWTH' ||
    growth.delayedOrStealthTripped;
  const spendTripped =
    spend.verdict === 'HITL' || spend.verdict === 'DENY_SPEND';

  // When morph signal present but counters have not yet tripped (e.g. first
  // morph with small Δ), still force HITL so representation-change cannot evade.
  if (morph && !growthTripped && !spendTripped) {
    return {
      verdict: 'HITL',
      gate: 'PolymorphicStealth.HITL',
      growth,
      spend,
      forcedEvaluation: true,
      escalate: true,
      reason:
        'polymorphic/stealth signal present — forced D2/D4 evaluation; HITL (no exact-string match required)',
    };
  }

  if (growthTripped && spendTripped) {
    return {
      verdict: 'TRIP_BOTH',
      gate: 'PolymorphicStealth.TRIP_BOTH',
      growth,
      spend,
      forcedEvaluation: morph,
      escalate: true,
      reason: 'polymorphic/stealth still trips growth AND spend',
    };
  }

  if (growthTripped) {
    return {
      verdict: 'TRIP_GROWTH',
      gate: 'PolymorphicStealth.TRIP_GROWTH',
      growth,
      spend,
      forcedEvaluation: morph,
      escalate: true,
      reason: 'polymorphic/stealth still trips D2 growth (no exact-string match required)',
    };
  }

  if (spendTripped) {
    return {
      verdict: 'TRIP_SPEND',
      gate: 'PolymorphicStealth.TRIP_SPEND',
      growth,
      spend,
      forcedEvaluation: morph,
      escalate: true,
      reason: 'polymorphic/stealth still trips D4 spend',
    };
  }

  return {
    verdict: 'ALLOW',
    gate: 'PolymorphicStealth.ALLOW',
    growth,
    spend,
    forcedEvaluation: morph,
    escalate: false,
    reason: morph
      ? 'morph signal noted; D2/D4 within bounds this turn'
      : 'no morph/delay signal; D2/D4 within bounds',
  };
}

/**
 * Convenience: evaluate morph/delay signals against growth-only (when spend N/A).
 */
export function forceGrowthEvalOnMorph(
  growthStore: AdjacentGrowthBoundStore,
  opts: {
    sessionId: string;
    promptTokenMass: number;
    signal: PolymorphicStealthSignal;
    config?: AdjacentGrowthConfig;
  },
): AdjacentGrowthCheckResult {
  return gateAdjacentGrowthBound(growthStore, {
    sessionId: opts.sessionId,
    promptTokenMass: opts.promptTokenMass,
    delayedOrStealthSignal:
      !!opts.signal.delayedGrowth || !!opts.signal.morphDetected,
    representationChanged:
      !!opts.signal.representationChanged || !!opts.signal.morphDetected,
    config: opts.config,
  });
}
