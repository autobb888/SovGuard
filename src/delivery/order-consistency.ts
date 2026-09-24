/**
 * ChronosAttack / Tool Order thin land B — Order-consistency abstain / HITL.
 *
 * For m=3 observations evaluate all 6 permutations via a provided
 * `decide(order)` callback. If max vote ≥ 4 → ALLOW with majority choice;
 * else ABSTAIN / HITL.
 *
 * Soft residual (NOT this land): m>3 vote cost opt-in; schedule-sensitivity
 * profiles per model.
 *
 * KPI = ≥4/6 agree else ABSTAIN. Not deepset 80%. Escalate BLOCK.
 * Shapes only — do not clone ChronosAttack kit.
 */

import type { ToolObservation } from './decision-step-barrier.js';
import { compareCanonical } from './decision-step-barrier.js';

export type OrderConsistencyVerdict = 'ALLOW' | 'ABSTAIN' | 'HITL';

export type OrderConsistencyGate =
  | 'OrderConsistency.ALLOW_majority'
  | 'OrderConsistency.ABSTAIN_below_threshold'
  | 'OrderConsistency.HITL_below_threshold'
  | 'OrderConsistency.DENY_bad_input';

export interface OrderConsistencyConfig {
  /**
   * Minimum votes for majority ALLOW (default 4 of 6 for m=3).
   * Paper defense: ≥4/6 permutations agree else abstain.
   */
  minMajorityVotes?: number;
  /**
   * When true (default), below-threshold → HITL (escalate-before-deny style).
   * When false → plain ABSTAIN.
   */
  hitlOnAbstain?: boolean;
}

export interface OrderConsistencyResult {
  verdict: OrderConsistencyVerdict;
  gate: OrderConsistencyGate;
  /** Majority choice when ALLOW; undefined on abstain. */
  choice?: string;
  /** Vote counts keyed by decide() return value. */
  votes: Record<string, number>;
  maxVotes: number;
  permutationCount: number;
  minMajorityVotes: number;
  /** Each perm's decide outcome (audit). */
  outcomes: Array<{ orderIds: string[]; choice: string }>;
  reason?: string;
}

const DEFAULT_MIN_MAJORITY = 4;

/** Generate all permutations of a shallow-copied array. */
export function permutations<T>(items: T[]): T[][] {
  if (items.length <= 1) return [items.slice()];
  const out: T[][] = [];
  for (let i = 0; i < items.length; i++) {
    const head = items[i];
    const rest = items.slice(0, i).concat(items.slice(i + 1));
    for (const p of permutations(rest)) {
      out.push([head, ...p]);
    }
  }
  return out;
}

/**
 * Evaluate order-consistency over all permutations of `observations`.
 * Designed for m=3 → 6 perms; works for other m (soft: cost scales with m!).
 *
 * `decide(order)` returns a choice string for that presentation order.
 * Caller supplies a deterministic decision oracle (fixture / model shim).
 */
export function evaluateOrderConsistency(
  observations: ToolObservation[],
  decide: (order: ToolObservation[]) => string,
  config?: OrderConsistencyConfig,
): OrderConsistencyResult {
  const minMajority = config?.minMajorityVotes ?? DEFAULT_MIN_MAJORITY;
  const hitlOnAbstain = config?.hitlOnAbstain !== false;

  if (!Array.isArray(observations) || observations.length === 0) {
    return {
      verdict: 'ABSTAIN',
      gate: 'OrderConsistency.DENY_bad_input',
      votes: {},
      maxVotes: 0,
      permutationCount: 0,
      minMajorityVotes: minMajority,
      outcomes: [],
      reason: 'empty observations',
    };
  }
  if (typeof decide !== 'function') {
    return {
      verdict: 'ABSTAIN',
      gate: 'OrderConsistency.DENY_bad_input',
      votes: {},
      maxVotes: 0,
      permutationCount: 0,
      minMajorityVotes: minMajority,
      outcomes: [],
      reason: 'decide callback required',
    };
  }

  const perms = permutations(observations);
  const votes: Record<string, number> = {};
  const outcomes: Array<{ orderIds: string[]; choice: string }> = [];

  for (const order of perms) {
    const choice = String(decide(order) ?? '');
    votes[choice] = (votes[choice] ?? 0) + 1;
    outcomes.push({
      orderIds: order.map((o) => o.id),
      choice,
    });
  }

  let maxVotes = 0;
  let majorityChoice: string | undefined;
  for (const [choice, n] of Object.entries(votes)) {
    if (n > maxVotes) {
      maxVotes = n;
      majorityChoice = choice;
    }
  }

  if (maxVotes >= minMajority && majorityChoice !== undefined) {
    return {
      verdict: 'ALLOW',
      gate: 'OrderConsistency.ALLOW_majority',
      choice: majorityChoice,
      votes,
      maxVotes,
      permutationCount: perms.length,
      minMajorityVotes: minMajority,
      outcomes,
    };
  }

  const verdict: OrderConsistencyVerdict = hitlOnAbstain ? 'HITL' : 'ABSTAIN';
  return {
    verdict,
    gate: hitlOnAbstain
      ? 'OrderConsistency.HITL_below_threshold'
      : 'OrderConsistency.ABSTAIN_below_threshold',
    votes,
    maxVotes,
    permutationCount: perms.length,
    minMajorityVotes: minMajority,
    outcomes,
    reason: `maxVotes ${maxVotes} < ${minMajority} — order-sensitive; abstain/HITL`,
  };
}

/**
 * Convenience: decide using canonical order as the sole presentation
 * (barrier-on path). Still useful as a control when voting is skipped.
 */
export function decideCanonicalOnly(
  observations: ToolObservation[],
  decide: (order: ToolObservation[]) => string,
): string {
  const ordered = [...observations].sort(compareCanonical);
  return String(decide(ordered) ?? '');
}
