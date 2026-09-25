/**
 * ApprovalLaundering thin land B — Closure witness Eff ⊆ Rep.
 *
 * Post-run observed effects must ⊆ approved representation (frozen Pred₆).
 * Unexplained residual → pause / re-ASK (no silent expand).
 * Ambient tmp/telemetry may be allowlisted; high-risk Ω₆ residual must pause.
 *
 * Compose with EffectBoundRecord; do not treat entry digest match as closure.
 * Escalate BLOCK. Not deepset 80%. Shapes only.
 */

import type { EffectBoundRecord, Omega6Class } from './effect-bound-record.js';
import { OMEGA6_CLASSES } from './effect-bound-record.js';

export type AmbientResidualClass = 'tmp' | 'telemetry' | 'cache' | 'log_rotate';

export const DEFAULT_AMBIENT_ALLOWLIST: readonly AmbientResidualClass[] = [
  'tmp',
  'telemetry',
  'cache',
  'log_rotate',
] as const;

/**
 * High-risk Ω₆ that never silent-expand as "ambient" when outside Rep.
 * file/env ambient tmp/telemetry may allowlist (FP mitigation).
 */
export const HIGH_RISK_OMEGA6: readonly Omega6Class[] = [
  'network',
  'process',
  'container',
  'MCP',
] as const;

export interface ObservedEffect {
  /** Ω₆ class of the observed effect. */
  omega6Class: Omega6Class;
  /** Optional ambient subclass (tmp / telemetry / …). */
  ambientClass?: AmbientResidualClass | string | null;
  /** Host shape label (no live payloads). */
  shape?: string;
  /** Explicit mark that this residual is unexplained vs Rep. */
  unexplained?: boolean;
}

export type ClosureVerdict =
  | 'CLOSED'
  | 'PAUSE_REASK'
  | 'AMBIENT_ALLOWLISTED'
  | 'DENY_bad_input';

export type ClosureWitnessGate =
  | 'ClosureWitness.CLOSED'
  | 'ClosureWitness.PAUSE_REASK_residual'
  | 'ClosureWitness.AMBIENT_ALLOWLISTED'
  | 'ClosureWitness.DENY_bad_input';

export interface ClosureWitnessResult {
  verdict: ClosureVerdict;
  gate: ClosureWitnessGate;
  /** Eff ⊆ Rep held (ambient allowlist counts as closed for that residual). */
  effSubseteqRep: boolean;
  /** True when host must pause / re-ASK (no silent expand). */
  pauseOrReAsk: boolean;
  /** Silent expand forbidden always on unexplained high-risk residual. */
  silentExpand: false;
  escalate: boolean;
  residual?: ObservedEffect[];
  ambientAllowed?: ObservedEffect[];
  reason?: string;
}

export interface ClosureWitnessOptions {
  /** Ambient residual classes permitted without re-ASK (default DEFAULT). */
  ambientAllowlist?: readonly (AmbientResidualClass | string)[];
  /**
   * Ω₆ that must pause/re-ASK when outside Rep (never waive via ambient label).
   * Default: network / process / container / MCP.
   */
  highRiskClasses?: readonly Omega6Class[];
}

function isOmega6(c: unknown): c is Omega6Class {
  return typeof c === 'string' && (OMEGA6_CLASSES as readonly string[]).includes(c);
}

/**
 * Assert observed Eff ⊆ approved Rep (frozen omega6Classes).
 * Unexplained / out-of-Rep high-risk → PAUSE_REASK.
 * Ambient tmp/telemetry on allowlist → AMBIENT_ALLOWLISTED (no HITL storm).
 */
export function assertEffSubseteqRep(
  rep: EffectBoundRecord | null | undefined,
  observed: readonly ObservedEffect[] | null | undefined,
  opts?: ClosureWitnessOptions,
): ClosureWitnessResult {
  const silentExpand = false as const;

  if (!rep || !rep.frozenBeforeAllow || !Array.isArray(rep.omega6Classes)) {
    return {
      verdict: 'DENY_bad_input',
      gate: 'ClosureWitness.DENY_bad_input',
      effSubseteqRep: false,
      pauseOrReAsk: true,
      silentExpand,
      escalate: true,
      reason: 'closure requires frozen EffectBoundRecord Rep',
    };
  }

  const approved = new Set(rep.omega6Classes);
  const ambientAllow = new Set(
    (opts?.ambientAllowlist ?? DEFAULT_AMBIENT_ALLOWLIST).map(String),
  );
  const highRisk = new Set<Omega6Class>(
    opts?.highRiskClasses ?? HIGH_RISK_OMEGA6,
  );

  const effects = Array.isArray(observed) ? observed : [];
  const residual: ObservedEffect[] = [];
  const ambientAllowed: ObservedEffect[] = [];

  for (const eff of effects) {
    if (!eff || !isOmega6(eff.omega6Class)) {
      residual.push(eff ?? { omega6Class: 'process', unexplained: true });
      continue;
    }

    const inRep = approved.has(eff.omega6Class);
    const hasAmbient =
      eff.ambientClass != null &&
      String(eff.ambientClass).length > 0 &&
      ambientAllow.has(String(eff.ambientClass));

    // In Rep and not marked unexplained → covered.
    if (inRep && eff.unexplained !== true) {
      continue;
    }

    // High-risk outside Rep (or unexplained high-risk) → always pause/re-ASK.
    // Ambient label must NOT waive network/process/container/MCP.
    if (highRisk.has(eff.omega6Class) && (!inRep || eff.unexplained === true)) {
      residual.push({ ...eff, unexplained: true });
      continue;
    }

    // Ambient tmp/telemetry (file/env class) → allowlist; no HITL storm.
    if (hasAmbient) {
      ambientAllowed.push(eff);
      continue;
    }

    // Unexplained or outside Rep, non-ambient → pause/re-ASK.
    if (!inRep || eff.unexplained === true) {
      residual.push({ ...eff, unexplained: true });
    }
  }

  if (residual.length > 0) {
    return {
      verdict: 'PAUSE_REASK',
      gate: 'ClosureWitness.PAUSE_REASK_residual',
      effSubseteqRep: false,
      pauseOrReAsk: true,
      silentExpand,
      escalate: true,
      residual,
      ambientAllowed: ambientAllowed.length ? ambientAllowed : undefined,
      reason:
        'Eff ⊈ Rep — unexplained residual; pause / re-ASK (no silent expand)',
    };
  }

  if (ambientAllowed.length > 0 && effects.every((e) => {
    const hasAmbient =
      e.ambientClass != null &&
      ambientAllow.has(String(e.ambientClass));
    return hasAmbient || approved.has(e.omega6Class);
  })) {
    // Pure ambient extras (and any in-Rep) → ambient allowlisted closure.
    if (effects.every((e) => !approved.has(e.omega6Class))) {
      return {
        verdict: 'AMBIENT_ALLOWLISTED',
        gate: 'ClosureWitness.AMBIENT_ALLOWLISTED',
        effSubseteqRep: true,
        pauseOrReAsk: false,
        silentExpand,
        escalate: false,
        ambientAllowed,
        reason: 'ambient tmp/telemetry allowlisted; Eff ⊆ Rep under policy',
      };
    }
  }

  return {
    verdict: 'CLOSED',
    gate: 'ClosureWitness.CLOSED',
    effSubseteqRep: true,
    pauseOrReAsk: false,
    silentExpand,
    escalate: false,
    ambientAllowed: ambientAllowed.length ? ambientAllowed : undefined,
    reason: 'Eff ⊆ Rep — closure held',
  };
}

/** Alias matching acceptance wording. */
export const assertClosureWitness = assertEffSubseteqRep;
