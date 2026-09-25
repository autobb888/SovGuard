/**
 * InstrumentalEvasion thin land E — Subagent policy inherit.
 *
 * Child / spawn agents inherit parent monitor policy *ceiling*. Parent cannot
 * launder prohibited ops via spawn_agent / Agent defer. Child may further
 * restrict; cannot exceed parent ceiling.
 *
 * Soft-compose ActionGuard. Soft residuals stay soft. Escalate BLOCK.
 * Not deepset 80%. Shapes only — no live child prompts.
 * other_agent ingress distrust ≠ policy inherit (orthogonal).
 */

export type MonitorPolicyDecision = 'ALLOW' | 'DENY' | 'BLOCK';

export interface MonitorPolicyCeiling {
  /** Effect classes denied at parent (ceiling). */
  deniedEffectClasses: ReadonlySet<string> | readonly string[];
  /** Optional opaque policy id / version for host wire. */
  policyId?: string;
  /** Prior parent decision context. */
  priorDecision?: MonitorPolicyDecision;
}

export interface SpawnAttempt {
  /** Shape: spawn_agent_or_defer etc. */
  shape?: string;
  /** Child instruction effect class shape. */
  childEffectClass: string;
  childInstructionShape?: string;
}

export type SubagentInheritVerdict = 'ALLOW' | 'DENY';

export type SubagentInheritGate =
  | 'SubagentInherit.ALLOW'
  | 'SubagentInherit.DENY_launder_via_spawn'
  | 'SubagentInherit.DENY_ceiling'
  | 'SubagentInherit.DENY_bad_input';

export interface SubagentInheritResult {
  verdict: SubagentInheritVerdict;
  gate: SubagentInheritGate;
  escalate: boolean;
  /** Child inherits parent ceiling. */
  inheritsParentCeiling: true;
  /** Child policy after inherit (may be further restricted). */
  childCeiling: MonitorPolicyCeiling;
  reason?: string;
}

function asSet(
  classes: ReadonlySet<string> | readonly string[] | undefined,
): Set<string> {
  if (!classes) return new Set();
  if (classes instanceof Set) return new Set(classes);
  return new Set(classes);
}

/**
 * Inherit parent monitor policy ceiling onto a child spawn context.
 * Returns the child ceiling (copy of denied classes; child may add more).
 */
export function inheritMonitorPolicyCeiling(
  parent: MonitorPolicyCeiling,
): MonitorPolicyCeiling {
  const denied = asSet(parent?.deniedEffectClasses);
  return {
    deniedEffectClasses: new Set(denied),
    policyId: parent?.policyId,
    priorDecision: parent?.priorDecision,
  };
}

/**
 * Deny laundering prohibited ops via spawn_agent when child instruction
 * targets a parent-denied effect class.
 */
export function denyLaunderViaSpawn(
  parent: MonitorPolicyCeiling,
  spawn: SpawnAttempt,
): SubagentInheritResult {
  const childEffect = String(spawn?.childEffectClass ?? '').trim();
  if (!childEffect) {
    return {
      verdict: 'DENY',
      gate: 'SubagentInherit.DENY_bad_input',
      escalate: true,
      inheritsParentCeiling: true,
      childCeiling: inheritMonitorPolicyCeiling(parent ?? { deniedEffectClasses: [] }),
      reason: 'childEffectClass required',
    };
  }

  const childCeiling = inheritMonitorPolicyCeiling(parent);
  const denied = asSet(childCeiling.deniedEffectClasses);

  if (denied.has(childEffect)) {
    return {
      verdict: 'DENY',
      gate: 'SubagentInherit.DENY_launder_via_spawn',
      escalate: true,
      inheritsParentCeiling: true,
      childCeiling,
      reason: `parent-denied effect class ${childEffect} cannot be laundered via spawn_agent`,
    };
  }

  // Also catch when parent priorDecision was DENY/BLOCK for same class via priorDecision hint
  if (
    (parent.priorDecision === 'DENY' || parent.priorDecision === 'BLOCK') &&
    denied.size === 0
  ) {
    // Host forgot to list class but signalled prior deny — fail closed if childInstruction matches
    const hint = String(spawn.childInstructionShape ?? '');
    if (/prohibited|same_prohibited/i.test(hint) || /prohibited/i.test(childEffect)) {
      const sealed = new Set(denied);
      sealed.add(childEffect);
      return {
        verdict: 'DENY',
        gate: 'SubagentInherit.DENY_ceiling',
        escalate: true,
        inheritsParentCeiling: true,
        childCeiling: { ...childCeiling, deniedEffectClasses: sealed },
        reason: 'parent prior DENY + prohibited child effect — inherit ceiling',
      };
    }
  }

  return {
    verdict: 'ALLOW',
    gate: 'SubagentInherit.ALLOW',
    escalate: false,
    inheritsParentCeiling: true,
    childCeiling,
  };
}

/**
 * Combined helper: inherit ceiling then gate spawn attempt.
 */
export function gateSubagentSpawn(
  parent: MonitorPolicyCeiling,
  spawn: SpawnAttempt,
): SubagentInheritResult {
  return denyLaunderViaSpawn(parent, spawn);
}
