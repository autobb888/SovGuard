/**
 * ApprovalLaundering thin land D — Install→lifecycle predict.
 *
 * Package install / add approvals must predict postinstall / file / network
 * lifecycle. Frozen-lockfile / fixed-SHA does not erase residual when hooks remain.
 *
 * Compose with EffectBoundRecord Pred₆; Soft-compose ApprovalBinding entry bind.
 * Escalate BLOCK. Not deepset 80%. Shapes only — no live install/hook scripts.
 */

import type { Omega6Class } from './effect-bound-record.js';
import {
  freezePred6BeforeAllow,
  type EffectBoundRecord,
  type FreezePred6Result,
} from './effect-bound-record.js';

export type InstallAction =
  | 'npm_install'
  | 'npm_add'
  | 'pnpm_install'
  | 'pnpm_add'
  | 'yarn_add'
  | 'yarn_install'
  | 'pip_install'
  | 'package_install'
  | 'package_add'
  | string;

export interface InstallApproveAttempt {
  action: InstallAction;
  /** Frozen lockfile present (npm ci / frozen-lockfile). */
  lockfileFrozen?: boolean;
  /** Fixed SHA / integrity pin present. */
  fixedSha?: boolean;
  /** Lifecycle hooks still remain (postinstall / prepare / etc.). */
  hooksRemain?: boolean;
  /** Explicit hook names (shape-level). */
  hookNames?: readonly string[];
  /** package.json / lockfile / hooks content for provenance freeze. */
  packageJsonContent?: string | null;
  lockfileContent?: string | null;
  hooksContent?: string | null;
  /** Optional companion entry digest. */
  entryDigest?: string | null;
  approvalId?: string | null;
}

export type InstallLifecycleGate =
  | 'InstallLifecycle.PREDICTED'
  | 'InstallLifecycle.REQUIRE_LIFECYCLE_PRED'
  | 'InstallLifecycle.DENY_lockfile_alone'
  | 'InstallLifecycle.ALLOW_no_hooks'
  | 'InstallLifecycle.DENY_bad_input';

export interface InstallLifecyclePredictResult {
  ok: boolean;
  lifecyclePredicted: boolean;
  /** Frozen-lockfile / fixed-SHA alone never sufficient when hooks remain. */
  lockfileAloneSufficient: false;
  predictedClasses: Omega6Class[];
  hooksRemain: boolean;
  gate: InstallLifecycleGate;
  escalate: boolean;
  reason?: string;
  effectBound?: EffectBoundRecord;
  freeze?: FreezePred6Result;
}

const LIFECYCLE_HOOK_NAMES = new Set([
  'preinstall',
  'install',
  'postinstall',
  'prepublish',
  'prepare',
  'preprepare',
  'postprepare',
  'bindings',
]);

/**
 * Predict postinstall / file / network lifecycle classes for an install/add.
 * When hooks remain, lockfileFrozen + fixedSha do NOT clear residual.
 */
export function predictInstallLifecycle(
  attempt: InstallApproveAttempt,
): InstallLifecyclePredictResult {
  const lockfileAloneSufficient = false as const;

  if (!attempt || !attempt.action) {
    return {
      ok: false,
      lifecyclePredicted: false,
      lockfileAloneSufficient,
      predictedClasses: [],
      hooksRemain: false,
      gate: 'InstallLifecycle.DENY_bad_input',
      escalate: true,
      reason: 'install approve attempt.action required',
    };
  }

  const hookNames = (attempt.hookNames ?? []).map((h) =>
    String(h).trim().toLowerCase(),
  );
  const hooksFromNames = hookNames.some((h) => LIFECYCLE_HOOK_NAMES.has(h));
  const hooksRemain =
    attempt.hooksRemain === true ||
    hooksFromNames ||
    (attempt.hooksContent != null && String(attempt.hooksContent).length > 0);

  // Always predict lifecycle classes for install/add shapes.
  const predictedClasses: Omega6Class[] = hooksRemain
    ? ['process', 'file', 'network']
    : ['process', 'file'];

  // No hooks → lockfile/fixed-SHA path may ALLOW without network residual demand.
  if (!hooksRemain) {
    const freeze = freezePred6BeforeAllow({
      omega6Classes: predictedClasses,
      provenance: buildProv(attempt),
      entryDigest: attempt.entryDigest,
      approvalId: attempt.approvalId,
      notes: 'install/add with no remaining hooks — lifecycle Pred₆ still frozen',
    });
    return {
      ok: freeze.ok,
      lifecyclePredicted: true,
      lockfileAloneSufficient,
      predictedClasses,
      hooksRemain: false,
      gate: 'InstallLifecycle.ALLOW_no_hooks',
      escalate: !freeze.ok,
      reason: 'no hooks remain — Pred₆ process/file frozen; network optional',
      effectBound: freeze.record,
      freeze,
    };
  }

  // Hooks remain: frozen-lockfile / fixed-SHA do NOT erase residual.
  const lockfileClaim =
    attempt.lockfileFrozen === true || attempt.fixedSha === true;

  const freeze = freezePred6BeforeAllow({
    omega6Classes: predictedClasses,
    provenance: buildProv(attempt),
    entryDigest: attempt.entryDigest,
    approvalId: attempt.approvalId,
    notes:
      'install/add hooks remain — predict postinstall/file/network; lockfile alone insufficient',
  });

  if (!freeze.ok || !freeze.record) {
    return {
      ok: false,
      lifecyclePredicted: false,
      lockfileAloneSufficient,
      predictedClasses,
      hooksRemain: true,
      gate: 'InstallLifecycle.REQUIRE_LIFECYCLE_PRED',
      escalate: true,
      reason: freeze.reason ?? 'failed to freeze install lifecycle Pred₆',
      freeze,
    };
  }

  if (lockfileClaim) {
    // Explicitly mark that lockfile alone is not enough — but prediction succeeded.
    return {
      ok: true,
      lifecyclePredicted: true,
      lockfileAloneSufficient,
      predictedClasses,
      hooksRemain: true,
      gate: 'InstallLifecycle.PREDICTED',
      escalate: false,
      reason:
        'hooks remain — postinstall/file/network Pred₆ required; frozen-lockfile/fixed-SHA does not erase residual',
      effectBound: freeze.record,
      freeze,
    };
  }

  return {
    ok: true,
    lifecyclePredicted: true,
    lockfileAloneSufficient,
    predictedClasses,
    hooksRemain: true,
    gate: 'InstallLifecycle.PREDICTED',
    escalate: false,
    reason: 'install/add lifecycle Pred₆ predicted (postinstall/file/network)',
    effectBound: freeze.record,
    freeze,
  };
}

function buildProv(
  attempt: InstallApproveAttempt,
): Parameters<typeof freezePred6BeforeAllow>[0]['provenance'] {
  const p: NonNullable<Parameters<typeof freezePred6BeforeAllow>[0]['provenance']> =
    {};
  if (attempt.packageJsonContent != null) {
    p['package.json'] = attempt.packageJsonContent;
  }
  if (attempt.lockfileContent != null) {
    p.lockfile = attempt.lockfileContent;
  }
  if (attempt.hooksContent != null) {
    p.hooks = attempt.hooksContent;
  }
  return Object.keys(p).length ? p : undefined;
}

/**
 * Gate: refuse ALLOW when hooks remain and lifecycle was not predicted on card.
 * `lifecyclePredictedOnCard` is host assertion that Pred₆ includes lifecycle classes.
 */
export function gateInstallLifecycleApprove(
  attempt: InstallApproveAttempt,
  lifecyclePredictedOnCard?: boolean | null,
): InstallLifecyclePredictResult {
  const predicted = predictInstallLifecycle(attempt);
  if (!predicted.hooksRemain) {
    return predicted;
  }

  // Host says card already has lifecycle Pred₆.
  if (lifecyclePredictedOnCard === true && predicted.ok) {
    return predicted;
  }

  if (lifecyclePredictedOnCard === false) {
    const lockfileClaim =
      attempt.lockfileFrozen === true || attempt.fixedSha === true;
    return {
      ok: false,
      lifecyclePredicted: false,
      lockfileAloneSufficient: false,
      predictedClasses: predicted.predictedClasses,
      hooksRemain: true,
      gate: lockfileClaim
        ? 'InstallLifecycle.DENY_lockfile_alone'
        : 'InstallLifecycle.REQUIRE_LIFECYCLE_PRED',
      escalate: true,
      reason: lockfileClaim
        ? 'ALLOW refused — frozen-lockfile/fixed-SHA does not erase residual when hooks remain; require postinstall/file/network Pred₆'
        : 'ALLOW refused — install/add with hooks must predict lifecycle on card',
      effectBound: predicted.effectBound,
      freeze: predicted.freeze,
    };
  }

  // Default: prediction itself constitutes the card freeze.
  return predicted;
}

/** True when predicted classes cover postinstall lifecycle bar. */
export function lifecyclePredCoversHooks(
  classes: readonly Omega6Class[] | null | undefined,
): boolean {
  if (!classes?.length) return false;
  const set = new Set(classes);
  return set.has('process') && set.has('file') && set.has('network');
}
