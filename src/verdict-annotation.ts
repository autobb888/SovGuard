/**
 * SovGuard — Enforcement-mode verdict annotation.
 *
 * Teams need to roll a guardrail out in OBSERVE mode before enforcing, so they
 * can measure the block rate on real traffic without risking over-blocking.
 * These helpers are PURE: they never change `result.safe`/`result.score`; they
 * only tell the caller what SovGuard *would* do and which mode it is running in.
 */

export type EnforcementMode = 'enforce' | 'monitor';

/** Resolve SOVGUARD_MODE into an enforcement mode. Defaults to 'enforce'. */
export function resolveMode(env: string | undefined): EnforcementMode {
  return env === 'monitor' ? 'monitor' : 'enforce';
}

/** Annotate a scan result with enforcement metadata. Pure; never mutates the verdict. */
export function annotateVerdict<T extends { safe: boolean; score: number; degraded?: boolean }>(
  result: T,
  mode: EnforcementMode,
  blockThreshold = 0.7,
): T & { mode: EnforcementMode; wouldBlock: boolean; degraded: boolean } {
  return {
    ...result,
    mode,
    wouldBlock: !result.safe && result.score >= blockThreshold,
    degraded: result.degraded ?? false,
  };
}
