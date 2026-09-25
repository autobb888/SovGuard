/**
 * TraceIntegrity thin land B — Session-path DENY.
 *
 * Known harness session path **shapes** (session.jsonl, transcript.db,
 * lifecycle.log, ~/.claude|codex|cursor session paths) — write / delete /
 * truncate / unlink → DENY + escalate.
 *
 * Privacy / reward framing must NOT authorize.
 * Shape patterns only — no live deletes.
 *
 * ActionGuard may compose content/plan-side later; do not reopen ControlToken.
 * Soft residuals stay soft. Escalate BLOCK. Not deepset 80%. Shapes only.
 */

export type SessionPathOp = 'write' | 'delete' | 'truncate' | 'unlink' | 'read' | 'stat';

export type SessionPathVerdict = 'ALLOW' | 'DENY';

export type SessionPathGateId =
  | 'SessionPathGate.ALLOW'
  | 'SessionPathGate.DENY_mutation'
  | 'SessionPathGate.DENY_privacy_framing'
  | 'SessionPathGate.DENY_bad_input';

export type SessionPathFraming =
  | 'none'
  | 'privacy_protection_skill_or_reward_cue'
  | 'privacy'
  | 'reward'
  | string;

export interface SessionPathAttempt {
  path: string;
  op: SessionPathOp;
  /** Privacy / reward framing — must not authorize wipe. */
  framing?: SessionPathFraming;
}

export interface SessionPathGateResult {
  verdict: SessionPathVerdict;
  gate: SessionPathGateId;
  /** Always true on DENY — escalate BLOCK. */
  escalate: boolean;
  path: string;
  op: SessionPathOp;
  matchedPattern?: string;
  privacyFramingAuthorizes: false;
  reason?: string;
}

/** Known harness session path shape patterns (not live filesystem deletes). */
export const HARNESS_SESSION_PATH_PATTERNS: ReadonlyArray<{ id: string; re: RegExp }> = [
  { id: 'session_jsonl', re: /(^|[\\/])session\.jsonl$/i },
  { id: 'transcript_db', re: /(^|[\\/])transcript\.db$/i },
  { id: 'lifecycle_log', re: /(^|[\\/])lifecycle\.log$/i },
  { id: 'harness_session_jsonl', re: /^harness:session\.jsonl$/i },
  { id: 'harness_transcript_db', re: /^harness:transcript\.db$/i },
  { id: 'harness_lifecycle_log', re: /^harness:lifecycle\.log$/i },
  { id: 'claude_session', re: /(^|[\\/])\.claude([\\/]|$)/i },
  { id: 'codex_session', re: /(^|[\\/])\.codex([\\/]sessions?[\\/]|$)/i },
  { id: 'cursor_session', re: /(^|[\\/])\.cursor([\\/]|$)/i },
  { id: 'jsonl_under_harness_home', re: /(^|[\\/])\.(claude|codex|cursor)[\\/].+\.jsonl$/i },
];

const MUTATING_OPS: ReadonlySet<SessionPathOp> = new Set([
  'write',
  'delete',
  'truncate',
  'unlink',
]);

export function matchHarnessSessionPath(path: string): string | undefined {
  const p = String(path ?? '');
  if (!p) return undefined;
  for (const { id, re } of HARNESS_SESSION_PATH_PATTERNS) {
    if (re.test(p)) return id;
  }
  return undefined;
}

export function isMutatingSessionPathOp(op: SessionPathOp): boolean {
  return MUTATING_OPS.has(op);
}

/**
 * Gate a session-path mutation attempt.
 * Known harness paths + mutating op → DENY + escalate.
 * Privacy/reward framing never authorizes.
 */
export function gateSessionPath(attempt: SessionPathAttempt): SessionPathGateResult {
  const path = String(attempt?.path ?? '');
  const op = attempt?.op;
  if (!path || !op) {
    return {
      verdict: 'DENY',
      gate: 'SessionPathGate.DENY_bad_input',
      escalate: true,
      path,
      op: (op ?? 'write') as SessionPathOp,
      privacyFramingAuthorizes: false,
      reason: 'path and op required',
    };
  }

  const matched = matchHarnessSessionPath(path);
  const framing = String(attempt.framing ?? 'none');
  const framed =
    framing !== 'none' &&
    /privacy|reward/i.test(framing);

  if (matched && isMutatingSessionPathOp(op)) {
    return {
      verdict: 'DENY',
      gate: framed
        ? 'SessionPathGate.DENY_privacy_framing'
        : 'SessionPathGate.DENY_mutation',
      escalate: true,
      path,
      op,
      matchedPattern: matched,
      privacyFramingAuthorizes: false,
      reason: framed
        ? 'privacy/reward framing does not authorize session-path wipe'
        : `mutating op ${op} on harness session path denied`,
    };
  }

  return {
    verdict: 'ALLOW',
    gate: 'SessionPathGate.ALLOW',
    escalate: false,
    path,
    op,
    matchedPattern: matched,
    privacyFramingAuthorizes: false,
  };
}

/** Batch helper — DENY if any attempt DENYs. */
export function gateSessionPaths(
  attempts: SessionPathAttempt[],
): { overall: SessionPathVerdict; results: SessionPathGateResult[]; escalate: boolean } {
  const results = attempts.map(gateSessionPath);
  const denied = results.filter((r) => r.verdict === 'DENY');
  return {
    overall: denied.length > 0 ? 'DENY' : 'ALLOW',
    results,
    escalate: denied.some((r) => r.escalate),
  };
}
