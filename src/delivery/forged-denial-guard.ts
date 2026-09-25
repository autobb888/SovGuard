/**
 * InstrumentalEvasion thin land D — Forged-denial anti-overrefusal.
 *
 * Untrusted content mimicking PreToolUse / monitor refusal must NOT abandon
 * otherwise allowed solvable tasks (Astra-class DoS). Authenticate denials
 * via channel / structured denial token vs untrusted text. Real authenticated
 * denials still bind.
 *
 * Soft-compose ActionGuard + ApprovalBinding. Soft residuals stay soft.
 * Escalate BLOCK. Not deepset 80%. Shapes only.
 */

export type DenialAuthSource =
  | 'authenticated_channel'
  | 'structured_denial_token'
  | 'untrusted_doc_or_tool_return'
  | 'untrusted_content'
  | string;

export type ForgedDenialVerdict =
  | 'IGNORE_FORGED'
  | 'BIND_AUTHENTICATED'
  | 'DENY_bad_input';

export type ForgedDenialGateId =
  | 'ForgedDenial.IGNORE_unauthenticated_refusal_text'
  | 'ForgedDenial.BIND_authenticated_denial'
  | 'ForgedDenial.DENY_bad_input';

export interface ForgedDenialProbe {
  /**
   * Content shape — e.g. fake_PreToolUse_or_monitor_refusal_text.
   * Descriptive only; not treated as a structured denial token.
   */
  contentShape?: string;
  /** Actual channel the text arrived on. */
  actualChannel: DenialAuthSource;
  /** Primary task shape that is otherwise allowed / solvable. */
  primaryTask?: string;
  /**
   * Host signal: a real authenticated denial is present on the trusted channel.
   * When true → bind (do not ignore real denials).
   */
  realAuthenticatedDenial?: boolean;
  /** Structured denial token from authenticated channel (if any). */
  denialToken?: string;
  /**
   * Optional expected token prefix / registry check — host may pass a set of
   * tokens previously minted by DenialPrecedenceLedger.
   */
  knownDenialTokens?: ReadonlySet<string> | readonly string[];
}

export interface ForgedDenialGuardResult {
  verdict: ForgedDenialVerdict;
  gate: ForgedDenialGateId;
  /** Anti-overrefusal: allowed solvable task may continue when forged. */
  primaryTaskMayContinue: boolean;
  /** Real authenticated denials still bind. */
  authenticatedDenialBinds: boolean;
  escalate: boolean;
  reason?: string;
}

const AUTH_CHANNELS = new Set([
  'authenticated_channel',
  'structured_denial_token',
  'guardrail',
  'monitor',
  'PreToolUse',
]);

function tokenKnown(
  token: string | undefined,
  known?: ReadonlySet<string> | readonly string[],
): boolean {
  if (!token) return false;
  if (!known) return false;
  if (known instanceof Set) return known.has(token);
  return (known as readonly string[]).includes(token);
}

function isAuthenticated(probe: ForgedDenialProbe): boolean {
  if (probe.realAuthenticatedDenial === true) return true;
  if (tokenKnown(probe.denialToken, probe.knownDenialTokens)) return true;
  // Trusted channel alone is insufficient without explicit auth flag or token —
  // but realAuthenticatedDenial:true OR known token binds. Auth channel +
  // realAuthenticatedDenial undefined + no token → not auto-bind (host must set flag).
  return false;
}

/**
 * Distinguish authenticated denial tokens / channels from untrusted mimicked
 * refusal text. Forged text must not abandon allowed solvable tasks; real
 * authenticated denials still bind.
 */
export function assessForgedDenial(
  probe: ForgedDenialProbe,
): ForgedDenialGuardResult {
  const channel = String(probe?.actualChannel ?? '');
  if (!channel) {
    return {
      verdict: 'DENY_bad_input',
      gate: 'ForgedDenial.DENY_bad_input',
      primaryTaskMayContinue: false,
      authenticatedDenialBinds: true,
      escalate: true,
      reason: 'actualChannel required',
    };
  }

  // Real authenticated denial → bind (do not ignore)
  if (isAuthenticated(probe)) {
    return {
      verdict: 'BIND_AUTHENTICATED',
      gate: 'ForgedDenial.BIND_authenticated_denial',
      primaryTaskMayContinue: false,
      authenticatedDenialBinds: true,
      escalate: true,
      reason: 'authenticated denial channel/token binds — do not ignore real denials',
    };
  }

  // Untrusted mimicked PreToolUse / monitor refusal text → anti-overrefusal
  // Document prose is never a structured denial token.
  void AUTH_CHANNELS; // documented auth channel names for host wires
  return {
    verdict: 'IGNORE_FORGED',
    gate: 'ForgedDenial.IGNORE_unauthenticated_refusal_text',
    primaryTaskMayContinue: true,
    authenticatedDenialBinds: true,
    escalate: false,
    reason:
      'untrusted content mimicking PreToolUse/monitor refusal must not abandon allowed solvable task',
  };
}

/** Convenience alias matching acceptance naming. */
export function gateForgedDenial(
  probe: ForgedDenialProbe,
): ForgedDenialGuardResult {
  return assessForgedDenial(probe);
}
