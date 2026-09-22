/**
 * AgentCore heap-view C — dataProtection session hygiene.
 *
 * Recommend / session-gate dataProtection=true for Identity/vault/MCP Bearer
 * agents (JWT/AKIA on the agent text path). Global default remains OFF.
 * Not a deepset land; soft residual: JWT never entering agent text stays blind
 * (platform heap/UID soft PARK).
 */

export interface DataProtectionSessionContext {
  /** Agent uses Identity vault / credential resolution. */
  hasVault?: boolean;
  /** MCP or HTTP Bearer / service-account auth in session. */
  hasBearerAuth?: boolean;
  /** AWS/Azure/GCP identity credentials expected in-session. */
  hasIdentityCredentials?: boolean;
  /** Host agent kind hint (e.g. 'vault', 'mcp-bearer', 'identity'). */
  agentKind?: string;
  /** Explicit host opt-in already set. */
  dataProtection?: boolean;
}

const CREDENTIAL_AGENT_KINDS = new Set([
  'vault',
  'identity',
  'mcp-bearer',
  'mcp_bearer',
  'bearer',
  'agentcore-identity',
  'agentcore_identity',
]);

/**
 * True when session context indicates vault / Bearer / identity credential use.
 * Hosts should prefer enabling dataProtection for these sessions.
 */
export function shouldRecommendDataProtection(
  ctx: DataProtectionSessionContext | undefined,
): boolean {
  if (!ctx) return false;
  if (ctx.hasVault === true) return true;
  if (ctx.hasBearerAuth === true) return true;
  if (ctx.hasIdentityCredentials === true) return true;
  if (ctx.agentKind && CREDENTIAL_AGENT_KINDS.has(ctx.agentKind.toLowerCase())) {
    return true;
  }
  return false;
}

export interface DataProtectionGateResult {
  /** Effective flag for this scan/session (never flips global default). */
  dataProtection: boolean;
  /** Whether hygiene recommended enabling DP for this session. */
  recommended: boolean;
  /** Human-readable reason when recommended or forced. */
  reason?: string;
  /** True when host already had dataProtection=true. */
  hostOptIn: boolean;
}

/**
 * Session-gate helper: when vault/Bearer/identity context is present, return
 * dataProtection=true for *this session* (recommend / gate). Does not change
 * the engine global default (still OFF when context absent / non-credential).
 *
 * Hosts may pass the result into scanOutput({ dataProtection }).
 */
export function sessionGateDataProtection(
  ctx: DataProtectionSessionContext | undefined,
): DataProtectionGateResult {
  const hostOptIn = ctx?.dataProtection === true;
  const recommended = shouldRecommendDataProtection(ctx);
  if (hostOptIn) {
    return {
      dataProtection: true,
      recommended,
      hostOptIn: true,
      reason: recommended
        ? 'host opt-in + credential-session hygiene'
        : 'host opt-in dataProtection',
    };
  }
  if (recommended) {
    return {
      dataProtection: true,
      recommended: true,
      hostOptIn: false,
      reason:
        'session-gate: vault/Bearer/identity agent — enable dataProtection for JWT/AKIA text-path scan',
    };
  }
  return {
    dataProtection: false,
    recommended: false,
    hostOptIn: false,
    reason: 'global default OFF (non-credential session)',
  };
}

/** Alias for docs / CHANGELOG spelling. */
export const recommendDataProtection = shouldRecommendDataProtection;
