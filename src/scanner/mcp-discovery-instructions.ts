/**
 * MCP DiscoveryInstructions thin land (DL-011 / P1).
 *
 * Server-controlled `instructions` from MCP `initialize` / discovery are
 * non-tool prose that hosts may fold into the system/trusted prompt *before*
 * any tool call. Deadbugz (tools/list) and GhostSplice (arg-content) do not
 * cover this surface — compose alongside them; do not subsume under tools/list.
 *
 * Thin land:
 *   1. isolate+label as untrusted; length cap; never default-fold into trusted/system
 *   2. pin instructions digest at consent; drift → reject fail-closed (Deadbugz-shaped, non-tool)
 *   3. refuse cacheScope:public OR bind cache key to caller+server for instruction-bearing discovery
 *   4. empty/absent → ALLOW
 *
 * Soft residual: host must wire pin into connect/consent. Not deepset 80%.
 */
import { createHash } from 'node:crypto';

/** Default max chars retained after isolate+cap (hostile long payloads). */
export const DEFAULT_INSTRUCTIONS_MAX_LENGTH = 4096;

/** Trust label — discovery instructions are never trusted/system. */
export const DISCOVERY_INSTRUCTIONS_LABEL = 'mcp_discovery_instructions' as const;

export type DiscoveryInstructionsTrust = 'untrusted';

export interface IsolatedDiscoveryInstructions {
  /** Always untrusted — never promote to system/trusted region. */
  trust: DiscoveryInstructionsTrust;
  label: typeof DISCOVERY_INSTRUCTIONS_LABEL;
  /** Capped text suitable only for untrusted/data regions (or HITL review). */
  text: string;
  truncated: boolean;
  originalLength: number;
  /** sha256 of normalized instructions (empty → empty digest). */
  digest: string;
  /** Hard false: hosts must not fold into trusted/system by default. */
  trustedRegionEligible: false;
  /** True when instructions were empty/absent. */
  empty: boolean;
}

export interface ConsentedDiscoveryInstructions {
  serverId: string;
  instructionsDigest: string;
  empty: boolean;
}

export interface InstructionsDriftCheck {
  ok: boolean;
  /** True when consented digest ≠ current (rug-pull / drift). */
  drift: boolean;
  reason?: string;
  consentedDigest: string;
  currentDigest: string;
}

export interface DiscoveryInstructionsIntegrityResult {
  ok: boolean;
  drift: boolean;
  /** Host must re-approve before trusting these instructions. */
  reapprovalRequired: boolean;
  /**
   * When drift: subsequent proposed acts from this MCP must be treated as
   * untrusted (ActionGuard source mcp_result). Never silent consent refresh.
   */
  markActsUntrusted: boolean;
  actionGuardSource: 'mcp_result';
  isolated: IsolatedDiscoveryInstructions;
  verify: InstructionsDriftCheck & { consented: boolean };
}

export type DiscoveryCachePolicy = 'refuse_public' | 'bind_to_caller_server';

export type DiscoveryCacheDecision =
  | { action: 'allow'; reason: string; cacheKey?: string }
  | { action: 'refuse'; reason: string }
  | { action: 'bind'; reason: string; cacheKey: string };

/** Normalize for hashing: null/undefined/whitespace-only → empty string. */
export function normalizeDiscoveryInstructions(
  instructions: string | null | undefined,
): string {
  if (instructions == null) return '';
  if (typeof instructions !== 'string') return String(instructions);
  return instructions;
}

/** True when instructions are empty or absent (M4 control). */
export function isEmptyDiscoveryInstructions(
  instructions: string | null | undefined,
): boolean {
  return normalizeDiscoveryInstructions(instructions).length === 0;
}

/**
 * Persistable digest over discovery instructions (Deadbugz-shaped, non-tool).
 * Empty/absent → digest of empty string (stable ALLOW control).
 */
export function hashDiscoveryInstructions(
  instructions: string | null | undefined,
): string {
  const payload = normalizeDiscoveryInstructions(instructions);
  return createHash('sha256').update(payload, 'utf8').digest('hex');
}

/**
 * Isolate+label+cap MCP discovery instructions.
 * Never marks trustedRegionEligible; hosts must not fold into system/trusted.
 */
export function isolateDiscoveryInstructions(
  instructions: string | null | undefined,
  opts?: { maxLength?: number },
): IsolatedDiscoveryInstructions {
  const maxLength = opts?.maxLength ?? DEFAULT_INSTRUCTIONS_MAX_LENGTH;
  const raw = normalizeDiscoveryInstructions(instructions);
  const empty = raw.length === 0;
  const truncated = raw.length > maxLength;
  const text = truncated ? raw.slice(0, maxLength) : raw;
  return {
    trust: 'untrusted',
    label: DISCOVERY_INSTRUCTIONS_LABEL,
    text,
    truncated,
    originalLength: raw.length,
    digest: hashDiscoveryInstructions(raw),
    trustedRegionEligible: false,
    empty,
  };
}

/**
 * Whether isolated instructions may enter a trusted/system prompt region.
 * Always false — DENY/HITL before any fold into trusted prompt (M1).
 * Parameter kept so hosts pass the isolate result explicitly (fail-closed API).
 */
export function mayFoldIntoTrustedRegion(
  _isolated: IsolatedDiscoveryInstructions,
): boolean {
  // trustedRegionEligible is typed `false` on IsolatedDiscoveryInstructions.
  void _isolated;
  return false;
}

/** Reject instructions digest mutation after consent without re-consent. */
export function checkDiscoveryInstructionsConsent(
  consented: ConsentedDiscoveryInstructions,
  current: string | null | undefined,
): InstructionsDriftCheck {
  const currentDigest = hashDiscoveryInstructions(current);
  if (consented.instructionsDigest !== currentDigest) {
    return {
      ok: false,
      drift: true,
      reason: 'instructionsDigest changed without re-consent (discovery_instructions_drift)',
      consentedDigest: consented.instructionsDigest,
      currentDigest,
    };
  }
  return {
    ok: true,
    drift: false,
    consentedDigest: consented.instructionsDigest,
    currentDigest,
  };
}

/** In-memory instructions consent ledger (Deadbugz-shaped, non-tool). */
export class DiscoveryInstructionsConsentStore {
  private store = new Map<string, ConsentedDiscoveryInstructions>();

  record(
    serverId: string,
    instructions: string | null | undefined,
  ): ConsentedDiscoveryInstructions {
    const entry: ConsentedDiscoveryInstructions = {
      serverId,
      instructionsDigest: hashDiscoveryInstructions(instructions),
      empty: isEmptyDiscoveryInstructions(instructions),
    };
    this.store.set(serverId, entry);
    return entry;
  }

  get(serverId: string): ConsentedDiscoveryInstructions | undefined {
    return this.store.get(serverId);
  }

  /**
   * Verify current instructions against stored consent.
   * Missing consent → ok:false drift:false (not yet consented).
   */
  verify(
    serverId: string,
    instructions: string | null | undefined,
  ): InstructionsDriftCheck & { consented: boolean } {
    const prior = this.get(serverId);
    if (!prior) {
      return {
        ok: false,
        drift: false,
        consented: false,
        reason: 'no discovery-instructions consent recorded',
        consentedDigest: '',
        currentDigest: hashDiscoveryInstructions(instructions),
      };
    }
    return { ...checkDiscoveryInstructionsConsent(prior, instructions), consented: true };
  }

  clear(): void {
    this.store.clear();
  }
}

/**
 * Continuous discovery-instructions integrity (Deadbugz-shaped, non-tool).
 * Call on initialize / discover refresh. Never silently refreshes consent.
 */
export function assertDiscoveryInstructionsIntegrity(
  store: DiscoveryInstructionsConsentStore,
  serverId: string,
  instructions: string | null | undefined,
  opts?: { maxLength?: number },
): DiscoveryInstructionsIntegrityResult {
  const isolated = isolateDiscoveryInstructions(instructions, opts);
  const verify = store.verify(serverId, instructions);
  let drift = false;
  let reapprovalRequired = false;

  if (verify.drift) {
    drift = true;
    reapprovalRequired = true;
  } else if (!verify.consented) {
    // Not yet consented — require approval; do not auto-record.
    // Empty/absent still needs an explicit pin for hosts that opt into the ledger,
    // but M4 ALLOW path is: empty → no false DENY on tool path (ok when empty + consented,
    // or when host skips the pin for empty). Here we only flag reapproval when non-empty
    // and not consented; empty without consent is ALLOW control (no reapprovalRequired).
    if (!isolated.empty) {
      reapprovalRequired = true;
    }
  }

  const ok = !drift && !reapprovalRequired && (verify.ok || isolated.empty);
  return {
    ok,
    drift,
    reapprovalRequired,
    markActsUntrusted: drift,
    actionGuardSource: 'mcp_result',
    isolated,
    verify,
  };
}

/**
 * Cache-scope policy for instruction-bearing discovery (M3).
 * - empty/absent instructions → ALLOW (even if cacheScope public)
 * - instruction-bearing + cacheScope public → refuse (default) or bind to caller+server
 */
export function evaluateDiscoveryCacheScope(opts: {
  instructions: string | null | undefined;
  cacheScope?: string | null;
  serverId: string;
  callerId?: string;
  /** Default refuse_public; bind_to_caller_server for gateway key binding. */
  policy?: DiscoveryCachePolicy;
}): DiscoveryCacheDecision {
  const empty = isEmptyDiscoveryInstructions(opts.instructions);
  const scope = (opts.cacheScope ?? '').toLowerCase().trim();
  const isPublic = scope === 'public';

  if (empty) {
    return {
      action: 'allow',
      reason: 'empty/absent discovery instructions — cacheScope unrestricted (M4 control)',
    };
  }

  if (!isPublic) {
    const key =
      opts.callerId != null && opts.callerId !== ''
        ? `caller:${opts.callerId}|server:${opts.serverId}`
        : `server:${opts.serverId}`;
    return {
      action: 'allow',
      reason: 'instruction-bearing discovery with non-public cacheScope',
      cacheKey: key,
    };
  }

  const policy = opts.policy ?? 'refuse_public';
  if (policy === 'bind_to_caller_server') {
    const caller = opts.callerId && opts.callerId !== '' ? opts.callerId : '';
    if (!caller) {
      return {
        action: 'refuse',
        reason:
          'cacheScope:public with instruction-bearing discovery requires callerId to bind cache key — refusing',
      };
    }
    const cacheKey = `caller:${caller}|server:${opts.serverId}|instructions`;
    return {
      action: 'bind',
      reason:
        'cacheScope:public refused as shared key; bound to caller+server so cross-caller poison cannot fan out',
      cacheKey,
    };
  }

  return {
    action: 'refuse',
    reason:
      'refuse cacheScope:public for instruction-bearing discovery (cross-caller poison)',
  };
}

/**
 * Bind a cache key to caller+server for instruction-bearing discovery.
 * Distinct keys for distinct callers — caller B must not inherit caller A poison.
 */
export function bindDiscoveryCacheKey(opts: {
  serverId: string;
  callerId: string;
  instructions?: string | null;
}): string {
  const empty = isEmptyDiscoveryInstructions(opts.instructions);
  const base = `caller:${opts.callerId}|server:${opts.serverId}`;
  return empty ? base : `${base}|instructions`;
}
