/**
 * A2M Attraction→Manipulation thin land — EIC mcp_config / registry gate (D).
 *
 * D1: mcp_config / MCP server registry append → DENY without fresh HITL
 *     ApprovalBinding envelope.
 * D2: Same write with fresh ApprovalBinding envelope → ALLOW per host HITL policy.
 *
 * Compose Loopjacking ApprovalBindingStore / compareApprovalAtUse /
 * releaseWithApproval — wire only; do NOT re-land ApprovalBinding.
 *
 * Soft residual: host must route mcp_config writes through this gate.
 */

import {
  ApprovalBindingStore,
  compareApprovalAtUse,
  releaseWithApproval,
  digestApprovalVector,
  type ApprovalVector,
  type UseTimeCompareResult,
  type ReleaseApprovalResult,
} from './approval-binding.js';

export type McpConfigWriteAction =
  | 'registry_append'
  | 'registry_remove'
  | 'mcp_config_write'
  | 'server_add'
  | 'server_update';

export interface McpServerProposal {
  id: string;
  url?: string;
  transport?: string;
  [k: string]: unknown;
}

export interface McpConfigWriteAttempt {
  action: McpConfigWriteAction | string;
  proposedServer?: McpServerProposal;
  /** Full config patch (optional; hashed into ApprovalVector.args). */
  patch?: Record<string, unknown>;
  /** Destination / config path hint. */
  destination?: string;
  /** Scope string (default mcp_config_registry_append). */
  scope?: string;
}

export interface McpConfigApprovalBinding {
  /** Fresh ApprovalBindingStore holding the HITL ticket. */
  store: ApprovalBindingStore;
  /** Ticket id from approveAction / store.record. */
  ticketId: string;
  /**
   * When true (default), consume ticket on ALLOW via releaseWithApproval
   * (one-shot — replay DENY).
   */
  consume?: boolean;
}

export type McpConfigGateVerdict = 'ALLOW' | 'DENY';

export interface McpConfigGateResult {
  verdict: McpConfigGateVerdict;
  reason?: string;
  /** Use-time compare when binding present. */
  compare?: UseTimeCompareResult;
  release?: ReleaseApprovalResult;
  /** Canonical vector used for compare. */
  vector?: ApprovalVector;
  gate?:
    | 'ConfigWriteGate.DENY_no_binding'
    | 'ConfigWriteGate.DENY_stale_or_mismatch'
    | 'ConfigWriteGate.ALLOW_fresh_envelope';
}

/** Canonical ApprovalVector for an mcp_config / registry write. */
export function mcpConfigApprovalVector(attempt: McpConfigWriteAttempt): ApprovalVector {
  const server: McpServerProposal = attempt.proposedServer ?? { id: '' };
  return {
    tool: 'mcp_config',
    args: {
      action: attempt.action,
      serverId: server.id ?? '',
      url: server.url ?? '',
      transport: server.transport ?? '',
      ...(attempt.patch ? { patch: attempt.patch } : {}),
    },
    destination: attempt.destination ?? server.url ?? '',
    scope: attempt.scope ?? 'mcp_config_registry_append',
  };
}

/**
 * Gate mcp_config / MCP server registry writes (D1 / D2).
 * Without fresh ApprovalBinding → DENY. With matching unconsumed ticket → ALLOW.
 */
export function gateMcpConfigWrite(
  attempt: McpConfigWriteAttempt,
  binding?: McpConfigApprovalBinding | null,
): McpConfigGateResult {
  const vector = mcpConfigApprovalVector(attempt);

  if (!binding || !binding.ticketId || !binding.store) {
    return {
      verdict: 'DENY',
      reason:
        'mcp_config / registry write DENY — fresh HITL ApprovalBinding envelope required',
      vector,
      gate: 'ConfigWriteGate.DENY_no_binding',
    };
  }

  const consume = binding.consume !== false;
  if (consume) {
    const release = releaseWithApproval(binding.store, binding.ticketId, vector);
    if (!release.allow) {
      return {
        verdict: 'DENY',
        reason:
          release.reason ??
          'mcp_config write DENY — ApprovalBinding mismatch / consumed / missing',
        compare: release.compare,
        release,
        vector,
        gate: 'ConfigWriteGate.DENY_stale_or_mismatch',
      };
    }
    return {
      verdict: 'ALLOW',
      reason: 'mcp_config write ALLOW — fresh ApprovalBinding envelope matched and consumed',
      compare: release.compare,
      release,
      vector,
      gate: 'ConfigWriteGate.ALLOW_fresh_envelope',
    };
  }

  const compare = compareApprovalAtUse(binding.store, binding.ticketId, vector);
  if (!compare.match) {
    return {
      verdict: 'DENY',
      reason:
        compare.reason ??
        'mcp_config write DENY — ApprovalBinding mismatch / consumed / missing',
      compare,
      vector,
      gate: 'ConfigWriteGate.DENY_stale_or_mismatch',
    };
  }
  return {
    verdict: 'ALLOW',
    reason: 'mcp_config write ALLOW — fresh ApprovalBinding envelope matched',
    compare,
    vector,
    gate: 'ConfigWriteGate.ALLOW_fresh_envelope',
  };
}

/** Digest helper for hosts building ApprovalBinding tickets for mcp_config. */
export function digestMcpConfigWrite(attempt: McpConfigWriteAttempt): string {
  return digestApprovalVector(mcpConfigApprovalVector(attempt));
}
