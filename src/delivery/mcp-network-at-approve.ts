/**
 * ApprovalLaundering thin land C — MCP config→network at approve.
 *
 * Streamable HTTP / remote / URL transport proposals must surface **network**
 * (and related Ω₆) on the card at decision time. Entry `mcp_config` digest
 * alone is insufficient.
 *
 * Compose with `gateMcpConfigWrite` — extend, do not gut.
 * Soft host Pred₆ UI stays Soft. Escalate BLOCK. Not deepset 80%. Shapes only.
 */

import type { Omega6Class } from './effect-bound-record.js';
import {
  gateMcpConfigWrite,
  type McpConfigWriteAttempt,
  type McpConfigApprovalBinding,
  type McpConfigGateResult,
  type McpServerProposal,
} from './mcp-config-gate.js';
import {
  freezePred6BeforeAllow,
  type EffectBoundRecord,
  type FreezePred6Result,
} from './effect-bound-record.js';

/** Transports that imply network Ω₆ at approve time. */
export const REMOTE_MCP_TRANSPORTS: readonly string[] = [
  'streamable_http',
  'streamable-http',
  'http',
  'https',
  'sse',
  'remote',
  'url',
  'websocket',
  'ws',
  'wss',
] as const;

export type McpNetworkAtApproveGate =
  | 'McpNetworkAtApprove.REQUIRE_NETWORK'
  | 'McpNetworkAtApprove.NETWORK_DECLARED'
  | 'McpNetworkAtApprove.LOCAL_NO_NETWORK_REQUIRED'
  | 'McpNetworkAtApprove.DENY_entry_digest_alone'
  | 'McpNetworkAtApprove.COMPOSE_MCP_GATE';

export interface McpNetworkDeclareInput {
  attempt: McpConfigWriteAttempt;
  /**
   * Ω₆ classes already on the Pred₆ card. Must include `network` when transport
   * is remote / streamable / URL.
   */
  omega6OnCard?: readonly Omega6Class[] | null;
  /** Optional frozen EffectBoundRecord (preferred over omega6OnCard alone). */
  effectBound?: EffectBoundRecord | null;
  /** Entry digest present (ApprovalBinding) — insufficient alone for remote. */
  entryDigestPresent?: boolean;
}

export interface McpNetworkDeclareResult {
  ok: boolean;
  requiresNetwork: boolean;
  networkDeclared: boolean;
  entryDigestAloneSufficient: false;
  gate: McpNetworkAtApproveGate;
  escalate: boolean;
  transport?: string;
  reason?: string;
  /** Suggested Ω₆ classes to freeze on the card. */
  suggestedOmega6?: Omega6Class[];
}

function normalizeTransport(t: unknown): string {
  return String(t ?? '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '_');
}

/** True when proposal uses Streamable HTTP / remote / URL-class transport. */
export function isRemoteMcpTransport(proposal?: McpServerProposal | null): boolean {
  if (!proposal) return false;
  const transport = normalizeTransport(proposal.transport);
  const url = String(proposal.url ?? '').trim();
  if (url && (/^https?:\/\//i.test(url) || /^wss?:\/\//i.test(url))) {
    return true;
  }
  if (!transport) {
    // URL without transport still implies network.
    return url.length > 0;
  }
  return REMOTE_MCP_TRANSPORTS.some(
    (r) => transport === r || transport.includes(r.replace(/_/g, '-')) || transport.includes(r),
  );
}

function networkDeclaredOn(
  omega6OnCard: readonly Omega6Class[] | null | undefined,
  effectBound: EffectBoundRecord | null | undefined,
): boolean {
  if (effectBound?.omega6Classes?.includes('network')) return true;
  if (Array.isArray(omega6OnCard) && omega6OnCard.includes('network')) return true;
  return false;
}

/**
 * Require network Ω₆ on the approval card for remote/streamable/URL MCP.
 * Entry digest alone → DENY_entry_digest_alone.
 */
export function requireNetworkOmega6OnCard(
  input: McpNetworkDeclareInput,
): McpNetworkDeclareResult {
  const entryDigestAloneSufficient = false as const;
  const attempt = input?.attempt;
  if (!attempt) {
    return {
      ok: false,
      requiresNetwork: true,
      networkDeclared: false,
      entryDigestAloneSufficient,
      gate: 'McpNetworkAtApprove.DENY_entry_digest_alone',
      escalate: true,
      reason: 'mcp network-at-approve requires attempt',
    };
  }

  const requiresNetwork = isRemoteMcpTransport(attempt.proposedServer);
  const transport = normalizeTransport(attempt.proposedServer?.transport) ||
    (attempt.proposedServer?.url ? 'url' : '');
  const networkDeclared = networkDeclaredOn(input.omega6OnCard, input.effectBound);

  if (!requiresNetwork) {
    return {
      ok: true,
      requiresNetwork: false,
      networkDeclared,
      entryDigestAloneSufficient,
      gate: 'McpNetworkAtApprove.LOCAL_NO_NETWORK_REQUIRED',
      escalate: false,
      transport,
      reason: 'local/stdio MCP transport — network Ω₆ not required by C',
      suggestedOmega6: ['MCP', 'process'],
    };
  }

  if (!networkDeclared) {
    // Entry digest present is explicitly insufficient.
    return {
      ok: false,
      requiresNetwork: true,
      networkDeclared: false,
      entryDigestAloneSufficient,
      gate:
        input.entryDigestPresent === true
          ? 'McpNetworkAtApprove.DENY_entry_digest_alone'
          : 'McpNetworkAtApprove.REQUIRE_NETWORK',
      escalate: true,
      transport,
      reason:
        'remote / Streamable HTTP / URL MCP must declare network Ω₆ on card at approve — entry mcp_config digest alone insufficient',
      suggestedOmega6: ['MCP', 'network', 'process'],
    };
  }

  return {
    ok: true,
    requiresNetwork: true,
    networkDeclared: true,
    entryDigestAloneSufficient,
    gate: 'McpNetworkAtApprove.NETWORK_DECLARED',
    escalate: false,
    transport,
    reason: 'network Ω₆ declared on Pred₆ card for remote MCP transport',
    suggestedOmega6: ['MCP', 'network', 'process'],
  };
}

export interface GateMcpConfigWithNetworkOpts {
  /** Pred₆ classes on card (or supply effectBound). */
  omega6OnCard?: readonly Omega6Class[];
  effectBound?: EffectBoundRecord | null;
  entryDigestPresent?: boolean;
  /**
   * When true (default), fail closed if network-at-approve fails even if
   * entry ApprovalBinding would ALLOW.
   */
  enforceNetworkAtApprove?: boolean;
}

export interface GateMcpConfigWithNetworkResult {
  /** Combined verdict — DENY if either entry gate or network-at-approve fails. */
  verdict: 'ALLOW' | 'DENY';
  entryGate: McpConfigGateResult;
  networkAtApprove: McpNetworkDeclareResult;
  effectBoundFreeze?: FreezePred6Result;
  gate: McpNetworkAtApproveGate | McpConfigGateResult['gate'];
  reason?: string;
}

/**
 * Compose: run `gateMcpConfigWrite` then require network Ω₆ for remote transports.
 * Does not gut the entry envelope gate.
 */
export function gateMcpConfigWriteWithNetworkAtApprove(
  attempt: McpConfigWriteAttempt,
  binding?: McpConfigApprovalBinding | null,
  opts?: GateMcpConfigWithNetworkOpts,
): GateMcpConfigWithNetworkResult {
  const entryGate = gateMcpConfigWrite(attempt, binding);
  const networkAtApprove = requireNetworkOmega6OnCard({
    attempt,
    omega6OnCard: opts?.omega6OnCard ?? opts?.effectBound?.omega6Classes,
    effectBound: opts?.effectBound,
    entryDigestPresent:
      opts?.entryDigestPresent ?? Boolean(binding?.ticketId),
  });

  const enforce = opts?.enforceNetworkAtApprove !== false;

  if (entryGate.verdict === 'DENY') {
    return {
      verdict: 'DENY',
      entryGate,
      networkAtApprove,
      gate: entryGate.gate,
      reason: entryGate.reason,
    };
  }

  if (enforce && !networkAtApprove.ok) {
    return {
      verdict: 'DENY',
      entryGate,
      networkAtApprove,
      gate: networkAtApprove.gate,
      reason: networkAtApprove.reason,
    };
  }

  return {
    verdict: 'ALLOW',
    entryGate,
    networkAtApprove,
    gate: 'McpNetworkAtApprove.COMPOSE_MCP_GATE',
    reason:
      'mcp_config entry envelope ALLOW + network Ω₆ declared (or not required)',
  };
}

/**
 * Helper: freeze Pred₆ with network for a remote MCP approve card.
 * Compose with entryDigest — does not replace ApprovalBinding.
 */
export function freezeMcpRemotePred6Card(args: {
  attempt: McpConfigWriteAttempt;
  entryDigest?: string | null;
  approvalId?: string | null;
  mcpJsonContent?: string | null;
  extraClasses?: readonly Omega6Class[];
}): FreezePred6Result {
  const remote = isRemoteMcpTransport(args.attempt.proposedServer);
  const classes: Omega6Class[] = [
    'MCP',
    ...(remote ? (['network'] as Omega6Class[]) : []),
    'process',
    ...(args.extraClasses ?? []),
  ];
  // unique preserve order via freezePred6BeforeAllow normalize
  return freezePred6BeforeAllow({
    omega6Classes: classes,
    provenance: args.mcpJsonContent
      ? { '.mcp.json': args.mcpJsonContent }
      : undefined,
    entryDigest: args.entryDigest,
    approvalId: args.approvalId,
    notes: remote
      ? 'MCP remote/streamable/URL — network Ω₆ frozen at approve'
      : 'MCP local transport Pred₆',
  });
}
