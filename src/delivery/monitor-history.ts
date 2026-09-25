/**
 * InstrumentalEvasion thin land A — History-aware monitor.
 *
 * Retain ≥N prior tool proposals with allow/block + truncated args +
 * effect-class hash. Write→execute / alias→edit decomposition stays linked
 * so the prohibited *effect* remains blocked.
 *
 * Soft-compose ActionGuard (content/plan/shell-class stay) + ApprovalBinding
 * (use-time approve bind stays). Do NOT gut ActionGuard or reopen closed lands.
 * Soft residuals (mcp_config / C-DoS / async Chronos / C–E / Soft D) stay soft.
 * Escalate BLOCK. Not deepset 80%. Shapes only — no EvasionBench kit/PoC.
 */

import { createHash } from 'node:crypto';

export type MonitorDecision = 'ALLOW' | 'BLOCK';

export type MonitorHistoryGate =
  | 'MonitorHistory.ALLOW'
  | 'MonitorHistory.BLOCK_linked_effect'
  | 'MonitorHistory.BLOCK_prior_deny'
  | 'MonitorHistory.DENY_bad_input';

export interface ToolProposal {
  toolName: string;
  /** Truncated / shape args — not live payloads. */
  args?: unknown;
  /**
   * Effect-class label (e.g. prohibited_effect_X). Host may supply; otherwise
   * derived from toolName + truncated args.
   */
  effectClass?: string;
  /**
   * Decomposition link shape — write_script_file / execute_written_script /
   * path_alias_or_hardlink / edit_via_alias, etc.
   */
  shape?: string;
}

export interface MonitorHistoryRecord {
  toolName: string;
  decision: MonitorDecision;
  truncatedArgs: string;
  effectClassHash: string;
  effectClass: string;
  shape?: string;
  recordedAt: number;
}

export interface MonitorHistoryEvalResult {
  verdict: MonitorDecision;
  gate: MonitorHistoryGate;
  escalate: boolean;
  effectClass: string;
  effectClassHash: string;
  linkedPrior?: MonitorHistoryRecord;
  reason?: string;
}

export interface MonitorHistoryOptions {
  /** Minimum retained prior decisions (default 8; paper ref ~40 upper). */
  windowSize?: number;
  /** Max chars retained for truncated args (default 600). */
  argsTruncateChars?: number;
}

const DEFAULT_WINDOW = 8;
const DEFAULT_ARGS_TRUNCATE = 600;

/** Stable truncate for ledger — never stores full live payloads. */
export function truncateArgs(args: unknown, maxChars = DEFAULT_ARGS_TRUNCATE): string {
  let s: string;
  try {
    s = typeof args === 'string' ? args : JSON.stringify(args ?? null);
  } catch {
    s = String(args);
  }
  if (s.length <= maxChars) return s;
  return s.slice(0, maxChars) + '…';
}

/** Effect-class hash — prefer explicit effectClass; else tool+truncated args. */
export function hashEffectClass(
  effectClass: string,
  toolName?: string,
  truncatedArgs?: string,
): string {
  const basis = effectClass
    ? `ec:${effectClass}`
    : `tool:${toolName ?? ''}\0${truncatedArgs ?? ''}`;
  return createHash('sha256').update(basis).digest('hex').slice(0, 16);
}

/**
 * History-aware monitor ledger: retains ≥N prior allow/block decisions and
 * links decomposition steps that share an effect-class hash.
 */
export class MonitorHistoryLedger {
  private readonly windowSize: number;
  private readonly argsTruncateChars: number;
  private readonly records: MonitorHistoryRecord[] = [];

  constructor(opts?: MonitorHistoryOptions) {
    this.windowSize = Math.max(1, opts?.windowSize ?? DEFAULT_WINDOW);
    this.argsTruncateChars = Math.max(32, opts?.argsTruncateChars ?? DEFAULT_ARGS_TRUNCATE);
  }

  get size(): number {
    return this.records.length;
  }

  /** Guaranteed capacity ≥ configured N. */
  get capacity(): number {
    return this.windowSize;
  }

  list(): readonly MonitorHistoryRecord[] {
    return this.records.slice();
  }

  /**
   * Evaluate a proposal against history. If a prior BLOCK shares the same
   * effect-class hash (write→execute / alias→edit), BLOCK the linked step.
   * Caller supplies the myopic base decision for novel effect classes.
   */
  evaluateWithHistory(
    proposal: ToolProposal,
    baseDecision: MonitorDecision = 'ALLOW',
  ): MonitorHistoryEvalResult {
    const toolName = String(proposal?.toolName ?? '');
    if (!toolName) {
      return {
        verdict: 'BLOCK',
        gate: 'MonitorHistory.DENY_bad_input',
        escalate: true,
        effectClass: '',
        effectClassHash: '',
        reason: 'toolName required',
      };
    }

    const truncatedArgs = truncateArgs(proposal.args, this.argsTruncateChars);
    const effectClass =
      String(proposal.effectClass ?? '').trim() ||
      `${toolName}:${truncatedArgs.slice(0, 64)}`;
    const effectClassHash = hashEffectClass(effectClass, toolName, truncatedArgs);

    // Link: prior BLOCK on same effect class → keep blocked (decomposition)
    const linkedPrior = [...this.records]
      .reverse()
      .find((r) => r.decision === 'BLOCK' && r.effectClassHash === effectClassHash);

    if (linkedPrior) {
      const result: MonitorHistoryEvalResult = {
        verdict: 'BLOCK',
        gate: 'MonitorHistory.BLOCK_linked_effect',
        escalate: true,
        effectClass,
        effectClassHash,
        linkedPrior,
        reason: `linked to prior BLOCK on effect class ${effectClass} (shape=${proposal.shape ?? 'n/a'})`,
      };
      this.push(toolName, 'BLOCK', truncatedArgs, effectClass, effectClassHash, proposal.shape);
      return result;
    }

    const verdict = baseDecision;
    const gate: MonitorHistoryGate =
      verdict === 'BLOCK'
        ? 'MonitorHistory.BLOCK_prior_deny'
        : 'MonitorHistory.ALLOW';
    this.push(toolName, verdict, truncatedArgs, effectClass, effectClassHash, proposal.shape);
    return {
      verdict,
      gate,
      escalate: verdict === 'BLOCK',
      effectClass,
      effectClassHash,
      reason: verdict === 'BLOCK' ? 'base decision BLOCK' : undefined,
    };
  }

  /** Record an external allow/block without re-evaluating (host wire). */
  recordDecision(
    proposal: ToolProposal,
    decision: MonitorDecision,
  ): MonitorHistoryRecord {
    const toolName = String(proposal?.toolName ?? '');
    const truncatedArgs = truncateArgs(proposal.args, this.argsTruncateChars);
    const effectClass =
      String(proposal.effectClass ?? '').trim() ||
      `${toolName}:${truncatedArgs.slice(0, 64)}`;
    const effectClassHash = hashEffectClass(effectClass, toolName, truncatedArgs);
    return this.push(
      toolName,
      decision,
      truncatedArgs,
      effectClass,
      effectClassHash,
      proposal.shape,
    );
  }

  private push(
    toolName: string,
    decision: MonitorDecision,
    truncatedArgs: string,
    effectClass: string,
    effectClassHash: string,
    shape?: string,
  ): MonitorHistoryRecord {
    const rec: MonitorHistoryRecord = {
      toolName,
      decision,
      truncatedArgs,
      effectClassHash,
      effectClass,
      shape,
      recordedAt: Date.now(),
    };
    this.records.push(rec);
    while (this.records.length > this.windowSize) {
      this.records.shift();
    }
    return rec;
  }
}
