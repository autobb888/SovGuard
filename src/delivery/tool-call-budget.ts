/**
 * A2M Attraction→Manipulation thin land — C-DoS same-tool cap (C).
 *
 * C1: Cap same-tool re-invocation + weighted token/cost escalate vs task
 *     baseline → DENY or HITL. NOT SessionScorer PI window alone.
 *
 * KPI = C-DoS inflation close (~paper 32.4×). Not deepset 80%.
 * Soft residual: host wires budget check before each tools/call.
 */

export type ToolCallBudgetVerdict =
  | 'ALLOW'
  | 'DENY'
  | 'HITL'
  | 'COST_ESCALATE';

export interface ToolCallBudgetConfig {
  /**
   * Max same-tool invocations allowed as a multiple of taskBaseline
   * (default 4). Storm above this → DENY/HITL.
   */
  maxInvocationMultiplier?: number;
  /**
   * Absolute ceiling on same-tool invocations regardless of baseline
   * (default 16).
   */
  absoluteMaxInvocations?: number;
  /**
   * Weighted token/cost multiplier vs baseline tokens before escalate
   * (default 8).
   */
  maxTokenCostMultiplier?: number;
  /**
   * When true (default), first trip is COST_ESCALATE / HITL before hard DENY
   * on subsequent storm (limits FP on long legit workflows).
   */
  escalateBeforeDeny?: boolean;
}

export interface ToolCallRecordInput {
  sessionId: string;
  tool: string;
  /** Optional weighted token/cost units for this invocation. */
  tokenCost?: number;
}

export interface ToolCallBudgetCheckInput {
  sessionId: string;
  tool: string;
  /** Expected invocations for this task (baseline). */
  taskBaselineInvocations: number;
  /** Optional baseline token/cost units for the task. */
  taskBaselineTokens?: number;
  /** Proposed additional cost for this next call. */
  proposedTokenCost?: number;
  config?: ToolCallBudgetConfig;
}

export interface ToolCallBudgetResult {
  verdict: ToolCallBudgetVerdict;
  observedInvocations: number;
  taskBaselineInvocations: number;
  invocationMultiplier: number;
  observedTokenCost: number;
  taskBaselineTokens: number;
  tokenCostMultiplier: number;
  reason?: string;
  gate?: 'CDoSCap.same_tool_reinvocation' | 'CDoSCap.ALLOW';
}

const DEFAULT_CONFIG: Required<ToolCallBudgetConfig> = {
  maxInvocationMultiplier: 4,
  absoluteMaxInvocations: 16,
  maxTokenCostMultiplier: 8,
  escalateBeforeDeny: true,
};

function mergeConfig(c?: ToolCallBudgetConfig): Required<ToolCallBudgetConfig> {
  return { ...DEFAULT_CONFIG, ...c };
}

export interface SessionToolStats {
  invocations: number;
  tokenCost: number;
  /** How many times we already escalated (HITL/COST) for this tool. */
  escalations: number;
}

/**
 * Per-session same-tool invocation + weighted cost counters (C-DoS).
 * Orthogonal to SessionScorer (PI scores).
 */
export class ToolCallBudgetStore {
  private stats = new Map<string, SessionToolStats>();

  private key(sessionId: string, tool: string): string {
    return `${sessionId}::${tool}`;
  }

  /** Record a completed (or about-to-run) invocation. */
  record(input: ToolCallRecordInput): SessionToolStats {
    const k = this.key(input.sessionId, input.tool);
    const cur = this.stats.get(k) ?? { invocations: 0, tokenCost: 0, escalations: 0 };
    cur.invocations += 1;
    cur.tokenCost += input.tokenCost ?? 0;
    this.stats.set(k, cur);
    return { ...cur };
  }

  get(sessionId: string, tool: string): SessionToolStats {
    return (
      this.stats.get(this.key(sessionId, tool)) ?? {
        invocations: 0,
        tokenCost: 0,
        escalations: 0,
      }
    );
  }

  /** Mark an escalation without counting an invocation. */
  markEscalated(sessionId: string, tool: string): SessionToolStats {
    const k = this.key(sessionId, tool);
    const cur = this.stats.get(k) ?? { invocations: 0, tokenCost: 0, escalations: 0 };
    cur.escalations += 1;
    this.stats.set(k, cur);
    return { ...cur };
  }

  clear(sessionId?: string): void {
    if (!sessionId) {
      this.stats.clear();
      return;
    }
    for (const k of [...this.stats.keys()]) {
      if (k.startsWith(`${sessionId}::`)) this.stats.delete(k);
    }
  }

  size(): number {
    return this.stats.size;
  }
}

/**
 * Check whether another same-tool invocation is within C-DoS caps (C1).
 * Does NOT mutate store — host calls record() after ALLOW, or markEscalated on HITL.
 */
export function checkToolCallBudget(
  store: ToolCallBudgetStore,
  input: ToolCallBudgetCheckInput,
): ToolCallBudgetResult {
  const cfg = mergeConfig(input.config);
  const cur = store.get(input.sessionId, input.tool);
  const baselineInv = Math.max(1, input.taskBaselineInvocations);
  const baselineTok = Math.max(1, input.taskBaselineTokens ?? baselineInv);
  const observedInvocations = cur.invocations + 1;
  const observedTokenCost = cur.tokenCost + (input.proposedTokenCost ?? 0);
  const invocationMultiplier = observedInvocations / baselineInv;
  const tokenCostMultiplier = observedTokenCost / baselineTok;

  const overInv =
    invocationMultiplier > cfg.maxInvocationMultiplier ||
    observedInvocations > cfg.absoluteMaxInvocations;
  const overCost = tokenCostMultiplier > cfg.maxTokenCostMultiplier;

  if (!overInv && !overCost) {
    return {
      verdict: 'ALLOW',
      observedInvocations,
      taskBaselineInvocations: baselineInv,
      invocationMultiplier,
      observedTokenCost,
      taskBaselineTokens: baselineTok,
      tokenCostMultiplier,
      gate: 'CDoSCap.ALLOW',
    };
  }

  const reason = overInv
    ? `Same-tool re-invocation storm for "${input.tool}": ${observedInvocations} vs baseline ${baselineInv} (${invocationMultiplier.toFixed(1)}×) — C-DoS cap`
    : `Weighted token/cost escalate for "${input.tool}": ${observedTokenCost} vs baseline ${baselineTok} (${tokenCostMultiplier.toFixed(1)}×) — C-DoS cap`;

  if (cfg.escalateBeforeDeny && cur.escalations === 0) {
    return {
      verdict: overCost && !overInv ? 'COST_ESCALATE' : 'HITL',
      observedInvocations,
      taskBaselineInvocations: baselineInv,
      invocationMultiplier,
      observedTokenCost,
      taskBaselineTokens: baselineTok,
      tokenCostMultiplier,
      reason: `${reason} → HITL/cost escalate (not SessionScorer PI window)`,
      gate: 'CDoSCap.same_tool_reinvocation',
    };
  }

  return {
    verdict: 'DENY',
    observedInvocations,
    taskBaselineInvocations: baselineInv,
    invocationMultiplier,
    observedTokenCost,
    taskBaselineTokens: baselineTok,
    tokenCostMultiplier,
    reason: `${reason} → DENY`,
    gate: 'CDoSCap.same_tool_reinvocation',
  };
}

/**
 * Check then record on ALLOW; markEscalated on first HITL/COST_ESCALATE;
 * DENY does not record.
 */
export function gateToolCall(
  store: ToolCallBudgetStore,
  input: ToolCallBudgetCheckInput & { tokenCost?: number },
): ToolCallBudgetResult {
  const check = checkToolCallBudget(store, {
    ...input,
    proposedTokenCost: input.proposedTokenCost ?? input.tokenCost,
  });
  if (check.verdict === 'ALLOW') {
    store.record({
      sessionId: input.sessionId,
      tool: input.tool,
      tokenCost: input.tokenCost ?? input.proposedTokenCost ?? 0,
    });
  } else if (check.verdict === 'HITL' || check.verdict === 'COST_ESCALATE') {
    store.markEscalated(input.sessionId, input.tool);
  }
  return check;
}
