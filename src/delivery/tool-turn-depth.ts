/**
 * PersistentBillable thin land D — D3 ToolTurnDepth / RecursiveOpportunity.
 *
 * Bound recursive opportunity / tool-turn depth **across tools**.
 * Compose with, do NOT replace, same-tool CDoSCap (`ToolCallBudgetStore`).
 *
 * Soft C-DoS owned on PersistentBillable track (volume + retained-mass).
 * Escalate BLOCK. Not deepset 80%. Shapes only — no DoW PoC/kit.
 */

export type ToolTurnDepthVerdict = 'ALLOW' | 'HITL' | 'DENY_DEPTH';

export type ToolTurnDepthGateId =
  | 'D3ToolTurnDepth.ALLOW'
  | 'D3ToolTurnDepth.HITL'
  | 'D3ToolTurnDepth.DENY_DEPTH'
  | 'D3ToolTurnDepth.DENY_bad_input'
  | 'D3ToolTurnDepth.COMPOSE_CDOS';

export interface ToolTurnDepthConfig {
  /** Max tool-turn depth across tools in a session chain (default 8). */
  maxCrossToolDepth?: number;
  /** Max distinct tools in a recursive opportunity window (default 6). */
  maxDistinctToolsInWindow?: number;
  /** Escalate HITL before hard DENY (default true). */
  escalateBeforeDeny?: boolean;
}

export interface ToolTurnDepthRecordInput {
  sessionId: string;
  tool: string;
  /** Optional parent tool that spawned this call (recursive opportunity). */
  parentTool?: string | null;
}

export interface ToolTurnDepthCheckInput {
  sessionId: string;
  tool: string;
  parentTool?: string | null;
  config?: ToolTurnDepthConfig;
  /**
   * Optional: host already ran same-tool CDoSCap. When provided, compose note
   * is attached — this gate does NOT replace volume check.
   */
  sameToolCdosChecked?: boolean;
}

export interface ToolTurnDepthCheckResult {
  verdict: ToolTurnDepthVerdict;
  gate: ToolTurnDepthGateId;
  crossToolDepth: number;
  distinctTools: number;
  maxCrossToolDepth: number;
  maxDistinctToolsInWindow: number;
  composeSameToolCdos: boolean;
  reason?: string;
  escalate: boolean;
}

export interface SessionToolTurnDepthStats {
  /** Current chain depth across tools (increments each tool turn). */
  crossToolDepth: number;
  toolsSeen: string[];
  escalations: number;
  lastTool: string | null;
}

const DEFAULT_CONFIG: Required<ToolTurnDepthConfig> = {
  maxCrossToolDepth: 8,
  maxDistinctToolsInWindow: 6,
  escalateBeforeDeny: true,
};

function mergeConfig(c?: ToolTurnDepthConfig): Required<ToolTurnDepthConfig> {
  return { ...DEFAULT_CONFIG, ...c };
}

/**
 * Per-session cross-tool depth / recursive opportunity counters (D3).
 * Orthogonal to ToolCallBudgetStore same-tool volume.
 */
export class ToolTurnDepthStore {
  private stats = new Map<string, SessionToolTurnDepthStats>();

  get(sessionId: string): SessionToolTurnDepthStats {
    const cur = this.stats.get(sessionId);
    if (!cur) {
      return {
        crossToolDepth: 0,
        toolsSeen: [],
        escalations: 0,
        lastTool: null,
      };
    }
    return {
      ...cur,
      toolsSeen: [...cur.toolsSeen],
    };
  }

  record(input: ToolTurnDepthRecordInput): SessionToolTurnDepthStats {
    const cur = this.stats.get(input.sessionId) ?? {
      crossToolDepth: 0,
      toolsSeen: [] as string[],
      escalations: 0,
      lastTool: null as string | null,
    };
    cur.crossToolDepth += 1;
    if (!cur.toolsSeen.includes(input.tool)) {
      cur.toolsSeen.push(input.tool);
    }
    cur.lastTool = input.tool;
    this.stats.set(input.sessionId, cur);
    return this.get(input.sessionId);
  }

  markEscalated(sessionId: string): SessionToolTurnDepthStats {
    const cur = this.stats.get(sessionId) ?? {
      crossToolDepth: 0,
      toolsSeen: [] as string[],
      escalations: 0,
      lastTool: null as string | null,
    };
    cur.escalations += 1;
    this.stats.set(sessionId, cur);
    return this.get(sessionId);
  }

  clear(sessionId?: string): void {
    if (!sessionId) {
      this.stats.clear();
      return;
    }
    this.stats.delete(sessionId);
  }

  size(): number {
    return this.stats.size;
  }
}

/**
 * Check D3 cross-tool depth / recursive opportunity.
 * Does NOT replace same-tool CDoSCap — compose only.
 */
export function checkToolTurnDepth(
  store: ToolTurnDepthStore,
  input: ToolTurnDepthCheckInput,
): ToolTurnDepthCheckResult {
  if (!input?.sessionId || !input.tool) {
    return {
      verdict: 'DENY_DEPTH',
      gate: 'D3ToolTurnDepth.DENY_bad_input',
      crossToolDepth: 0,
      distinctTools: 0,
      maxCrossToolDepth: DEFAULT_CONFIG.maxCrossToolDepth,
      maxDistinctToolsInWindow: DEFAULT_CONFIG.maxDistinctToolsInWindow,
      composeSameToolCdos: !!input?.sameToolCdosChecked,
      escalate: true,
      reason: 'sessionId + tool required for D3 tool-turn depth',
    };
  }

  const cfg = mergeConfig(input.config);
  const cur = store.get(input.sessionId);
  const nextDepth = cur.crossToolDepth + 1;
  const distinctSet = new Set(cur.toolsSeen);
  distinctSet.add(input.tool);
  const distinctTools = distinctSet.size;
  const composeSameToolCdos = input.sameToolCdosChecked === true;

  const overDepth = nextDepth > cfg.maxCrossToolDepth;
  const overDistinct = distinctTools > cfg.maxDistinctToolsInWindow;

  if (!overDepth && !overDistinct) {
    return {
      verdict: 'ALLOW',
      gate: composeSameToolCdos
        ? 'D3ToolTurnDepth.COMPOSE_CDOS'
        : 'D3ToolTurnDepth.ALLOW',
      crossToolDepth: nextDepth,
      distinctTools,
      maxCrossToolDepth: cfg.maxCrossToolDepth,
      maxDistinctToolsInWindow: cfg.maxDistinctToolsInWindow,
      composeSameToolCdos,
      escalate: false,
      reason: composeSameToolCdos
        ? 'D3 depth OK — composed with same-tool CDoSCap (volume stays)'
        : undefined,
    };
  }

  const reason = overDepth
    ? `D3 cross-tool depth trip: ${nextDepth} > max ${cfg.maxCrossToolDepth}`
    : `D3 recursive opportunity trip: ${distinctTools} distinct tools > max ${cfg.maxDistinctToolsInWindow}`;

  if (cfg.escalateBeforeDeny && cur.escalations === 0) {
    return {
      verdict: 'HITL',
      gate: 'D3ToolTurnDepth.HITL',
      crossToolDepth: nextDepth,
      distinctTools,
      maxCrossToolDepth: cfg.maxCrossToolDepth,
      maxDistinctToolsInWindow: cfg.maxDistinctToolsInWindow,
      composeSameToolCdos,
      reason: `${reason} → HITL (compose same-tool CDoSCap; do not replace volume)`,
      escalate: true,
    };
  }

  return {
    verdict: 'DENY_DEPTH',
    gate: 'D3ToolTurnDepth.DENY_DEPTH',
    crossToolDepth: nextDepth,
    distinctTools,
    maxCrossToolDepth: cfg.maxCrossToolDepth,
    maxDistinctToolsInWindow: cfg.maxDistinctToolsInWindow,
    composeSameToolCdos,
    reason: `${reason} → DENY depth (volume cap still separate)`,
    escalate: true,
  };
}

/**
 * Check then record on ALLOW; markEscalated on HITL; DENY does not record depth growth.
 */
export function gateToolTurnDepth(
  store: ToolTurnDepthStore,
  input: ToolTurnDepthCheckInput,
): ToolTurnDepthCheckResult {
  const check = checkToolTurnDepth(store, input);
  if (check.verdict === 'ALLOW') {
    store.record({
      sessionId: input.sessionId,
      tool: input.tool,
      parentTool: input.parentTool,
    });
  } else if (check.verdict === 'HITL') {
    store.markEscalated(input.sessionId);
  }
  return check;
}
