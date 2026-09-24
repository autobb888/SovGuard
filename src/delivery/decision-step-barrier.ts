/**
 * ChronosAttack / Tool Order thin land A — Decision-step barrier.
 *
 * Buffer all tool observations for one logical decision; present in
 * **canonical tool order** (stable sort by tool name then id). Arrival
 * timing must NOT determine the serialization seen by the model.
 *
 * Soft residual (NOT this land): async host wait-until-quiescence wire.
 * Orthogonal: ActionGuard (content), PeerRegistry (identity), A2M return
 * IFC / C-DoS (content/volume), ControlToken assessTraceToolComposite (CoT).
 *
 * KPI = barrier + canonical order. Not deepset 80%. Escalate BLOCK.
 * Shapes only — do not clone ChronosAttack kit.
 */

/** One authentic tool observation enrolled into a decision-step barrier. */
export interface ToolObservation {
  /** Stable observation id (unique within a decision). */
  id: string;
  /** Tool / peer name used for canonical ordering. */
  toolName: string;
  /** Authentic payload (content not poisoned — Chronos is delay-only). */
  payload: unknown;
  /** Optional arrival timestamp (ms); ignored for serialization order. */
  arrivedAt?: number;
}

export type BarrierState = 'open' | 'sealed';

export interface DecisionStep {
  decisionId: string;
  state: BarrierState;
  observations: ToolObservation[];
  sealedAt?: number;
}

export type BarrierVerdict = 'BUFFERED' | 'SEALED' | 'DENY';

export type BarrierGate =
  | 'DecisionStepBarrier.BUFFERED'
  | 'DecisionStepBarrier.SEALED'
  | 'DecisionStepBarrier.DENY_sealed'
  | 'DecisionStepBarrier.DENY_missing'
  | 'DecisionStepBarrier.DENY_duplicate_id';

export interface EnrollResult {
  verdict: BarrierVerdict;
  gate: BarrierGate;
  decisionId: string;
  bufferedCount: number;
  reason?: string;
}

export interface SealResult {
  verdict: 'SEALED' | 'DENY';
  gate: BarrierGate;
  decisionId: string;
  canonicalOrder: ToolObservation[];
  reason?: string;
}

export interface SerializeForModelResult {
  decisionId: string;
  /** Serialization order presented to the model — ALWAYS canonical, never arrival. */
  order: ToolObservation[];
  /** Stable string form: toolName::id in canonical sequence. */
  serialized: string;
  sealed: boolean;
}

/**
 * Stable canonical comparator: toolName ASC, then id ASC.
 * Arrival timing / enrollment order must not affect this.
 */
export function compareCanonical(a: ToolObservation, b: ToolObservation): number {
  const byName = String(a.toolName ?? '').localeCompare(String(b.toolName ?? ''), 'en');
  if (byName !== 0) return byName;
  return String(a.id ?? '').localeCompare(String(b.id ?? ''), 'en');
}

/** Sort a list into canonical tool order (does not mutate input). */
export function canonicalToolOrder(observations: ToolObservation[]): ToolObservation[] {
  return [...observations].sort(compareCanonical);
}

/** Serialize canonical order for model presentation. */
export function serializeCanonical(observations: ToolObservation[]): string {
  return canonicalToolOrder(observations)
    .map((o) => `${o.toolName}::${o.id}`)
    .join('|');
}

export interface DecisionStepBarrierOptions {
  /** Max observations buffered per decision (default 32). */
  maxObservationsPerDecision?: number;
}

/**
 * Decision-step barrier: buffer peers for one logical decision, flush in
 * canonical tool-name order. Host soft wire (wait-until-quiescence) is
 * product follow-on — engine exposes buffer + canonicalize only.
 */
export class DecisionStepBarrier {
  private steps = new Map<string, DecisionStep>();
  private readonly maxObs: number;

  constructor(opts?: DecisionStepBarrierOptions) {
    this.maxObs = opts?.maxObservationsPerDecision ?? 32;
  }

  /** Open (or reuse open) decision and enroll one authentic observation. */
  enrollObservation(decisionId: string, obs: ToolObservation): EnrollResult {
    const id = String(decisionId ?? '').trim();
    if (!id) {
      return {
        verdict: 'DENY',
        gate: 'DecisionStepBarrier.DENY_missing',
        decisionId: id,
        bufferedCount: 0,
        reason: 'missing decisionId',
      };
    }
    if (!obs || !String(obs.id ?? '').trim() || !String(obs.toolName ?? '').trim()) {
      return {
        verdict: 'DENY',
        gate: 'DecisionStepBarrier.DENY_missing',
        decisionId: id,
        bufferedCount: 0,
        reason: 'observation requires id and toolName',
      };
    }

    let step = this.steps.get(id);
    if (!step) {
      step = { decisionId: id, state: 'open', observations: [] };
      this.steps.set(id, step);
    }
    if (step.state === 'sealed') {
      return {
        verdict: 'DENY',
        gate: 'DecisionStepBarrier.DENY_sealed',
        decisionId: id,
        bufferedCount: step.observations.length,
        reason: 'decision already sealed — late obs must use SessionScorer order-flip path',
      };
    }
    if (step.observations.some((o) => o.id === obs.id)) {
      return {
        verdict: 'DENY',
        gate: 'DecisionStepBarrier.DENY_duplicate_id',
        decisionId: id,
        bufferedCount: step.observations.length,
        reason: `duplicate observation id ${obs.id}`,
      };
    }
    if (step.observations.length >= this.maxObs) {
      return {
        verdict: 'DENY',
        gate: 'DecisionStepBarrier.DENY_missing',
        decisionId: id,
        bufferedCount: step.observations.length,
        reason: `max observations (${this.maxObs}) reached`,
      };
    }

    step.observations.push({
      id: String(obs.id),
      toolName: String(obs.toolName),
      payload: obs.payload,
      arrivedAt: obs.arrivedAt,
    });

    return {
      verdict: 'BUFFERED',
      gate: 'DecisionStepBarrier.BUFFERED',
      decisionId: id,
      bufferedCount: step.observations.length,
    };
  }

  /** Seal decision — further enrolls DENY; presentation uses canonical order. */
  sealDecision(decisionId: string): SealResult {
    const step = this.steps.get(String(decisionId ?? '').trim());
    if (!step) {
      return {
        verdict: 'DENY',
        gate: 'DecisionStepBarrier.DENY_missing',
        decisionId: String(decisionId ?? ''),
        canonicalOrder: [],
        reason: 'unknown decisionId',
      };
    }
    step.state = 'sealed';
    step.sealedAt = Date.now();
    const canonicalOrder = canonicalToolOrder(step.observations);
    return {
      verdict: 'SEALED',
      gate: 'DecisionStepBarrier.SEALED',
      decisionId: step.decisionId,
      canonicalOrder,
    };
  }

  /** Canonical tool order for a decision (works open or sealed). */
  getCanonicalOrder(decisionId: string): ToolObservation[] {
    const step = this.steps.get(String(decisionId ?? '').trim());
    if (!step) return [];
    return canonicalToolOrder(step.observations);
  }

  /**
   * Serialization seen by the model — ALWAYS canonical tool order.
   * Arrival / enrollment order must not appear here.
   */
  serializeForModel(decisionId: string): SerializeForModelResult {
    const step = this.steps.get(String(decisionId ?? '').trim());
    if (!step) {
      return {
        decisionId: String(decisionId ?? ''),
        order: [],
        serialized: '',
        sealed: false,
      };
    }
    const order = canonicalToolOrder(step.observations);
    return {
      decisionId: step.decisionId,
      order,
      serialized: serializeCanonical(order),
      sealed: step.state === 'sealed',
    };
  }

  /** Arrival / enrollment order (diagnostic only — never present to model). */
  getArrivalOrder(decisionId: string): ToolObservation[] {
    const step = this.steps.get(String(decisionId ?? '').trim());
    if (!step) return [];
    return [...step.observations];
  }

  getState(decisionId: string): BarrierState | undefined {
    return this.steps.get(String(decisionId ?? '').trim())?.state;
  }

  clear(decisionId: string): void {
    this.steps.delete(String(decisionId ?? '').trim());
  }

  get size(): number {
    return this.steps.size;
  }
}
