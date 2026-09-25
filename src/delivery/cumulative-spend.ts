/**
 * PersistentBillable thin land E — D4 CumulativeSpend + ProgressAuthorized.
 *
 * Session cumulative spend ceiling; exemptions require **host-verified**
 * milestones (API accepts only host-signed / host-set milestones —
 * reject model self-report).
 *
 * Compose with ToolCallBudgetStore per-invocation weighted cost (volume/cost ≠
 * session cumulative spend). Soft C-DoS owned on PersistentBillable track.
 * Escalate BLOCK. Not deepset 80%. Shapes only — no DoW PoC/kit.
 */

import { createHash } from 'node:crypto';

export type CumulativeSpendVerdict =
  | 'ALLOW'
  | 'HITL'
  | 'DENY_SPEND'
  | 'ALLOW_PROGRESS_AUTHORIZED';

export type CumulativeSpendGateId =
  | 'D4CumulativeSpend.ALLOW'
  | 'D4CumulativeSpend.HITL'
  | 'D4CumulativeSpend.DENY_SPEND'
  | 'D4CumulativeSpend.ALLOW_PROGRESS_AUTHORIZED'
  | 'D4CumulativeSpend.DENY_model_self_report'
  | 'D4CumulativeSpend.DENY_bad_input';

export interface CumulativeSpendConfig {
  /** Session cumulative spend ceiling in abstract cost units (default 10000). */
  sessionSpendCeiling?: number;
  /** Soft trip ratio before HITL (default 0.85). */
  softTripRatio?: number;
  /** Escalate HITL before hard DENY (default true). */
  escalateBeforeDeny?: boolean;
}

export interface HostMilestone {
  /** Milestone id set by host. */
  id: string;
  /** Host-signed or host-set attestation token (required). */
  hostAttestation: string;
  /** Spend budget unlocked by this milestone (additional units). */
  unlockSpendUnits: number;
  /** Wall-clock set by host (ms). */
  hostSetAt: number;
  /** Optional notes. */
  notes?: string;
  /**
   * Must be true and set only via recordHostVerifiedMilestone.
   * Model-supplied objects with this forged true are rejected.
   */
  hostVerified: true;
}

export interface ModelProgressClaim {
  /** Model self-reported progress label — NEVER sufficient alone. */
  claimedMilestoneId?: string;
  claimedProgress?: string;
  claimedSpendExemption?: boolean;
}

export interface CumulativeSpendCheckInput {
  sessionId: string;
  /** Proposed additional spend this turn. */
  proposedSpend: number;
  /** Optional model self-report — rejected as exemption basis. */
  modelClaim?: ModelProgressClaim | null;
  /**
   * Optional host milestone id already recorded via recordHostVerifiedMilestone.
   * Only host-verified milestones unlock exemptions.
   */
  hostMilestoneId?: string | null;
  config?: CumulativeSpendConfig;
}

export interface CumulativeSpendCheckResult {
  verdict: CumulativeSpendVerdict;
  gate: CumulativeSpendGateId;
  cumulativeSpend: number;
  sessionSpendCeiling: number;
  effectiveCeiling: number;
  progressAuthorized: boolean;
  modelSelfReportRejected: boolean;
  reason?: string;
  escalate: boolean;
}

export interface SessionCumulativeSpendStats {
  cumulativeSpend: number;
  escalations: number;
  /** Host-verified milestone ids. */
  hostMilestoneIds: string[];
  /** Extra ceiling unlocked by host milestones. */
  unlockedSpendUnits: number;
}

const DEFAULT_CONFIG: Required<CumulativeSpendConfig> = {
  sessionSpendCeiling: 10000,
  softTripRatio: 0.85,
  escalateBeforeDeny: true,
};

function mergeConfig(c?: CumulativeSpendConfig): Required<CumulativeSpendConfig> {
  return { ...DEFAULT_CONFIG, ...c };
}

/** Stable digest of host attestation material. */
export function digestHostAttestation(attestation: string): string {
  return createHash('sha256').update(attestation).digest('hex');
}

/**
 * Per-session cumulative spend + host-verified milestones (D4).
 * Model self-report never unlocks ceiling.
 */
export class CumulativeSpendStore {
  private stats = new Map<string, SessionCumulativeSpendStats>();
  /** sessionId::milestoneId → HostMilestone (host-verified only). */
  private milestones = new Map<string, HostMilestone>();

  private mKey(sessionId: string, milestoneId: string): string {
    return `${sessionId}::${milestoneId}`;
  }

  get(sessionId: string): SessionCumulativeSpendStats {
    const cur = this.stats.get(sessionId);
    if (!cur) {
      return {
        cumulativeSpend: 0,
        escalations: 0,
        hostMilestoneIds: [],
        unlockedSpendUnits: 0,
      };
    }
    return { ...cur, hostMilestoneIds: [...cur.hostMilestoneIds] };
  }

  /**
   * Host-only API: record a verified milestone.
   * Rejects payloads that look like model self-report (missing attestation,
   * hostVerified !== true, or empty attestation).
   */
  recordHostVerifiedMilestone(
    sessionId: string,
    milestone: Omit<HostMilestone, 'hostVerified'> & { hostVerified?: boolean },
  ): { ok: boolean; reason?: string; milestone?: HostMilestone } {
    if (!sessionId || !milestone?.id) {
      return { ok: false, reason: 'sessionId + milestone.id required' };
    }
    if (!milestone.hostAttestation || milestone.hostAttestation.trim().length === 0) {
      return {
        ok: false,
        reason: 'hostAttestation required — model self-report rejected',
      };
    }
    // Explicit reject when caller tries to pass hostVerified:false or omit with a model claim shape.
    if (milestone.hostVerified === false) {
      return {
        ok: false,
        reason: 'hostVerified must be set by host API — model self-report rejected',
      };
    }

    const sealed: HostMilestone = {
      id: milestone.id,
      hostAttestation: milestone.hostAttestation,
      unlockSpendUnits: Math.max(0, milestone.unlockSpendUnits ?? 0),
      hostSetAt: milestone.hostSetAt ?? Date.now(),
      notes: milestone.notes,
      hostVerified: true,
    };

    this.milestones.set(this.mKey(sessionId, sealed.id), sealed);
    const cur = this.stats.get(sessionId) ?? {
      cumulativeSpend: 0,
      escalations: 0,
      hostMilestoneIds: [] as string[],
      unlockedSpendUnits: 0,
    };
    if (!cur.hostMilestoneIds.includes(sealed.id)) {
      cur.hostMilestoneIds.push(sealed.id);
      cur.unlockedSpendUnits += sealed.unlockSpendUnits;
    }
    this.stats.set(sessionId, cur);
    return { ok: true, milestone: sealed };
  }

  getHostMilestone(sessionId: string, milestoneId: string): HostMilestone | null {
    return this.milestones.get(this.mKey(sessionId, milestoneId)) ?? null;
  }

  /** Reject helper: model self-report can never mint a milestone. */
  rejectModelSelfReportMilestone(
    _sessionId: string,
    claim: ModelProgressClaim,
  ): { ok: false; gate: 'D4CumulativeSpend.DENY_model_self_report'; reason: string } {
    return {
      ok: false,
      gate: 'D4CumulativeSpend.DENY_model_self_report',
      reason: `model self-report rejected as progress-authorized exemption (claimed=${claim.claimedMilestoneId ?? claim.claimedProgress ?? 'n/a'})`,
    };
  }

  recordSpend(sessionId: string, units: number): SessionCumulativeSpendStats {
    const cur = this.stats.get(sessionId) ?? {
      cumulativeSpend: 0,
      escalations: 0,
      hostMilestoneIds: [] as string[],
      unlockedSpendUnits: 0,
    };
    cur.cumulativeSpend += Math.max(0, units);
    this.stats.set(sessionId, cur);
    return this.get(sessionId);
  }

  markEscalated(sessionId: string): SessionCumulativeSpendStats {
    const cur = this.stats.get(sessionId) ?? {
      cumulativeSpend: 0,
      escalations: 0,
      hostMilestoneIds: [] as string[],
      unlockedSpendUnits: 0,
    };
    cur.escalations += 1;
    this.stats.set(sessionId, cur);
    return this.get(sessionId);
  }

  clear(sessionId?: string): void {
    if (!sessionId) {
      this.stats.clear();
      this.milestones.clear();
      return;
    }
    this.stats.delete(sessionId);
    for (const k of [...this.milestones.keys()]) {
      if (k.startsWith(`${sessionId}::`)) this.milestones.delete(k);
    }
  }

  size(): number {
    return this.stats.size;
  }
}

/**
 * Check D4 cumulative spend. Model self-report never authorizes exemption.
 * Host-verified milestones may raise effective ceiling.
 */
export function checkCumulativeSpend(
  store: CumulativeSpendStore,
  input: CumulativeSpendCheckInput,
): CumulativeSpendCheckResult {
  if (!input?.sessionId) {
    return {
      verdict: 'DENY_SPEND',
      gate: 'D4CumulativeSpend.DENY_bad_input',
      cumulativeSpend: 0,
      sessionSpendCeiling: DEFAULT_CONFIG.sessionSpendCeiling,
      effectiveCeiling: DEFAULT_CONFIG.sessionSpendCeiling,
      progressAuthorized: false,
      modelSelfReportRejected: false,
      escalate: true,
      reason: 'sessionId required for D4 cumulative spend',
    };
  }

  const cfg = mergeConfig(input.config);
  const cur = store.get(input.sessionId);
  const proposed = Math.max(0, input.proposedSpend);
  const nextSpend = cur.cumulativeSpend + proposed;
  const effectiveCeiling = cfg.sessionSpendCeiling + cur.unlockedSpendUnits;

  // Model self-report path: always reject as exemption basis.
  let modelSelfReportRejected = false;
  if (
    input.modelClaim &&
    (input.modelClaim.claimedSpendExemption ||
      input.modelClaim.claimedMilestoneId ||
      input.modelClaim.claimedProgress)
  ) {
    modelSelfReportRejected = true;
    // If they ONLY have a model claim (no host milestone), and would exceed ceiling → deny with explicit gate.
    const hostOk =
      !!input.hostMilestoneId &&
      !!store.getHostMilestone(input.sessionId, input.hostMilestoneId)?.hostVerified;
    if (!hostOk && nextSpend > effectiveCeiling) {
      return {
        verdict: 'DENY_SPEND',
        gate: 'D4CumulativeSpend.DENY_model_self_report',
        cumulativeSpend: nextSpend,
        sessionSpendCeiling: cfg.sessionSpendCeiling,
        effectiveCeiling,
        progressAuthorized: false,
        modelSelfReportRejected: true,
        reason: store.rejectModelSelfReportMilestone(input.sessionId, input.modelClaim).reason,
        escalate: true,
      };
    }
  }

  let progressAuthorized = false;
  if (input.hostMilestoneId) {
    const m = store.getHostMilestone(input.sessionId, input.hostMilestoneId);
    if (m?.hostVerified === true) {
      progressAuthorized = true;
    } else {
      // Claimed host id but not recorded via host API → treat as model forge.
      modelSelfReportRejected = true;
      return {
        verdict: 'DENY_SPEND',
        gate: 'D4CumulativeSpend.DENY_model_self_report',
        cumulativeSpend: nextSpend,
        sessionSpendCeiling: cfg.sessionSpendCeiling,
        effectiveCeiling,
        progressAuthorized: false,
        modelSelfReportRejected: true,
        reason:
          'hostMilestoneId not host-verified — model/self-reported milestone rejected',
        escalate: true,
      };
    }
  }

  if (nextSpend <= effectiveCeiling) {
    return {
      verdict: progressAuthorized ? 'ALLOW_PROGRESS_AUTHORIZED' : 'ALLOW',
      gate: progressAuthorized
        ? 'D4CumulativeSpend.ALLOW_PROGRESS_AUTHORIZED'
        : 'D4CumulativeSpend.ALLOW',
      cumulativeSpend: nextSpend,
      sessionSpendCeiling: cfg.sessionSpendCeiling,
      effectiveCeiling,
      progressAuthorized,
      modelSelfReportRejected,
      escalate: false,
    };
  }

  // Over ceiling.
  const soft = effectiveCeiling * cfg.softTripRatio;
  const reason = `D4 cumulative spend trip: ${nextSpend} > ceiling ${effectiveCeiling}` +
    (modelSelfReportRejected ? ' (model self-report rejected)' : '');

  if (cfg.escalateBeforeDeny && cur.escalations === 0 && nextSpend <= effectiveCeiling * 1.25) {
    return {
      verdict: 'HITL',
      gate: 'D4CumulativeSpend.HITL',
      cumulativeSpend: nextSpend,
      sessionSpendCeiling: cfg.sessionSpendCeiling,
      effectiveCeiling,
      progressAuthorized: false,
      modelSelfReportRejected,
      reason: `${reason} → HITL (need host-verified milestone for exemption)`,
      escalate: true,
    };
  }

  // Soft band also HITL first when under soft*1.0 already exceeded but escalate path.
  if (cfg.escalateBeforeDeny && cur.escalations === 0 && nextSpend > soft) {
    return {
      verdict: 'HITL',
      gate: 'D4CumulativeSpend.HITL',
      cumulativeSpend: nextSpend,
      sessionSpendCeiling: cfg.sessionSpendCeiling,
      effectiveCeiling,
      progressAuthorized: false,
      modelSelfReportRejected,
      reason: `${reason} → HITL`,
      escalate: true,
    };
  }

  return {
    verdict: 'DENY_SPEND',
    gate: 'D4CumulativeSpend.DENY_SPEND',
    cumulativeSpend: nextSpend,
    sessionSpendCeiling: cfg.sessionSpendCeiling,
    effectiveCeiling,
    progressAuthorized: false,
    modelSelfReportRejected,
    reason: `${reason} → DENY spend`,
    escalate: true,
  };
}

/**
 * Check then record spend on ALLOW / ALLOW_PROGRESS_AUTHORIZED;
 * markEscalated on HITL; DENY does not record spend.
 */
export function gateCumulativeSpend(
  store: CumulativeSpendStore,
  input: CumulativeSpendCheckInput,
): CumulativeSpendCheckResult {
  const check = checkCumulativeSpend(store, input);
  if (
    check.verdict === 'ALLOW' ||
    check.verdict === 'ALLOW_PROGRESS_AUTHORIZED'
  ) {
    store.recordSpend(input.sessionId, input.proposedSpend);
  } else if (check.verdict === 'HITL') {
    store.markEscalated(input.sessionId);
  }
  return check;
}
