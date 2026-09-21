/**
 * Loopjacking ApprovalBinding (thin land) — exact use-time bind of HITL-approved A.
 *
 * A: digest (tool, args, destination, scope) at approve via stable stringify + sha256
 * B: use-time compare before/inside ActionGuard allow — mismatch DENY / re-approval
 * C: one-shot consume after successful release — replay DENY
 * D: refuse-lossy approve when UI view incomplete vs executable vector
 *
 * KPI = approval-binding integrity at the act gate. Not deepset 80%.
 * Orthogonal to SchemaConsent (schema hash) / argAllowlist / scanProposedToolArgs.
 */

import { createHash, randomUUID } from 'node:crypto';

/** Canonical action vector bound at HITL approve and rechecked at use-time. */
export interface ApprovalVector {
  tool: string;
  args?: Record<string, unknown>;
  destination?: string;
  scope?: string;
}

/** Host-supplied UI view of the action presented for human approve. */
export interface UiApproveView {
  tool: string;
  /** Args actually shown to the human (may omit keys). */
  shownArgs?: Record<string, unknown>;
  shownDestination?: string;
  shownScope?: string;
  /**
   * Host declares the UI was lossy vs the executable object.
   * When true, approve MUST refuse (soft residual until host can present full vector).
   */
  lossy?: boolean;
  /** Explicit keys present on executable.args but omitted from shownArgs. */
  omittedKeys?: string[];
}

export interface ApprovalTicket {
  id: string;
  /** sha256 hex of stable-stringified ApprovalVector. */
  digest: string;
  /** Snapshot of the approved vector (for diagnostics; compare uses digest). */
  vector: ApprovalVector;
  consumed: boolean;
  createdAt: number;
}

export interface ApproveActionResult {
  ok: boolean;
  ticket?: ApprovalTicket;
  reason?: string;
  /** True when refuse was due to incomplete/lossy UI vs executable. */
  refusedLossy?: boolean;
}

export interface UseTimeCompareResult {
  match: boolean;
  approvedDigest: string;
  useDigest: string;
  reason?: string;
  /** True when ticket was already consumed (replay). */
  consumed?: boolean;
  /** True when ticket id missing from store. */
  missing?: boolean;
}

export interface ReleaseApprovalResult {
  allow: boolean;
  reason?: string;
  /** Ticket was marked consumed on this successful release. */
  consumedNow?: boolean;
  compare?: UseTimeCompareResult;
}

/** Canonical JSON for hashing (sorted keys) — same shape as tool-schema stableStringify. */
export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(',')}}`;
}

/** Normalize vector fields for digest (stable key order via stableStringify). */
export function canonicalizeApprovalVector(v: ApprovalVector): Record<string, unknown> {
  return {
    tool: v.tool,
    args: v.args ?? {},
    destination: v.destination ?? '',
    scope: v.scope ?? '',
  };
}

/** sha256 hex digest of (tool, args, destination, scope). */
export function digestApprovalVector(v: ApprovalVector): string {
  return createHash('sha256')
    .update(stableStringify(canonicalizeApprovalVector(v)))
    .digest('hex');
}

/**
 * Representation completeness host contract (D).
 * Refuse when UI is lossy / incomplete vs the full executable vector.
 */
export function assertRepresentationComplete(
  uiView: UiApproveView,
  executable: ApprovalVector,
): { ok: boolean; reason?: string } {
  if (uiView.lossy === true) {
    return {
      ok: false,
      reason: 'UI approve view is lossy vs executable vector — refuse approve / require full canonical presentation',
    };
  }
  if (uiView.tool !== executable.tool) {
    return {
      ok: false,
      reason: `UI tool "${uiView.tool}" ≠ executable tool "${executable.tool}"`,
    };
  }
  const execArgs = executable.args ?? {};
  const shown = uiView.shownArgs ?? {};
  const omitted =
    uiView.omittedKeys ??
    Object.keys(execArgs).filter((k) => !Object.prototype.hasOwnProperty.call(shown, k));
  if (omitted.length > 0) {
    return {
      ok: false,
      reason: `UI omits executable arg keys: ${omitted.join(', ')} — refuse lossy approve`,
    };
  }
  // Shown destination/scope must match when host supplies them; missing shown fields
  // while executable has non-empty values are also incomplete.
  if (
    (executable.destination ?? '') !== '' &&
    uiView.shownDestination === undefined
  ) {
    return {
      ok: false,
      reason: 'UI omits destination present on executable — refuse lossy approve',
    };
  }
  if (
    uiView.shownDestination !== undefined &&
    (uiView.shownDestination ?? '') !== (executable.destination ?? '')
  ) {
    return {
      ok: false,
      reason: 'UI destination ≠ executable destination — refuse approve',
    };
  }
  if ((executable.scope ?? '') !== '' && uiView.shownScope === undefined) {
    return {
      ok: false,
      reason: 'UI omits scope present on executable — refuse lossy approve',
    };
  }
  if (
    uiView.shownScope !== undefined &&
    (uiView.shownScope ?? '') !== (executable.scope ?? '')
  ) {
    return {
      ok: false,
      reason: 'UI scope ≠ executable scope — refuse approve',
    };
  }
  // Digests of shown-only vs full executable must match when host claims complete.
  const shownVector: ApprovalVector = {
    tool: uiView.tool,
    args: shown,
    destination: uiView.shownDestination ?? executable.destination,
    scope: uiView.shownScope ?? executable.scope,
  };
  if (digestApprovalVector(shownVector) !== digestApprovalVector(executable)) {
    return {
      ok: false,
      reason: 'UI shown vector digest ≠ executable digest — refuse lossy approve',
    };
  }
  return { ok: true };
}

/**
 * HITL approve path (A + D): refuse lossy UI; else persist ApprovalTicket digest.
 */
export function approveAction(
  store: ApprovalBindingStore,
  executable: ApprovalVector,
  opts?: { uiView?: UiApproveView; ticketId?: string },
): ApproveActionResult {
  if (opts?.uiView) {
    const completeness = assertRepresentationComplete(opts.uiView, executable);
    if (!completeness.ok) {
      return {
        ok: false,
        refusedLossy: true,
        reason: completeness.reason,
      };
    }
  }
  const ticket = store.record(executable, opts?.ticketId);
  return { ok: true, ticket };
}

/** Use-time digest compare (B) — does not consume. */
export function compareApprovalAtUse(
  store: ApprovalBindingStore,
  ticketId: string,
  useTime: ApprovalVector,
): UseTimeCompareResult {
  const ticket = store.get(ticketId);
  const useDigest = digestApprovalVector(useTime);
  if (!ticket) {
    return {
      match: false,
      approvedDigest: '',
      useDigest,
      missing: true,
      reason: 'approval ticket not found — deny / require re-approval',
    };
  }
  if (ticket.consumed) {
    return {
      match: false,
      approvedDigest: ticket.digest,
      useDigest,
      consumed: true,
      reason: 'approval ticket already consumed — replay denied',
    };
  }
  if (ticket.digest !== useDigest) {
    return {
      match: false,
      approvedDigest: ticket.digest,
      useDigest,
      reason: 'use-time digest ≠ approved digest — deny / require re-approval',
    };
  }
  return {
    match: true,
    approvedDigest: ticket.digest,
    useDigest,
  };
}

/**
 * Release path (B + C): compare then consume on successful allow.
 * Replay of consumed ticket → DENY.
 */
export function releaseWithApproval(
  store: ApprovalBindingStore,
  ticketId: string,
  useTime: ApprovalVector,
): ReleaseApprovalResult {
  const compare = compareApprovalAtUse(store, ticketId, useTime);
  if (!compare.match) {
    return { allow: false, reason: compare.reason, compare };
  }
  const consumed = store.consume(ticketId);
  if (!consumed) {
    // Race / double-consume
    return {
      allow: false,
      reason: 'approval ticket already consumed — replay denied',
      compare: { ...compare, match: false, consumed: true },
    };
  }
  return { allow: true, consumedNow: true, compare };
}

/** In-memory ApprovalTicket ledger for hosts that do not persist their own. */
export class ApprovalBindingStore {
  private store = new Map<string, ApprovalTicket>();

  record(vector: ApprovalVector, ticketId?: string): ApprovalTicket {
    const id = ticketId ?? randomUUID();
    const ticket: ApprovalTicket = {
      id,
      digest: digestApprovalVector(vector),
      vector: {
        tool: vector.tool,
        args: vector.args ? { ...vector.args } : {},
        destination: vector.destination ?? '',
        scope: vector.scope ?? '',
      },
      consumed: false,
      createdAt: Date.now(),
    };
    this.store.set(id, ticket);
    return ticket;
  }

  get(ticketId: string): ApprovalTicket | undefined {
    return this.store.get(ticketId);
  }

  /**
   * Mark ticket consumed (one-shot). Returns false if missing or already consumed.
   */
  consume(ticketId: string): boolean {
    const t = this.store.get(ticketId);
    if (!t || t.consumed) return false;
    t.consumed = true;
    this.store.set(ticketId, t);
    return true;
  }

  clear(): void {
    this.store.clear();
  }

  size(): number {
    return this.store.size;
  }
}

/**
 * Build ApprovalVector from a proposed tool action + optional destination/scope.
 */
export function approvalVectorFromToolAction(
  name: string,
  args: Record<string, unknown> | undefined,
  meta?: { destination?: string; scope?: string },
): ApprovalVector {
  return {
    tool: name,
    args: args ?? {},
    destination: meta?.destination ?? '',
    scope: meta?.scope ?? '',
  };
}
