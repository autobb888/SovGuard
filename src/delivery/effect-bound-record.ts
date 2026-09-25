/**
 * ApprovalLaundering thin land A — Effect-bound Pred₆ card.
 *
 * Before ALLOW, freeze predicted Ω₆ classes (process / file / env / network /
 * container / MCP) + provenance digests (package.json / lockfile / Dockerfile /
 * `.mcp.json` / hooks) into a companion EffectBoundRecord.
 *
 * Compose with ApprovalBinding entry digest bind — do NOT replace it.
 * Soft-compose ActionGuard (do not stretch as Pred₆ predictor).
 * Escalate BLOCK. Not deepset 80%. Shapes only — no Approval Laundering PoC/kit.
 */

import { createHash } from 'node:crypto';
import { stableStringify } from './approval-binding.js';

/** Ω₆ effect classes predicted before ALLOW. */
export type Omega6Class =
  | 'process'
  | 'file'
  | 'env'
  | 'network'
  | 'container'
  | 'MCP';

export const OMEGA6_CLASSES: readonly Omega6Class[] = [
  'process',
  'file',
  'env',
  'network',
  'container',
  'MCP',
] as const;

/** Provenance artifact keys whose digests freeze into the card. */
export type ProvenanceKey =
  | 'package.json'
  | 'lockfile'
  | 'Dockerfile'
  | '.mcp.json'
  | 'hooks';

export const PROVENANCE_KEYS: readonly ProvenanceKey[] = [
  'package.json',
  'lockfile',
  'Dockerfile',
  '.mcp.json',
  'hooks',
] as const;

export interface ProvenanceInput {
  /** Raw content or already-known digest hex. Prefer content for freeze. */
  content?: string | Buffer | null;
  /** Precomputed sha256 hex (used when content absent). */
  digest?: string | null;
}

export interface FreezePred6Input {
  /** Predicted Ω₆ classes for this approval card. */
  omega6Classes: readonly Omega6Class[];
  /**
   * Provenance artifacts to digest. Missing keys may be omitted; present keys
   * freeze a sha256 (empty content → empty digest marker, still frozen).
   */
  provenance?: Partial<Record<ProvenanceKey, ProvenanceInput | string | Buffer | null>>;
  /** Optional companion link to ApprovalBinding entry digest (compose only). */
  entryDigest?: string | null;
  /** Optional ticket / approval id for diagnostics. */
  approvalId?: string | null;
  /** Host-supplied notes (shape-level only). */
  notes?: string;
}

export interface EffectBoundRecord {
  /** Frozen Ω₆ class set (sorted unique). */
  omega6Classes: Omega6Class[];
  /** sha256 hex per provenance key that was supplied. */
  provenanceDigests: Partial<Record<ProvenanceKey, string>>;
  /** Companion entry digest from ApprovalBinding — compose, never replace. */
  entryDigest: string | null;
  approvalId: string | null;
  /** Wall-clock freeze instant (ms). */
  frozenAt: number;
  /** True only when freezePred6BeforeAllow succeeded with ≥1 class. */
  frozenBeforeAllow: boolean;
  notes?: string;
}

export type EffectBoundGate =
  | 'EffectBound.FROZEN'
  | 'EffectBound.DENY_empty_pred6'
  | 'EffectBound.DENY_bad_input';

export interface FreezePred6Result {
  ok: boolean;
  record?: EffectBoundRecord;
  gate: EffectBoundGate;
  reason?: string;
  /** True when caller must not ALLOW without a frozen card. */
  escalate: boolean;
}

/** sha256 hex of string/Buffer content. */
export function digestProvenanceContent(content: string | Buffer): string {
  return createHash('sha256').update(content).digest('hex');
}

function normalizeProvenance(
  input?: FreezePred6Input['provenance'],
): Partial<Record<ProvenanceKey, string>> {
  const out: Partial<Record<ProvenanceKey, string>> = {};
  if (!input) return out;
  for (const key of PROVENANCE_KEYS) {
    const v = input[key];
    if (v === undefined || v === null) continue;
    if (typeof v === 'string' || Buffer.isBuffer(v)) {
      out[key] = digestProvenanceContent(v);
      continue;
    }
    const pi = v as ProvenanceInput;
    if (pi.digest && typeof pi.digest === 'string' && pi.digest.length > 0) {
      out[key] = pi.digest;
    } else if (pi.content !== undefined && pi.content !== null) {
      out[key] = digestProvenanceContent(pi.content);
    } else {
      // Present-but-empty: freeze empty marker so card still records the key.
      out[key] = digestProvenanceContent('');
    }
  }
  return out;
}

function normalizeClasses(classes: readonly Omega6Class[]): Omega6Class[] {
  const set = new Set<Omega6Class>();
  for (const c of classes ?? []) {
    if ((OMEGA6_CLASSES as readonly string[]).includes(c)) {
      set.add(c);
    }
  }
  return OMEGA6_CLASSES.filter((c) => set.has(c));
}

/**
 * Freeze Pred₆ + provenance digests BEFORE ALLOW.
 * Returns DENY_empty_pred6 when no valid Ω₆ classes — host must not ALLOW.
 * Entry digest is recorded as companion only (does not replace ApprovalBinding).
 */
export function freezePred6BeforeAllow(input: FreezePred6Input): FreezePred6Result {
  if (!input || !Array.isArray(input.omega6Classes)) {
    return {
      ok: false,
      gate: 'EffectBound.DENY_bad_input',
      escalate: true,
      reason: 'omega6Classes array required before ALLOW',
    };
  }

  const omega6Classes = normalizeClasses(input.omega6Classes);
  if (omega6Classes.length === 0) {
    return {
      ok: false,
      gate: 'EffectBound.DENY_empty_pred6',
      escalate: true,
      reason: 'ALLOW refused — Pred₆ card empty; freeze Ω₆ classes before ALLOW',
    };
  }

  const provenanceDigests = normalizeProvenance(input.provenance);
  const record: EffectBoundRecord = {
    omega6Classes,
    provenanceDigests,
    entryDigest: input.entryDigest ?? null,
    approvalId: input.approvalId ?? null,
    frozenAt: Date.now(),
    frozenBeforeAllow: true,
    notes: input.notes,
  };

  return {
    ok: true,
    record,
    gate: 'EffectBound.FROZEN',
    escalate: false,
    reason: 'Pred₆ + provenance frozen before ALLOW (compose with entry digest)',
  };
}

/** Stable digest of an EffectBoundRecord for diagnostics / compose checks. */
export function digestEffectBoundRecord(record: EffectBoundRecord): string {
  return createHash('sha256')
    .update(
      stableStringify({
        omega6Classes: record.omega6Classes,
        provenanceDigests: record.provenanceDigests,
        entryDigest: record.entryDigest ?? '',
      }),
    )
    .digest('hex');
}

/**
 * Guard: ALLOW only when a frozen EffectBoundRecord is present.
 * Does not perform entry-bind compare — that stays in ApprovalBinding.
 */
export function requireFrozenPred6BeforeAllow(
  record: EffectBoundRecord | null | undefined,
): { allow: boolean; reason?: string; escalate: boolean } {
  if (!record || record.frozenBeforeAllow !== true || !record.omega6Classes?.length) {
    return {
      allow: false,
      escalate: true,
      reason: 'ALLOW blocked — EffectBoundRecord Pred₆ not frozen before ALLOW',
    };
  }
  return { allow: true, escalate: false };
}
