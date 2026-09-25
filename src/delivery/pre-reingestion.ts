/**
 * PersistentBillable thin land A — PreReingestionGate.
 *
 * Before the next billable model call, transform / compress / tombstone
 * untrusted tool returns (`source=mcp_result` and peers). Raw retained mass
 * must NOT re-enter the prompt unchanged.
 *
 * Compose with applyReturnIfc / labelToolReturn (trust label ≠ pre-reingestion)
 * and ToolCallBudgetStore volume (volume ≠ retained-mass). Soft host wire before
 * provider call. Soft C-DoS owned on PersistentBillable track.
 * Escalate BLOCK. Not deepset 80%. Shapes only — no DoW PoC/kit.
 */

import { createHash } from 'node:crypto';

/** Sources treated as untrusted retained returns (mcp_result + peers). */
export const UNTRUSTED_RETURN_SOURCES = [
  'mcp_result',
  'api_response',
  'tool_result',
  'peer_return',
  'untrusted_tool_return',
] as const;

export type UntrustedReturnSource = (typeof UNTRUSTED_RETURN_SOURCES)[number] | string;

export type PreReingestionVerdict =
  | 'ALLOW_TRANSFORMED'
  | 'TOMBSTONE'
  | 'HITL'
  | 'DENY_RAW_REENTER';

export type PreReingestionGateId =
  | 'PreReingestion.ALLOW_TRANSFORMED'
  | 'PreReingestion.TOMBSTONE'
  | 'PreReingestion.HITL'
  | 'PreReingestion.DENY_RAW_REENTER'
  | 'PreReingestion.ALLOW_trusted'
  | 'PreReingestion.DENY_bad_input';

export type PreReingestionPolicy = 'compress' | 'tombstone' | 'transform' | 'hitl';

export interface PreReingestInput {
  /** Raw retained tool-return body (string or JSON-like). */
  raw: string | unknown;
  /** Source channel — mcp_result and peers are gated. */
  source?: UntrustedReturnSource | null;
  /** Optional tool name (audit). */
  tool?: string | null;
  /** Prefer tombstone when raw exceeds this char length (default 4096). */
  tombstoneAboveChars?: number;
  /** Force HITL instead of silent transform (host high-value artifact). */
  requireHitl?: boolean;
  /** Host policy override. */
  policy?: PreReingestionPolicy;
  /** When true, refuse any path that would re-enter raw unchanged. */
  forbidRawReenter?: boolean;
}

export interface PreReingestResult {
  ok: boolean;
  verdict: PreReingestionVerdict | 'ALLOW';
  gate: PreReingestionGateId;
  /** Transformed / compressed / tombstoned body safe for next billable prompt. */
  transformed?: string;
  /** Digest of original raw (for recall without re-entering mass). */
  rawDigest?: string;
  /** Original char length before transform. */
  originalChars: number;
  /** Transformed char length. */
  transformedChars: number;
  /** True when raw would have re-entered unchanged — always blocked for untrusted. */
  rawReenterBlocked: boolean;
  reason?: string;
  escalate: boolean;
}

export interface ApplyPreReingestionInput {
  /** Retained untrusted returns to gate before next billable call. */
  returns: readonly PreReingestInput[];
  /** When true (default), any DENY_RAW_REENTER fails the whole batch. */
  failClosed?: boolean;
}

export interface ApplyPreReingestionResult {
  ok: boolean;
  results: PreReingestResult[];
  /** Bodies safe to fold into next billable prompt (transformed only). */
  safeBodies: string[];
  /** True when any raw re-enter was denied. */
  rawReenterBlocked: boolean;
  gate: PreReingestionGateId | 'PreReingestion.BATCH_OK' | 'PreReingestion.BATCH_DENY';
  reason?: string;
  escalate: boolean;
}

function isUntrustedSource(source?: string | null): boolean {
  if (!source) return true; // fail closed: missing source treated untrusted
  const s = source.toLowerCase();
  return (
    (UNTRUSTED_RETURN_SOURCES as readonly string[]).includes(s) ||
    s.includes('mcp') ||
    s.includes('untrusted') ||
    s.includes('peer')
  );
}

function estimateChars(raw: string | unknown): number {
  if (typeof raw === 'string') return raw.length;
  try {
    return JSON.stringify(raw)?.length ?? 0;
  } catch {
    return String(raw).length;
  }
}

function rawAsString(raw: string | unknown): string {
  if (typeof raw === 'string') return raw;
  try {
    return JSON.stringify(raw) ?? '';
  } catch {
    return String(raw);
  }
}

/** sha256 hex of raw content for tombstone recall without re-entering mass. */
export function digestRetainedRaw(raw: string | unknown): string {
  return createHash('sha256').update(rawAsString(raw)).digest('hex');
}

/**
 * Compress untrusted return: keep short digest + truncated preview.
 * Representation changes — raw mass does not re-enter unchanged.
 */
export function compressUntrustedReturn(raw: string | unknown, maxPreview = 256): string {
  const s = rawAsString(raw);
  const digest = digestRetainedRaw(s);
  const preview = s.length <= maxPreview ? s : `${s.slice(0, maxPreview)}…`;
  return `[compressed source=untrusted digest=${digest.slice(0, 16)} chars=${s.length}] ${preview}`;
}

/** Tombstone: replace body with digest-only marker (no raw mass). */
export function tombstoneUntrustedReturn(raw: string | unknown): string {
  const digest = digestRetainedRaw(raw);
  const chars = estimateChars(raw);
  return `[tombstone source=untrusted digest=${digest} chars=${chars}]`;
}

/**
 * Gate a single untrusted tool return before next billable model call.
 * Raw re-enter → DENY_RAW_REENTER. Trusted sources may ALLOW unchanged.
 */
export function preReingestUntrustedReturn(input: PreReingestInput): PreReingestResult {
  if (!input || input.raw === undefined || input.raw === null) {
    return {
      ok: false,
      verdict: 'DENY_RAW_REENTER',
      gate: 'PreReingestion.DENY_bad_input',
      originalChars: 0,
      transformedChars: 0,
      rawReenterBlocked: true,
      escalate: true,
      reason: 'pre-reingestion requires raw return body',
    };
  }

  const originalChars = estimateChars(input.raw);
  const untrusted = isUntrustedSource(input.source);
  const forbidRaw = input.forbidRawReenter !== false;

  if (!untrusted) {
    const body = rawAsString(input.raw);
    return {
      ok: true,
      verdict: 'ALLOW',
      gate: 'PreReingestion.ALLOW_trusted',
      transformed: body,
      rawDigest: digestRetainedRaw(input.raw),
      originalChars,
      transformedChars: body.length,
      rawReenterBlocked: false,
      escalate: false,
      reason: 'trusted source — raw re-enter permitted',
    };
  }

  // Untrusted: never allow raw unchanged into next billable prompt.
  if (input.requireHitl || input.policy === 'hitl') {
    return {
      ok: false,
      verdict: 'HITL',
      gate: 'PreReingestion.HITL',
      rawDigest: digestRetainedRaw(input.raw),
      originalChars,
      transformedChars: 0,
      rawReenterBlocked: true,
      escalate: true,
      reason: 'untrusted retained return → HITL before billable re-meter',
    };
  }

  const tombstoneAbove = input.tombstoneAboveChars ?? 4096;
  const preferTombstone =
    input.policy === 'tombstone' || originalChars > tombstoneAbove;

  if (preferTombstone) {
    const transformed = tombstoneUntrustedReturn(input.raw);
    return {
      ok: true,
      verdict: 'TOMBSTONE',
      gate: 'PreReingestion.TOMBSTONE',
      transformed,
      rawDigest: digestRetainedRaw(input.raw),
      originalChars,
      transformedChars: transformed.length,
      rawReenterBlocked: true,
      escalate: false,
      reason: 'untrusted return tombstoned — raw mass must not re-enter prompt',
    };
  }

  const transformed = compressUntrustedReturn(input.raw);
  // Sanity: transformed must not equal raw.
  if (forbidRaw && transformed === rawAsString(input.raw)) {
    return {
      ok: false,
      verdict: 'DENY_RAW_REENTER',
      gate: 'PreReingestion.DENY_RAW_REENTER',
      rawDigest: digestRetainedRaw(input.raw),
      originalChars,
      transformedChars: 0,
      rawReenterBlocked: true,
      escalate: true,
      reason: 'transform collapsed to raw — DENY raw re-enter before billable call',
    };
  }

  return {
    ok: true,
    verdict: 'ALLOW_TRANSFORMED',
    gate: 'PreReingestion.ALLOW_TRANSFORMED',
    transformed,
    rawDigest: digestRetainedRaw(input.raw),
    originalChars,
    transformedChars: transformed.length,
    rawReenterBlocked: true,
    escalate: false,
    reason: 'untrusted return compressed/transformed before billable call',
  };
}

/**
 * Apply pre-reingestion to a batch of retained returns before next billable call.
 * Soft host wire: call this immediately before provider completion request.
 */
export function applyPreReingestionBeforeBillable(
  input: ApplyPreReingestionInput,
): ApplyPreReingestionResult {
  if (!input || !Array.isArray(input.returns)) {
    return {
      ok: false,
      results: [],
      safeBodies: [],
      rawReenterBlocked: true,
      gate: 'PreReingestion.BATCH_DENY',
      escalate: true,
      reason: 'returns array required before billable call',
    };
  }

  const failClosed = input.failClosed !== false;
  const results = input.returns.map((r) => preReingestUntrustedReturn(r));
  const safeBodies: string[] = [];
  let rawReenterBlocked = false;
  let anyDeny = false;
  let anyHitl = false;

  for (const r of results) {
    if (r.rawReenterBlocked) rawReenterBlocked = true;
    if (r.verdict === 'DENY_RAW_REENTER' || r.gate === 'PreReingestion.DENY_bad_input') {
      anyDeny = true;
    }
    if (r.verdict === 'HITL') anyHitl = true;
    if (r.ok && r.transformed !== undefined) {
      safeBodies.push(r.transformed);
    }
  }

  if (anyDeny && failClosed) {
    return {
      ok: false,
      results,
      safeBodies: [],
      rawReenterBlocked: true,
      gate: 'PreReingestion.BATCH_DENY',
      escalate: true,
      reason: 'batch deny — raw untrusted mass must not re-enter billable prompt',
    };
  }

  if (anyHitl) {
    return {
      ok: false,
      results,
      safeBodies,
      rawReenterBlocked: true,
      gate: 'PreReingestion.HITL',
      escalate: true,
      reason: 'batch HITL — host confirm before billable re-meter',
    };
  }

  return {
    ok: true,
    results,
    safeBodies,
    rawReenterBlocked,
    gate: 'PreReingestion.BATCH_OK',
    escalate: false,
    reason: 'all untrusted returns transformed/tombstoned before billable call',
  };
}

/**
 * Assert helper: raw body must not equal proposed next-prompt fragment for untrusted.
 * Used by hosts / tests to prove DENY_RAW_REENTER path.
 */
export function denyRawReenterUntrusted(opts: {
  source?: string | null;
  raw: string | unknown;
  proposedPromptFragment: string;
}): PreReingestResult {
  const untrusted = isUntrustedSource(opts.source);
  if (untrusted && rawAsString(opts.raw) === opts.proposedPromptFragment) {
    return {
      ok: false,
      verdict: 'DENY_RAW_REENTER',
      gate: 'PreReingestion.DENY_RAW_REENTER',
      rawDigest: digestRetainedRaw(opts.raw),
      originalChars: estimateChars(opts.raw),
      transformedChars: 0,
      rawReenterBlocked: true,
      escalate: true,
      reason: 'DENY — raw untrusted retained mass re-enters prompt unchanged',
    };
  }
  return preReingestUntrustedReturn({
    raw: opts.raw,
    source: opts.source,
  });
}
