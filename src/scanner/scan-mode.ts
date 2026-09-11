/**
 * DL-011c — ScanMode router (Option C thin land).
 *
 * Routes scrub / delivery posture by declared product mode, aligned with
 * provenance `source` when mode is omitted. Does not change model weights,
 * thresholds, PIGuard, or CLF_ESCALATE enablement.
 */

import type { SourceTrust } from './context.js';

export type ScanMode = 'user_chat' | 'untrusted_content' | 'security_research';

export type ModeSource = 'explicit' | 'inferred_from_source' | 'default';

export interface ScanModeMeta {
  mode: ScanMode;
  modeSource: ModeSource;
  /** Present when mode is security_research (v1: score/flags unchanged; advisory only). */
  advisory?: true;
}

/** Sources that infer untrusted_content when mode is omitted. */
const UNTRUSTED_SOURCES: ReadonlySet<string> = new Set([
  'email',
  'file',
  'web',
  'mcp_result',
  'api',
  'job',
  'other_agent',
  // Existing SourceTrust aliases used by the engine today
  'api_response',
  'job_description',
  'workspace_file',
]);

const SCAN_MODES: ReadonlySet<string> = new Set([
  'user_chat',
  'untrusted_content',
  'security_research',
]);

export function isScanMode(value: unknown): value is ScanMode {
  return typeof value === 'string' && SCAN_MODES.has(value);
}

/**
 * Resolve product ScanMode from optional explicit mode + provenance source.
 * - Explicit mode always wins.
 * - security_research is NEVER inferred from source alone.
 * - source user / unset → user_chat
 * - untrusted sources → untrusted_content
 */
export function resolveScanMode(opts: {
  mode?: ScanMode | null;
  source?: SourceTrust | string | null;
}): ScanModeMeta {
  if (opts.mode != null && isScanMode(opts.mode)) {
    const meta: ScanModeMeta = { mode: opts.mode, modeSource: 'explicit' };
    if (opts.mode === 'security_research') meta.advisory = true;
    return meta;
  }

  const source = opts.source ?? undefined;
  if (source == null || source === '' || source === 'user') {
    return {
      mode: 'user_chat',
      modeSource: source === 'user' ? 'inferred_from_source' : 'default',
    };
  }

  if (UNTRUSTED_SOURCES.has(source)) {
    return { mode: 'untrusted_content', modeSource: 'inferred_from_source' };
  }

  // Unknown source strings: fail closed to untrusted_content (never security_research).
  return { mode: 'untrusted_content', modeSource: 'inferred_from_source' };
}

/**
 * Whether boundary scrub / untrusted ingress scrub should run for this mode+source.
 * - user_chat: always off (FP-safe chat path)
 * - untrusted_content: always on
 * - security_research: on only when source is present and ≠ user
 */
export function shouldScrubForMode(mode: ScanMode, source?: SourceTrust | string | null): boolean {
  if (mode === 'user_chat') return false;
  if (mode === 'untrusted_content') return true;
  // security_research
  return source != null && source !== '' && source !== 'user';
}

/** Build response meta blob (additive; avoids colliding with enforcement `mode`). */
export function scanModeResponseMeta(resolved: ScanModeMeta): {
  mode: ScanMode;
  modeSource: ModeSource;
  advisory?: true;
} {
  const out: { mode: ScanMode; modeSource: ModeSource; advisory?: true } = {
    mode: resolved.mode,
    modeSource: resolved.modeSource,
  };
  if (resolved.advisory) out.advisory = true;
  return out;
}
