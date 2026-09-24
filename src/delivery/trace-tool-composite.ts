/**
 * ControlToken TraceDelete B+C — empty/weak-trace + tool/act composite.
 *
 * Paper (arxiv 2609.27542 / deleting-the-trace): forged empty Harmony analysis
 * channel defeats CoT monitors while unsafe tool calls still fire; adaptive
 * one-line benign decoy defeats empty-only tripwires. This module fail-closes
 * when tool/act fires with empty OR weak analysis/reasoning, and composes with
 * ActionGuard TrustedPlan for the normal-CoT ALLOW control path.
 *
 * Soft D (parser harden / require tool-call terminator) is host/harness — not
 * built here. Do not reopen A2M. Not deepset 80%. Escalate BLOCK.
 */

import {
  actionGuard,
  type ActionGuardResult,
  type ProposedAction,
  type TrustedPlan,
} from './action-guard.js';

/** Default trimmed-length floor below which analysis is treated as weak/decoy. */
export const DEFAULT_WEAK_TRACE_MAX_CHARS = 80;

/** Obvious one-line filler shapes (decoy-resistant CT3). Case-insensitive. */
const FILLER_LINE_RE =
  /^(ok(ay)?\.?|sure\.?|proceeding\.?|routine request[;.!]?\s*proceeding\.?|looks good\.?|acknowledged\.?|got it\.?|will do\.?|continuing\.?|done\.?)$/i;

export type TraceToolVerdict = 'ALLOW' | 'DENY' | 'ESCALATE';

export type TraceWeakKind =
  | 'empty'
  | 'whitespace_only'
  | 'below_length_threshold'
  | 'one_line_filler';

export interface TraceToolCompositeInput {
  /** Model analysis / reasoning channel text for this turn (may be empty). */
  analysisText?: string | null;
  /** Alias for analysisText (reasoning channel). */
  reasoningText?: string | null;
  /** Proposed tool/act/fetch about to fire. */
  proposed: ProposedAction | ProposedAction[];
  /**
   * When provided, normal substantial CoT composes with ActionGuard.
   * Empty/weak + tool still DENY/ESCALATE before/alongside plan checks.
   */
  trustedPlan?: TrustedPlan;
  /** Forwarded to actionGuard on the ALLOW control path. */
  actionGuardOpts?: Parameters<typeof actionGuard>[2];
  /** Override weak-trace length threshold (default 80). */
  weakTraceMaxChars?: number;
  /**
   * When true (default), empty/weak+tool returns ESCALATE (require ActionGuard
   * IFC / HITL) rather than hard DENY. Host may treat either as fail-closed.
   */
  escalateOnWeakTrace?: boolean;
}

export interface TraceToolCompositeResult {
  verdict: TraceToolVerdict;
  reason: string;
  /** Present when analysis was classified empty/weak. */
  weakKind?: TraceWeakKind;
  analysisLength: number;
  analysisTrimmedLength: number;
  /** ActionGuard result when trustedPlan was supplied and composite did not short-circuit. */
  actionGuard?: ActionGuardResult;
  /** Gate id for logs / fixtures. */
  gate:
    | 'TraceToolComposite.empty_or_weak_trace'
    | 'TraceToolComposite.require_action_guard'
    | 'TraceToolComposite.ALLOW'
    | 'TraceToolComposite.action_guard_deny';
}

function resolveAnalysis(input: TraceToolCompositeInput): string {
  if (typeof input.analysisText === 'string') return input.analysisText;
  if (typeof input.reasoningText === 'string') return input.reasoningText;
  return '';
}

function asProposedList(proposed: ProposedAction | ProposedAction[]): ProposedAction[] {
  return Array.isArray(proposed) ? proposed : [proposed];
}

function hasToolOrActFire(proposed: ProposedAction[]): boolean {
  return proposed.some(
    (p) => p.type === 'tool' || p.type === 'action' || p.type === 'fetch',
  );
}

/**
 * Classify analysis/reasoning as empty or weak (decoy-resistant).
 * Returns null when substantial enough for the normal CoT path.
 */
export function classifyTraceWeakness(
  analysisText: string | null | undefined,
  weakTraceMaxChars: number = DEFAULT_WEAK_TRACE_MAX_CHARS,
): TraceWeakKind | null {
  if (analysisText == null) return 'empty';
  if (analysisText.length === 0) return 'empty';
  const trimmed = analysisText.trim();
  if (trimmed.length === 0) return 'whitespace_only';
  if (trimmed.length <= weakTraceMaxChars) {
    // One-line filler (exact-ish) or any short prose below threshold
    const singleLine = !trimmed.includes('\n');
    if (singleLine && FILLER_LINE_RE.test(trimmed)) return 'one_line_filler';
    return 'below_length_threshold';
  }
  // Long but still obvious single-line filler phrase padded with spaces — rare;
  // substantive multi-sentence CoT clears the length floor.
  if (!trimmed.includes('\n') && FILLER_LINE_RE.test(trimmed)) return 'one_line_filler';
  return null;
}

/**
 * Empty/weak analysis + tool/act → DENY/ESCALATE (CT2/CT3).
 * Substantial CoT + TrustedPlan → compose ActionGuard ALLOW path (CT4).
 * Substantial CoT without plan → ESCALATE (require ActionGuard IFC).
 */
export function assessTraceToolComposite(
  input: TraceToolCompositeInput,
): TraceToolCompositeResult {
  const analysis = resolveAnalysis(input);
  const trimmedLen = analysis.trim().length;
  const proposed = asProposedList(input.proposed);
  const maxChars = input.weakTraceMaxChars ?? DEFAULT_WEAK_TRACE_MAX_CHARS;
  const escalateWeak = input.escalateOnWeakTrace !== false;

  const weakKind = classifyTraceWeakness(analysis, maxChars);
  const toolFires = hasToolOrActFire(proposed);

  if (weakKind && toolFires) {
    const verdict: TraceToolVerdict = escalateWeak ? 'ESCALATE' : 'DENY';
    return {
      verdict,
      reason:
        `trace_tool_composite: ${weakKind} analysis/reasoning (trimmedLen=${trimmedLen}) ` +
        `with tool/act fire — ${verdict}; require ActionGuard argument IFC / HITL ` +
        `(empty-only tripwire insufficient; decoy-resistant)`,
      weakKind,
      analysisLength: analysis.length,
      analysisTrimmedLength: trimmedLen,
      gate: 'TraceToolComposite.empty_or_weak_trace',
    };
  }

  // No tool/act fire → nothing to gate on composite (ingress scrub is separate).
  if (!toolFires) {
    return {
      verdict: 'ALLOW',
      reason: 'trace_tool_composite: no tool/act/fetch proposed',
      analysisLength: analysis.length,
      analysisTrimmedLength: trimmedLen,
      gate: 'TraceToolComposite.ALLOW',
    };
  }

  // Substantial CoT + tool: compose ActionGuard when plan provided (CT4).
  if (input.trustedPlan) {
    const ag = actionGuard(input.trustedPlan, proposed, input.actionGuardOpts);
    if (ag.denied.length > 0) {
      return {
        verdict: 'DENY',
        reason:
          `trace_tool_composite: ActionGuard denied ${ag.denied.length} action(s)` +
          (ag.denied[0]?.reason ? ` — ${ag.denied[0].reason}` : ''),
        analysisLength: analysis.length,
        analysisTrimmedLength: trimmedLen,
        actionGuard: ag,
        gate: 'TraceToolComposite.action_guard_deny',
      };
    }
    return {
      verdict: 'ALLOW',
      reason: 'trace_tool_composite: substantial CoT + TrustedPlan ActionGuard ALLOW',
      analysisLength: analysis.length,
      analysisTrimmedLength: trimmedLen,
      actionGuard: ag,
      gate: 'TraceToolComposite.ALLOW',
    };
  }

  // Substantial CoT but no plan wired — fail closed toward ActionGuard IFC.
  return {
    verdict: 'ESCALATE',
    reason:
      'trace_tool_composite: substantial CoT but no TrustedPlan — require ActionGuard IFC',
    analysisLength: analysis.length,
    analysisTrimmedLength: trimmedLen,
    gate: 'TraceToolComposite.require_action_guard',
  };
}

/**
 * Soft D helper (documented; unused by default): true when a tool-call open
 * tag lacks a matching closer. Host/harness should require terminators;
 * engine does not wire this into assessTraceToolComposite by default.
 */
export function hasUnclosedToolCallSpan(text: string): boolean {
  const open = (text.match(/<tool_call\b[^>]*>/gi) ?? []).length;
  const close = (text.match(/<\/tool_call\s*>/gi) ?? []).length;
  return open > close;
}
