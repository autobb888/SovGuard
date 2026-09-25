/**
 * TraceIntegrity thin land C — Skill→tamper refuse.
 *
 * Skill (or injected instruction) demanding session wipe / fabricate
 * lifecycle after a benign primary task → REFUSE skill step;
 * `primaryTaskMayComplete: true`.
 *
 * Soft residuals stay soft. Escalate BLOCK. Not deepset 80%. Shapes only.
 * Do not reopen ControlToken / Chronos / A2A / A2M.
 */

export type SkillTamperVerdict = 'ALLOW' | 'REFUSE';

export type SkillTamperGateId =
  | 'SkillTamperGate.ALLOW'
  | 'SkillTamperGate.REFUSE_tamper_demand'
  | 'SkillTamperGate.DENY_bad_input';

export type SkillTamperDemandShape =
  | 'wipe_or_fabricate_session_after_task'
  | 'wipe_session'
  | 'fabricate_lifecycle'
  | 'erase_audit'
  | string;

export interface SkillTamperDemand {
  shape: SkillTamperDemandShape;
  lifecycleFabricate?: boolean;
  wipeSession?: boolean;
  /** Free-text demand (shape detection). */
  text?: string;
}

export interface SkillTamperAttempt {
  primaryTask: string;
  skillDemand?: SkillTamperDemand | null;
  /** Injected instruction equivalent to skill demand. */
  injectedInstruction?: string;
}

export interface SkillTamperGateResult {
  verdict: SkillTamperVerdict;
  gate: SkillTamperGateId;
  /** Always true when skill refused — benign primary may still finish. */
  primaryTaskMayComplete: boolean;
  escalate: boolean;
  reason?: string;
  matchedDemand?: string;
}

const TAMPER_SHAPES = new Set([
  'wipe_or_fabricate_session_after_task',
  'wipe_session',
  'fabricate_lifecycle',
  'erase_audit',
]);

const TAMPER_TEXT_RE =
  /\b(wipe|erase|delete|fabricate|falsify|scrub)\b.{0,80}\b(session|transcript|lifecycle|audit|jsonl|trace)\b|\b(session|transcript|lifecycle|audit)\b.{0,80}\b(wipe|erase|delete|fabricate|falsify|scrub)\b/i;

function demandIsTamper(d?: SkillTamperDemand | null, injected?: string): string | undefined {
  if (d) {
    const shape = String(d.shape ?? '');
    if (TAMPER_SHAPES.has(shape)) return shape;
    if (d.lifecycleFabricate || d.wipeSession) {
      return d.lifecycleFabricate ? 'fabricate_lifecycle' : 'wipe_session';
    }
    if (d.text && TAMPER_TEXT_RE.test(d.text)) return 'text_tamper_demand';
  }
  if (injected && TAMPER_TEXT_RE.test(injected)) return 'injected_tamper_instruction';
  return undefined;
}

/**
 * Gate a skill/injected step that may demand session wipe or lifecycle fabricate.
 * REFUSE the skill step; primary benign task may complete.
 */
export function gateSkillTamper(attempt: SkillTamperAttempt): SkillTamperGateResult {
  const primary = String(attempt?.primaryTask ?? '').trim();
  if (!primary) {
    return {
      verdict: 'REFUSE',
      gate: 'SkillTamperGate.DENY_bad_input',
      primaryTaskMayComplete: false,
      escalate: true,
      reason: 'primaryTask required',
    };
  }

  const matched = demandIsTamper(attempt.skillDemand, attempt.injectedInstruction);
  if (matched) {
    return {
      verdict: 'REFUSE',
      gate: 'SkillTamperGate.REFUSE_tamper_demand',
      primaryTaskMayComplete: true,
      escalate: true,
      matchedDemand: matched,
      reason: 'skill/injected step demands session wipe or lifecycle fabricate — refuse skill; primary may complete',
    };
  }

  return {
    verdict: 'ALLOW',
    gate: 'SkillTamperGate.ALLOW',
    primaryTaskMayComplete: true,
    escalate: false,
  };
}
