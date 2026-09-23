/**
 * A2M Attraction→Manipulation thin land — Return IFC (B).
 *
 * B1: Strip or DENY instruction-shaped fields on third-party tool returns
 *     (`required_action`, `blocking_condition`, call-again / re-call privilege).
 *     No new privileges from return.
 * B2: Data-only structured returns → ALLOW.
 * B3: Label third-party returns untrusted / data-only (`source=mcp_result` style);
 *     host/engine path observes label; no trust promotion.
 *
 * KPI = FIDES-style return IFC (cuts ASR). Not deepset 80%. Not MTIR-as-ASR.
 * Soft residual: host must set source=mcp_result on returns for GhostSplice G5.
 * Does not replace GhostSplice arg-content / Deadbugz / MCP Discovery.
 */

/** Trust label stamped on every gated return. */
export type ReturnTrustLabel = 'untrusted' | 'data_only';

export type ReturnIfcVerdict = 'ALLOW' | 'DENY' | 'STRIP';

/** Instruction-shaped / privilege-escalation keys stripped or denied. */
export const RETURN_INSTRUCTION_FIELDS = [
  'required_action',
  'requiredAction',
  'blocking_condition',
  'blockingCondition',
  'call_again',
  'callAgain',
  'call-again',
  're_call',
  'reCall',
  'recall',
  'privilege_hint',
  'privilegeHint',
  'privilege',
  'elevated_privileges',
  'elevatedPrivileges',
  'bypass_hitl',
  'bypassHitl',
  'new_tools',
  'newTools',
  'grant_tools',
  'grantTools',
  'must_invoke',
  'mustInvoke',
  'force_tool',
  'forceTool',
  'system_override',
  'systemOverride',
] as const;

const INSTRUCTION_FIELD_SET = new Set<string>(
  RETURN_INSTRUCTION_FIELDS.map((s) => s.toLowerCase().replace(/_/g, '')),
);

function normKey(k: string): string {
  return k.toLowerCase().replace(/[-_]/g, '');
}

export function isInstructionShapedField(key: string): boolean {
  return INSTRUCTION_FIELD_SET.has(normKey(key));
}

/** Values that look like call-again / privilege directives even under benign keys. */
const CALL_AGAIN_VALUE_RE =
  /\b(call[_\s-]?again|re-?invoke|re-?call|must\s+re-?invoke|bypass[_\s-]?hitl|elevated\s+privileges?)\b/i;

export interface ReturnIfcOptions {
  /**
   * Source channel. Third-party MCP returns should be `mcp_result`
   * (GhostSplice G5 compose). Defaults to `mcp_result`.
   */
  source?: string;
  /** Tool name (audit). */
  tool?: string;
  /** Registry id (audit). */
  registry?: string;
  /**
   * When true (default), strip instruction fields and ALLOW remainder if any
   * data remains. When false, DENY entire return if any instruction field present.
   */
  strip?: boolean;
  /** Max depth when walking nested objects (default 6). */
  maxDepth?: number;
}

export interface ReturnIfcResult {
  verdict: ReturnIfcVerdict;
  /** Always untrusted or data_only for third-party returns — never trusted/system. */
  trust: ReturnTrustLabel;
  /** Provenance source for host/GhostSplice (default mcp_result). */
  source: string;
  /** Body after strip (or original when ALLOW data-only / DENY). */
  body: unknown;
  /** Keys removed (B1). */
  strippedFields: string[];
  /** True when instruction-shaped content was observed. */
  instructionShaped: boolean;
  reason?: string;
  tool?: string;
  registry?: string;
  gate?:
    | 'ReturnIFC.strip_instruction_fields'
    | 'ReturnIFC.DENY_instruction_fields'
    | 'ReturnIFC.ALLOW_data_only'
    | 'ReturnIFC.untrusted_label';
}

function walkStrip(
  value: unknown,
  stripped: string[],
  depth: number,
  maxDepth: number,
  path: string,
): { value: unknown; hadInstruction: boolean } {
  if (depth > maxDepth) return { value, hadInstruction: false };
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'string' && CALL_AGAIN_VALUE_RE.test(value) && path) {
      // String leaf under non-instruction key that itself is a directive — flag.
      return { value, hadInstruction: true };
    }
    return { value, hadInstruction: false };
  }
  if (Array.isArray(value)) {
    let had = false;
    const out = value.map((el, i) => {
      const r = walkStrip(el, stripped, depth + 1, maxDepth, `${path}[${i}]`);
      had = had || r.hadInstruction;
      return r.value;
    });
    return { value: out, hadInstruction: had };
  }
  const obj = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  let had = false;
  for (const [k, v] of Object.entries(obj)) {
    if (isInstructionShapedField(k)) {
      stripped.push(path ? `${path}.${k}` : k);
      had = true;
      continue; // strip
    }
    const r = walkStrip(v, stripped, depth + 1, maxDepth, path ? `${path}.${k}` : k);
    had = had || r.hadInstruction;
    out[k] = r.value;
  }
  return { value: out, hadInstruction: had };
}

function hasInstructionShaped(value: unknown, depth = 0, maxDepth = 6): boolean {
  if (depth > maxDepth || value === null || typeof value !== 'object') {
    return typeof value === 'string' && CALL_AGAIN_VALUE_RE.test(value);
  }
  if (Array.isArray(value)) {
    return value.some((el) => hasInstructionShaped(el, depth + 1, maxDepth));
  }
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (isInstructionShapedField(k)) return true;
    if (hasInstructionShaped(v, depth + 1, maxDepth)) return true;
  }
  return false;
}

/**
 * Apply return IFC to a third-party tool return (B1–B3).
 * Always labels untrusted/data-only with source=mcp_result by default.
 */
export function applyReturnIfc(
  returnBody: unknown,
  opts?: ReturnIfcOptions,
): ReturnIfcResult {
  const source = opts?.source ?? 'mcp_result';
  const strip = opts?.strip !== false;
  const maxDepth = opts?.maxDepth ?? 6;

  // Never promote trust — third-party returns stay untrusted/data-only.
  if (returnBody === null || returnBody === undefined) {
    return {
      verdict: 'ALLOW',
      trust: 'data_only',
      source,
      body: returnBody,
      strippedFields: [],
      instructionShaped: false,
      tool: opts?.tool,
      registry: opts?.registry,
      gate: 'ReturnIFC.ALLOW_data_only',
      reason: 'Empty/null return — data-only ALLOW',
    };
  }

  const instructionShaped = hasInstructionShaped(returnBody, 0, maxDepth);

  if (!instructionShaped) {
    return {
      verdict: 'ALLOW',
      trust: 'data_only',
      source,
      body: returnBody,
      strippedFields: [],
      instructionShaped: false,
      tool: opts?.tool,
      registry: opts?.registry,
      gate: 'ReturnIFC.ALLOW_data_only',
      reason: 'Data-only structured return — ALLOW (untrusted/data-only label)',
    };
  }

  if (!strip) {
    return {
      verdict: 'DENY',
      trust: 'untrusted',
      source,
      body: returnBody,
      strippedFields: [],
      instructionShaped: true,
      tool: opts?.tool,
      registry: opts?.registry,
      gate: 'ReturnIFC.DENY_instruction_fields',
      reason:
        'Instruction-shaped return fields (required_action / call-again / blocking_condition / privilege) — DENY; no new privileges from return',
    };
  }

  const strippedFields: string[] = [];
  const walked = walkStrip(returnBody, strippedFields, 0, maxDepth, '');
  // After strip: if only instruction fields existed, body may be empty object —
  // still STRIP (not trust promote). Remaining data → ALLOW with untrusted label.
  const remaining = walked.value;
  const stillInstruction = hasInstructionShaped(remaining, 0, maxDepth);

  if (stillInstruction || strippedFields.length === 0) {
    // Directive buried in string values we did not strip keys for — DENY escalate.
    return {
      verdict: 'DENY',
      trust: 'untrusted',
      source,
      body: remaining,
      strippedFields,
      instructionShaped: true,
      tool: opts?.tool,
      registry: opts?.registry,
      gate: 'ReturnIFC.DENY_instruction_fields',
      reason:
        'Instruction-shaped content remains after strip — DENY escalate; no new privileges from return',
    };
  }

  return {
    verdict: 'STRIP',
    trust: 'untrusted',
    source,
    body: remaining,
    strippedFields,
    instructionShaped: true,
    tool: opts?.tool,
    registry: opts?.registry,
    gate: 'ReturnIFC.strip_instruction_fields',
    reason: `Stripped instruction-shaped fields: ${strippedFields.join(', ')} — no new privileges from return`,
  };
}

/**
 * Label a third-party return untrusted/data-only without strip (B3 helper).
 * Always sets source=mcp_result unless overridden — never trusted/system.
 */
export function labelToolReturn(
  returnBody: unknown,
  opts?: ReturnIfcOptions,
): ReturnIfcResult {
  const source = opts?.source ?? 'mcp_result';
  if (source === 'trusted' || source === 'system' || source === 'user') {
    // Refuse trust promotion — force mcp_result / untrusted.
    return {
      verdict: 'ALLOW',
      trust: 'untrusted',
      source: 'mcp_result',
      body: returnBody,
      strippedFields: [],
      instructionShaped: false,
      tool: opts?.tool,
      registry: opts?.registry,
      gate: 'ReturnIFC.untrusted_label',
      reason:
        'Refused trust promotion — third-party tool return forced source=mcp_result / untrusted',
    };
  }
  const shaped = hasInstructionShaped(returnBody);
  return {
    verdict: 'ALLOW',
    trust: shaped ? 'untrusted' : 'data_only',
    source,
    body: returnBody,
    strippedFields: [],
    instructionShaped: shaped,
    tool: opts?.tool,
    registry: opts?.registry,
    gate: 'ReturnIFC.untrusted_label',
    reason: 'Third-party tool return labeled untrusted/data-only (no trust promotion)',
  };
}

/** True when result must not be treated as trusted directive by host. */
export function isReturnTrustedDirective(result: ReturnIfcResult): boolean {
  return false; // never — IFC forbids trust promotion
}
