/**
 * DL-006 — Boundary / special-token scrub on untrusted ingress.
 * Neutralize forged tool_call / SYSTEM / chat-template / role markers so
 * parsers and models cannot treat untrusted data as privileged turns.
 */

export interface BoundaryScrubOptions {
  /** Extra literal or RegExp patterns to neutralize (merged with defaults). */
  extraPatterns?: Array<RegExp | string>;
}

export interface BoundaryScrubResult {
  text: string;
  /** Human-readable labels for matched boundary kinds. */
  hits: string[];
  changed: boolean;
}

/** Default reserved boundary tokens (MCP / XML / chat-template / role). */
export const DEFAULT_BOUNDARY_PATTERNS: ReadonlyArray<{ label: string; pattern: RegExp }> = [
  { label: 'tool_call', pattern: /<\/?tool_call\b[^>]*>/gi },
  { label: 'tool_calls', pattern: /<\/?tool_calls\b[^>]*>/gi },
  { label: 'function_call', pattern: /<\/?function_call\b[^>]*>/gi },
  { label: 'system_bracket', pattern: /\[\s*SYSTEM\s*\]/gi },
  { label: 'system_xml', pattern: /<\/?system\b[^>]*>/gi },
  { label: 'im_start', pattern: /<\|im_start\|>/gi },
  { label: 'im_end', pattern: /<\|im_end\|>/gi },
  { label: 'endoftext', pattern: /<\|endoftext\|>/gi },
  { label: 'eot_id', pattern: /<\|eot_id\|>/gi },
  { label: 'start_header', pattern: /<\|start_header_id\|>/gi },
  { label: 'end_header', pattern: /<\|end_header_id\|>/gi },
  { label: 'assistant_role', pattern: /<\/?assistant\b[^>]*>/gi },
  { label: 'user_role_xml', pattern: /<\/?user\b[^>]*>/gi },
];

/** Break delimiter characters so exact parser matches fail; keep readable. */
export function neutralizeBoundaryToken(token: string): string {
  return token
    .replace(/</g, '‹')
    .replace(/>/g, '›')
    .replace(/\[/g, '〔')
    .replace(/\]/g, '〕')
    .replace(/\|/g, '¦');
}

/**
 * Detect and neutralize reserved boundary tokens in text.
 * Safe to run repeatedly; already-neutralized forms are not re-matched.
 */
export function scrubBoundaries(
  text: string,
  opts?: BoundaryScrubOptions,
): BoundaryScrubResult {
  let out = text;
  const hits: string[] = [];

  const patterns = [...DEFAULT_BOUNDARY_PATTERNS];
  for (const extra of opts?.extraPatterns ?? []) {
    if (typeof extra === 'string') {
      patterns.push({
        label: 'extra',
        pattern: new RegExp(extra.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'),
      });
    } else {
      patterns.push({ label: 'extra', pattern: extra });
    }
  }

  for (const { label, pattern } of patterns) {
    // Reset lastIndex for global patterns
    pattern.lastIndex = 0;
    if (!pattern.test(out)) continue;
    pattern.lastIndex = 0;
    hits.push(label);
    out = out.replace(pattern, (m) => neutralizeBoundaryToken(m));
  }

  return {
    text: out,
    hits: [...new Set(hits)],
    changed: out !== text,
  };
}
