/**
 * DL-006 — Boundary / special-token scrub on untrusted ingress.
 * Neutralize forged tool_call / SYSTEM / chat-template / role delimiters so
 * parsers and models do not treat untrusted data as privileged turns.
 */

export interface BoundaryScrubOptions {
  /** Extra RegExp sources (without flags) merged into the default set. */
  extraPatterns?: RegExp[];
}

export interface BoundaryScrubResult {
  text: string;
  hits: string[];
  scrubbed: boolean;
}

/**
 * Default reserved boundary tokens (MCP/XML/role/chat-template).
 * Case-insensitive where useful; keep patterns specific to limit FP.
 */
export const DEFAULT_BOUNDARY_PATTERNS: RegExp[] = [
  /<\/?tool_call\b[^>]*>/gi,
  /<\/?tool_calls\b[^>]*>/gi,
  /<\/?function_call\b[^>]*>/gi,
  /<\/?invoke\b[^>]*>/gi,
  /\[SYSTEM\]/gi,
  /\[\/?SYSTEM\]/gi,
  /\[INST\]/gi,
  /\[\/INST\]/gi,
  /<<SYS>>/gi,
  /<\/?SYS>>/gi,
  /<\|im_start\|>/gi,
  /<\|im_end\|>/gi,
  /<\|endoftext\|>/gi,
  /<\|system\|>/gi,
  /<\|user\|>/gi,
  /<\|assistant\|>/gi,
  /<\/?\|?(?:system|user|assistant)\|?>/gi,
  /<\/?system\b[^>]*>/gi,
  /<\/?assistant\b[^>]*>/gi,
];

/** Break delimiter glyphs so exact parser matches fail; keep text readable. */
export function neutralizeBoundaryToken(token: string): string {
  return token
    .replace(/</g, '‹')
    .replace(/>/g, '›')
    .replace(/\[/g, '〔')
    .replace(/\]/g, '〕')
    .replace(/\|/g, '¦');
}

/**
 * Detect + neutralize reserved boundary tokens in text.
 * Idempotent for already-neutralized glyphs (‹ › 〔〕 ¦).
 */
export function scrubBoundaries(
  text: string,
  opts?: BoundaryScrubOptions,
): BoundaryScrubResult {
  const patterns = opts?.extraPatterns?.length
    ? [...DEFAULT_BOUNDARY_PATTERNS, ...opts.extraPatterns]
    : DEFAULT_BOUNDARY_PATTERNS;

  const hits: string[] = [];
  let out = text;
  for (const re of patterns) {
    // Fresh lastIndex for global regexes
    const flags = re.flags.includes('g') ? re.flags : `${re.flags}g`;
    const compiled = new RegExp(re.source, flags);
    out = out.replace(compiled, (match) => {
      hits.push(match);
      return neutralizeBoundaryToken(match);
    });
  }

  return {
    text: out,
    hits,
    scrubbed: hits.length > 0,
  };
}

/** True when text still contains a raw (un-neutralized) default boundary token. */
export function hasRawBoundaryToken(text: string): boolean {
  for (const re of DEFAULT_BOUNDARY_PATTERNS) {
    const flags = re.flags.includes('g') ? re.flags : `${re.flags}g`;
    if (new RegExp(re.source, flags).test(text)) return true;
  }
  return false;
}
