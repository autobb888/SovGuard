/**
 * Optional host-callable redact helper for J41 opt-in data protection.
 *
 * Rewrites spans for flags with `action: 'redact'` using placeholders such as
 * `[REDACTED_CC]` / `[REDACTED_KEY]`. Hosts may call after `scanOutput`; this
 * is **not** auto-applied inside `scanOutput` (behavior unchanged).
 *
 * Detectors (`scanPII` / `scanSecrets` / `scanFinancial`) are untouched.
 * Secret flags today store `evidence: '(redacted)'` — for those, this helper
 * re-applies the same secret *shapes* (not live credentials) to locate spans.
 *
 * Not a DLP product. Not deepset 80%. Escalate BLOCK.
 */

import type { OutputFlag } from '../types.js';

/** Placeholders used when rewriting redact-action spans. */
export const REDACT_PLACEHOLDERS = {
  cc: '[REDACTED_CC]',
  key: '[REDACTED_KEY]',
  ssn: '[REDACTED_SSN]',
  email: '[REDACTED_EMAIL]',
  phone: '[REDACTED_PHONE]',
  financial: '[REDACTED_WALLET]',
  generic: '[REDACTED]',
} as const;

/**
 * Secret shapes mirrored from `secrets.ts` RULES — locate spans when flag
 * evidence was scrubbed to `(redacted)`. Keep in sync with detector patterns;
 * do not change detector behavior.
 */
const SECRET_SHAPE_RES: RegExp[] = [
  /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
  /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bASIA[0-9A-Z]{16}\b/g,
  /\bsk-[A-Za-z0-9]{20,}\b/g,
  /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  /\bAIza[A-Za-z0-9_\-]{35}\b/g,
];

function placeholderFor(flag: OutputFlag): string {
  const detail = (flag.detail ?? '').toLowerCase();
  if (flag.type === 'secret_leak') return REDACT_PLACEHOLDERS.key;
  if (flag.type === 'financial_manipulation') return REDACT_PLACEHOLDERS.financial;
  if (flag.type === 'pii_detected') {
    if (detail.includes('credit card') || detail.includes('card number')) {
      return REDACT_PLACEHOLDERS.cc;
    }
    if (detail.includes('ssn')) return REDACT_PLACEHOLDERS.ssn;
    if (detail.includes('email')) return REDACT_PLACEHOLDERS.email;
    if (detail.includes('phone')) return REDACT_PLACEHOLDERS.phone;
  }
  return REDACT_PLACEHOLDERS.generic;
}

function replaceAllLiteral(haystack: string, needle: string, replacement: string): string {
  if (!needle) return haystack;
  return haystack.split(needle).join(replacement);
}

/**
 * Rewrite `text` for flags whose `action` is `'redact'`.
 * Leaves `warn` / `block` / `flag` / `pass` spans untouched (host decides).
 * Does not mutate `flags`. Does not call or alter `scanOutput`.
 */
export function redactOutput(flags: readonly OutputFlag[], text: string): string {
  const redactFlags = flags.filter((f) => f.action === 'redact');
  if (redactFlags.length === 0) return text;

  let out = text;

  // Concrete evidence spans (PII etc. — detectors store the match text).
  // Longest-first so nested/overlapping literals replace safely.
  const concrete = redactFlags
    .filter((f) => f.evidence && f.evidence !== '(redacted)')
    .slice()
    .sort((a, b) => b.evidence.length - a.evidence.length);

  for (const f of concrete) {
    out = replaceAllLiteral(out, f.evidence, placeholderFor(f));
  }

  // Secret leaks scrub evidence in the flag payload; re-apply shapes to text.
  const needsSecretShapes = redactFlags.some(
    (f) => f.type === 'secret_leak' && (!f.evidence || f.evidence === '(redacted)'),
  );
  if (needsSecretShapes) {
    for (const re of SECRET_SHAPE_RES) {
      const local = new RegExp(re.source, re.flags);
      out = out.replace(local, REDACT_PLACEHOLDERS.key);
    }
  }

  return out;
}
