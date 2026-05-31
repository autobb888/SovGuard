/**
 * Egress / effect detection.
 *
 * The other outbound scanners look for sensitive *content* (PII, code, URLs).
 * This one looks for evidence that a prompt injection actually SUCCEEDED -- the
 * agent's own output betraying that it broke character or leaked its context.
 * Detecting the effect is often more reliable than catching the obfuscated
 * input, and it closes the loop with the canary system.
 */

import type { OutputFlag } from '../types.js';

export interface EgressContext {
  /** If set, the agent's response is checked for this canary phrase. */
  canaryToken?: string;
}

// Invisible/zero-width + variation-selector chars used to obfuscate a leaked
// canary. Built via RegExp() with escape sequences to keep the source ASCII-only.
const INVISIBLE_RE = new RegExp(
  '[\\u200B-\\u200F\\u2028-\\u202F\\u2060-\\u206F\\uFEFF\\u00AD\\uFE00-\\uFE0F]',
  'g',
);

/** Normalize for canary comparison: strip invisibles, collapse whitespace, lowercase. */
function normalizeForCanary(s: string): string {
  return s.replace(INVISIBLE_RE, '').replace(/\s+/g, ' ').trim().toLowerCase();
}

// First-person / imperative acknowledgements that the agent obeyed an injection.
// Phrased to require agent-voice constructions so third-person discussion of an
// attack ("an attacker might say 'ignore all previous instructions'") does NOT match.
const COMPLIANCE_PATTERNS: RegExp[] = [
  /\b(dan|developer|jailbreak|god|sudo|unrestricted)\s*mode\s*(enabled|activated|engaged|on\b)/i,
  /\bjailbreak\s*(successful|complete|achieved|mode)/i,
  /\bas\s+(dan|an?\s+(unrestricted|unfiltered|jailbroken)\b)/i,
  /\bi\s+(will|am\s+going\s+to|shall|can)\s+(now\s+)?(ignore|disregard|bypass|override)\s+(my|the|all|any)\b/i,
  /\bi\s+am\s+now\s+(an?\s+)?(unrestricted|unfiltered|jailbroken|free\s+from|no\s+longer\s+bound)/i,
  /\b(ignoring|disregarding|bypassing|overriding)\b[^.\n]{0,30}?\b(previous|prior|earlier|system|safety)\b[^.\n]{0,20}?\b(instructions?|rules?|guidelines?|prompts?|directives?|restrictions?)\b/i,
  /\b(my|your)\s+(restrictions?|guidelines?|filters?|safety\s+\w+)\s+(have\s+been\s+|are\s+)?(disabled|removed|lifted|turned\s+off|bypassed)/i,
];

// The output disclosing the agent's own system prompt / instructions.
const DISCLOSURE_PATTERNS: RegExp[] = [
  /\bhere\s+(is|are)\s+(my|the)\s+(system\s+)?(prompt|instructions?|rules?|guidelines?)\s*[:\-"]/i,
  /\b(my|the)\s+(system\s+)?(prompt|instructions?)\s+(is|are|was|were)\s*[:"]/i,
  /<\|?\s*(system|im_start)\s*\|?>/i,
];

export function scanEgress(message: string, context: EgressContext = {}): OutputFlag[] {
  const flags: OutputFlag[] = [];

  // 1. Canary leak -- strongest possible signal an injection extracted context.
  if (context.canaryToken) {
    const haystack = normalizeForCanary(message);
    const needle = normalizeForCanary(context.canaryToken);
    if (needle.length > 0 && haystack.includes(needle)) {
      flags.push({
        type: 'agent_exfiltration',
        severity: 'critical',
        detail: 'Canary token leaked in agent output -- injection likely succeeded',
        evidence: '[canary phrase redacted]',
        action: 'block',
      });
    }
  }

  // 2. Compliance / jailbreak acknowledgement.
  for (const re of COMPLIANCE_PATTERNS) {
    const m = re.exec(message);
    if (m) {
      flags.push({
        type: 'injection_success',
        severity: 'high',
        detail: 'Output acknowledges breaking character / obeying an injection',
        evidence: m[0].slice(0, 80),
        action: 'block',
      });
      break; // one compliance flag is enough
    }
  }

  // 3. System-prompt / instruction disclosure.
  for (const re of DISCLOSURE_PATTERNS) {
    const m = re.exec(message);
    if (m) {
      flags.push({
        type: 'injection_success',
        severity: 'high',
        detail: 'Output appears to disclose the system prompt / hidden instructions',
        evidence: m[0].slice(0, 80),
        action: 'block',
      });
      break;
    }
  }

  return flags;
}
