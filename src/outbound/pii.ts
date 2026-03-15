/**
 * Outbound PII Scanner
 * Detects SSN, credit cards, emails, phone numbers in agent responses.
 */

import type { OutputFlag } from '../types.js';
import { EMAIL_RE } from './patterns.js';

const SSN_RE = /\b(\d{3})-(\d{2})-(\d{4})\b/g;
const CC_RE = /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,4}\b/g;
const PHONE_RE = /\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b/g;

/** Categories where email/phone are expected and normal */
const CONTACT_NORMAL_CATEGORIES = new Set([
  'code-review', 'development', 'web-development', 'software',
  'writing', 'translation', 'virtual-assistant',
]);

function luhnCheck(num: string): boolean {
  const digits = num.replace(/\D/g, '');
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function ssnAreaValid(area: string): boolean {
  const n = parseInt(area, 10);
  return n > 0 && n < 900 && n !== 666;
}

export function scanPII(message: string, jobCategory?: string): OutputFlag[] {
  const flags: OutputFlag[] = [];
  const contactNormal = jobCategory ? CONTACT_NORMAL_CATEGORIES.has(jobCategory) : false;

  // SSN
  let m: RegExpExecArray | null;
  const ssnRe = new RegExp(SSN_RE.source, SSN_RE.flags);
  while ((m = ssnRe.exec(message)) !== null) {
    if (ssnAreaValid(m[1]) && m[2] !== '00' && m[3] !== '0000') {
      flags.push({
        type: 'pii_detected',
        severity: 'critical',
        detail: 'SSN pattern detected in output',
        evidence: m[0],
        action: 'block',
      });
    }
  }

  // Credit cards
  const ccRe = new RegExp(CC_RE.source, CC_RE.flags);
  while ((m = ccRe.exec(message)) !== null) {
    const digits = m[0].replace(/\D/g, '');
    if (digits.length >= 13 && digits.length <= 19 && luhnCheck(digits)) {
      flags.push({
        type: 'pii_detected',
        severity: 'critical',
        detail: 'Credit card number detected in output',
        evidence: m[0],
        action: 'block',
      });
    }
  }

  // Email (reject consecutive dots — invalid per RFC 5321)
  const emailRe = new RegExp(EMAIL_RE.source, EMAIL_RE.flags);
  while ((m = emailRe.exec(message)) !== null) {
    if (/\.\./.test(m[0])) continue; // skip "user@domain..com" etc.
    flags.push({
      type: 'pii_detected',
      severity: contactNormal ? 'low' : 'medium',
      detail: 'Email address in output',
      evidence: m[0],
      action: 'warn',
    });
  }

  // Phone
  const phoneRe = new RegExp(PHONE_RE.source, PHONE_RE.flags);
  while ((m = phoneRe.exec(message)) !== null) {
    if (m[0].replace(/\D/g, '').length >= 10) {
      flags.push({
        type: 'pii_detected',
        severity: contactNormal ? 'low' : 'medium',
        detail: 'Phone number in output',
        evidence: m[0],
        action: 'warn',
      });
    }
  }

  return flags;
}
