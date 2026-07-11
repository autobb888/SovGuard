/** Secret-value detection: flags credentials appearing as CONTENT (leak/exfil). */
import type { OutputFlag } from '../types.js';

interface SecretRule { re: RegExp; label: string; severity: OutputFlag['severity']; }
const RULES: SecretRule[] = [
  { re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/, label: 'private_key', severity: 'critical' },
  { re: /\bAKIA[0-9A-Z]{16}\b/, label: 'aws_access_key_id', severity: 'critical' },
  { re: /\bASIA[0-9A-Z]{16}\b/, label: 'aws_temp_key_id', severity: 'critical' },
  { re: /\bsk-[A-Za-z0-9]{20,}\b/, label: 'openai_key', severity: 'high' },
  { re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/, label: 'github_token', severity: 'high' },
  { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, label: 'slack_token', severity: 'high' },
  { re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, label: 'jwt', severity: 'medium' },
  { re: /\bAIza[A-Za-z0-9_\-]{35}\b/, label: 'google_api_key', severity: 'high' },
];

export function scanSecrets(message: string): OutputFlag[] {
  const flags: OutputFlag[] = [];
  for (const rule of RULES) {
    const m = message.match(rule.re);
    if (m) flags.push({ type: 'secret_leak', severity: rule.severity,
      detail: `Possible ${rule.label} present in content`,
      evidence: m[0].slice(0, 12) + '…', action: rule.severity === 'critical' ? 'block' : 'redact' });
  }
  return flags;
}
