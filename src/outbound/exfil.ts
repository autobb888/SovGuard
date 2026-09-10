/**
 * Outbound image-exfiltration scanner.
 * DL-004: when allowedUrls is provided, remote image URLs not on the trusted-plan
 * allowlist are blocked (shared safe matcher with ActionGuard).
 */
import type { OutputFlag } from '../types.js';
import { urlOnTrustedAllowlist } from '../delivery/action-guard.js';

const MARKDOWN_IMAGE_REMOTE = /!\[.*?\]\(\s*(https?:\/\/[^)]*)\s*\)/i;
const HTML_IMG_REMOTE = /<img\s[^>]{0,500}\bsrc\s*=\s*["']?\s*(https?:\/\/[^"'\s>)]+)/i;

export function scanExfil(
  message: string,
  opts?: { allowedUrls?: string[] },
): OutputFlag[] {
  const flags: OutputFlag[] = [];
  const allowed = opts?.allowedUrls;

  const md = MARKDOWN_IMAGE_REMOTE.exec(message);
  if (md) {
    const url = md[1];
    const allowlisted = allowed ? urlOnTrustedAllowlist(url, allowed) : false;
    if (allowed && !allowlisted) {
      flags.push({
        type: 'agent_exfiltration',
        severity: 'high',
        detail: 'Markdown image URL not on trusted-plan allowlist — blocking EchoLeak-class echo',
        evidence: md[0].slice(0, 200),
        action: 'block',
      });
    } else {
      flags.push({
        type: 'agent_exfiltration',
        severity: 'medium',
        detail: 'Markdown image with remote URL in output — possible zero-click exfiltration',
        evidence: md[0].slice(0, 200),
        action: 'warn',
      });
    }
  }
  const img = HTML_IMG_REMOTE.exec(message);
  if (img) {
    const url = img[1];
    const allowlisted = allowed ? urlOnTrustedAllowlist(url, allowed) : false;
    if (allowed && !allowlisted) {
      flags.push({
        type: 'agent_exfiltration',
        severity: 'high',
        detail: 'HTML <img> URL not on trusted-plan allowlist — blocking EchoLeak-class echo',
        evidence: img[0].slice(0, 200),
        action: 'block',
      });
    } else {
      flags.push({
        type: 'agent_exfiltration',
        severity: 'medium',
        detail: 'HTML <img> with remote src in output — possible zero-click exfiltration',
        evidence: img[0].slice(0, 200),
        action: 'warn',
      });
    }
  }
  return flags;
}
