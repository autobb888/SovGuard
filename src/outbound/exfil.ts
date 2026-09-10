/**
 * Outbound image-exfiltration scanner.
 * Auto-loading remote images in an agent RESPONSE are a zero-click data
 * exfiltration channel (EchoLeak-class): the rendering client GETs the URL,
 * leaking whatever the attacker encoded into the path/query. Mirrors the inbound
 * markdown_image_exfil / html_img_exfil patterns (src/scanner/regex.ts) but runs
 * on OUTPUT, where they were previously never applied.
 *
 * DL-004: when allowedUrls is provided, remote image URLs not on the trusted-plan
 * allowlist are blocked (not just warned).
 */
import type { OutputFlag } from '../types.js';

const MARKDOWN_IMAGE_REMOTE = /!\[.*?\]\(\s*(https?:\/\/[^)]*)\s*\)/i;
const HTML_IMG_REMOTE = /<img\s[^>]{0,500}\bsrc\s*=\s*["']?\s*(https?:\/\/[^"'\s>)]+)/i;

function onAllowlist(url: string, allowedUrls: string[]): boolean {
  for (const entry of allowedUrls) {
    const e = entry.trim();
    if (!e) continue;
    if (url === e || url.startsWith(e)) return true;
    try {
      const u = new URL(url);
      const a = new URL(e.includes('://') ? e : `https://${e}`);
      if (u.origin === a.origin && (url.startsWith(e) || url.startsWith(a.href))) return true;
    } catch { /* ignore */ }
  }
  return false;
}

export function scanExfil(
  message: string,
  opts?: { allowedUrls?: string[] },
): OutputFlag[] {
  const flags: OutputFlag[] = [];
  const allowed = opts?.allowedUrls;

  const md = MARKDOWN_IMAGE_REMOTE.exec(message);
  if (md) {
    const url = md[1];
    const allowlisted = allowed ? onAllowlist(url, allowed) : false;
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
    const allowlisted = allowed ? onAllowlist(url, allowed) : false;
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
