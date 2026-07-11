/**
 * Outbound image-exfiltration scanner.
 * Auto-loading remote images in an agent RESPONSE are a zero-click data
 * exfiltration channel (EchoLeak-class): the rendering client GETs the URL,
 * leaking whatever the attacker encoded into the path/query. Mirrors the inbound
 * markdown_image_exfil / html_img_exfil patterns (src/scanner/regex.ts) but runs
 * on OUTPUT, where they were previously never applied.
 */
import type { OutputFlag } from '../types.js';

const MARKDOWN_IMAGE_REMOTE = /!\[.*?\]\(\s*https?:\/\/[^)]*\)/i;
const HTML_IMG_REMOTE = /<img\s[^>]{0,500}\bsrc\s*=\s*["']?\s*https?:\/\/[^"'\s>)]+/i;

export function scanExfil(message: string): OutputFlag[] {
  const flags: OutputFlag[] = [];
  const md = message.match(MARKDOWN_IMAGE_REMOTE);
  if (md) flags.push({ type: 'agent_exfiltration', severity: 'medium',
    detail: 'Markdown image with remote URL in output — possible zero-click exfiltration',
    evidence: md[0].slice(0, 200), action: 'warn' });
  const img = message.match(HTML_IMG_REMOTE);
  if (img) flags.push({ type: 'agent_exfiltration', severity: 'medium',
    detail: 'HTML <img> with remote src in output — possible zero-click exfiltration',
    evidence: img[0].slice(0, 200), action: 'warn' });
  return flags;
}
