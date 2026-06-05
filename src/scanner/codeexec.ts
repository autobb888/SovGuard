/**
 * Malicious-code / execution detection (Phase 1).
 *
 * Separate from the prompt-injection PATTERNS table in scanner/regex.ts: these
 * patterns target an agent WRITING malware (reverse shells, curl|bash, install
 * hooks, persistence), not an agent being tricked. Kept out of the shared
 * injection table so the /v1/scan text path and the ML classifier are untouched.
 *
 * Decision model: each pattern has an intrinsic tier — 'weapon' (no benign use,
 * always block) or 'contextual' (warn by default, escalate to block when the
 * write lands somewhere the host executes). See decideCodeExec.
 */

import { decodeHexEscapes, decodeUnicodeEscapes, decodeUrlEncoding } from './regex.js';

export type CodeExecCategory =
  | 'reverse_shell'
  | 'download_and_execute'
  | 'package_lifecycle_exec'
  | 'persistence';

export type CodeExecTier = 'weapon' | 'contextual';

export interface CodeExecMatch {
  category: CodeExecCategory;
  tier: CodeExecTier;
  label: string;
  matched: string;
}

interface CodeExecPattern {
  pattern: RegExp;
  category: CodeExecCategory;
  tier: CodeExecTier;
  label: string;
}

const PATTERNS: CodeExecPattern[] = [
  // ── reverse_shell (weapon) ───────────────────────────────
  { pattern: /\/dev\/(?:tcp|udp)\/[\w.\-]+\/\d+/i, category: 'reverse_shell', tier: 'weapon', label: 'dev_tcp' },
  { pattern: /\bnc(?:at)?\s+(?:-\w+\s+)*-\w*e\w*\b/i, category: 'reverse_shell', tier: 'weapon', label: 'nc_exec' },
  { pattern: /\bmkfifo\b[\s\S]{0,80}?\|\s*(?:ba|z|k|tc|da)?sh\b/i, category: 'reverse_shell', tier: 'weapon', label: 'mkfifo_backpipe' },
  { pattern: /\bsocat\b[\s\S]{0,80}?\bexec:/i, category: 'reverse_shell', tier: 'weapon', label: 'socat_exec' },
  { pattern: /\bsocket\s*\.\s*socket\s*\([\s\S]{0,200}?(?:subprocess|os\.dup2|\/bin\/(?:sh|bash))/i, category: 'reverse_shell', tier: 'weapon', label: 'python_revshell' },
  { pattern: /\b(?:perl|ruby|php)\b[\s\S]{0,40}?-e\b[\s\S]{0,200}?(?:fsockopen|Socket|socket)[\s\S]{0,200}?(?:exec|system|\/bin\/(?:sh|bash))/i, category: 'reverse_shell', tier: 'weapon', label: 'script_revshell' },
  { pattern: /New-Object\s+(?:System\.)?Net\.Sockets\.TCPClient/i, category: 'reverse_shell', tier: 'weapon', label: 'powershell_tcpclient' },

  // ── download_and_execute ─────────────────────────────────
  { pattern: /\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget|fetch)\b/i, category: 'download_and_execute', tier: 'weapon', label: 'process_substitution' },
  { pattern: /(?:DownloadString|Invoke-WebRequest|\bIWR\b|Net\.WebClient)[\s\S]{0,120}?\|\s*(?:IEX|Invoke-Expression)\b/i, category: 'download_and_execute', tier: 'weapon', label: 'ps_iex_download' },
  { pattern: /(?:IEX|Invoke-Expression)\b[\s\S]{0,120}?(?:DownloadString|Invoke-WebRequest|\bIWR\b|Net\.WebClient)/i, category: 'download_and_execute', tier: 'weapon', label: 'ps_iex_download2' },
  { pattern: /\b(?:curl|wget|fetch)\b[^\n|]{0,200}?\|\s*(?:sudo\s+)?(?:ba|z|k|tc|da)?sh\b/i, category: 'download_and_execute', tier: 'contextual', label: 'pipe_to_shell' },

  // ── package_lifecycle_exec (contextual) ──────────────────
  { pattern: /"(?:preinstall|postinstall|prepare|install)"\s*:\s*"[^"]{0,400}?(?:\bcurl\b|\bwget\b|\bbash\b|\bsh\b|node\s+-e|\beval\b)/i, category: 'package_lifecycle_exec', tier: 'contextual', label: 'npm_install_hook' },
  { pattern: /(?:os\.system|subprocess\.[A-Za-z_]+)\s*\([^)]{0,200}?(?:curl|wget|https?:\/\/|\/bin\/(?:sh|bash))/i, category: 'package_lifecycle_exec', tier: 'contextual', label: 'py_install_exec' },
  { pattern: /Command::new\s*\(\s*"(?:sh|bash|curl|wget|cmd|powershell)"/i, category: 'package_lifecycle_exec', tier: 'contextual', label: 'buildrs_command' },
  { pattern: /\/\/go:generate\b[^\n]{0,120}?\b(?:curl|wget|bash|sh|eval)\b/i, category: 'package_lifecycle_exec', tier: 'contextual', label: 'go_generate_exec' },

  // ── persistence (contextual) ─────────────────────────────
  { pattern: />>\s*\S{0,80}?\.ssh\/authorized_keys/i, category: 'persistence', tier: 'contextual', label: 'authorized_keys_append' },
  { pattern: />>\s*\S{0,80}?[\/.](?:bashrc|zshrc|profile|bash_profile)\b/i, category: 'persistence', tier: 'contextual', label: 'shell_rc_append' },
];

function scanOnce(text: string): CodeExecMatch[] {
  const out: CodeExecMatch[] = [];
  for (const def of PATTERNS) {
    const m = def.pattern.exec(text);
    if (m) out.push({ category: def.category, tier: def.tier, label: def.label, matched: m[0].slice(0, 200) });
  }
  return out;
}

/** Decode long base64 runs to utf-8 (catches eval(atob('...')) wrappers). Capped. */
function base64Variants(text: string): string[] {
  const variants: string[] = [];
  const re = /[A-Za-z0-9+/]{16,}={0,2}/g;
  let m: RegExpExecArray | null;
  let count = 0;
  while ((m = re.exec(text)) !== null && count < 20) {
    count++;
    try {
      const decoded = Buffer.from(m[0], 'base64').toString('utf-8');
      if (decoded.length > 4 && /[ -~]{4,}/.test(decoded)) variants.push(decoded);
    } catch { /* not valid base64 */ }
  }
  return variants;
}

export function detectCodeExec(text: string): CodeExecMatch[] {
  const variants = new Set<string>([text]);
  for (const v of [decodeHexEscapes(text), decodeUnicodeEscapes(text), decodeUrlEncoding(text)]) {
    if (v !== text) variants.add(v);
  }
  for (const v of base64Variants(text)) variants.add(v);

  const seen = new Set<string>();
  const matches: CodeExecMatch[] = [];
  for (const variant of variants) {
    for (const m of scanOnce(variant)) {
      const key = `${m.category}:${m.label}`;
      if (seen.has(key)) continue;
      seen.add(key);
      matches.push(m);
    }
  }
  return matches;
}
