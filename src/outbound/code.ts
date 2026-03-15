/**
 * Outbound Code Scanner
 * Detects malicious code patterns in agent deliverables.
 */

import type { OutputFlag } from '../types.js';

const CODE_BLOCK_RE = /(?:```|~~~)[\s\S]*?(?:```|~~~)|<(?:pre|code|script)[\s\S]*?<\/(?:pre|code|script)>/gi;

const CODE_CATEGORIES = new Set([
  'code-review', 'development', 'web-development', 'software',
  'programming', 'devops', 'data-science',
]);

interface MaliciousPattern {
  re: RegExp;
  detail: string;
  severity: 'medium' | 'high' | 'critical';
}

const MALICIOUS_PATTERNS: MaliciousPattern[] = [
  { re: /\beval\s*\(\s*[^)\s]/i, detail: 'eval() call detected', severity: 'high' },
  { re: /\bexec\s*\(/i, detail: 'exec() call detected', severity: 'high' },
  { re: /\bsubprocess\s*\.\s*(call|run|Popen|check_output)\s*\(/i, detail: 'subprocess execution detected', severity: 'high' },
  { re: /\bos\s*\.\s*system\s*\(/i, detail: 'os.system() call detected', severity: 'high' },
  { re: /\bchild_process\b/i, detail: 'child_process module usage', severity: 'high' },
  { re: /\bFunction\s*\(/i, detail: 'Function() constructor detected', severity: 'high' },
  { re: /\brequire\s*\(\s*['"]child_process['"]/i, detail: 'child_process require detected', severity: 'high' },
  { re: /\bimport\s*\(\s*['"]/i, detail: 'Dynamic import() detected', severity: 'medium' },
  { re: /atob\s*\(|btoa\s*\(|Buffer\.from\s*\([^)]*,\s*['"]base64['"]\)/i, detail: 'Base64 encoding/decoding detected', severity: 'medium' },
  { re: /stratum\+tcp:\/\//i, detail: 'Crypto mining pool URL detected', severity: 'critical' },
  { re: /coinhive/i, detail: 'CoinHive reference detected', severity: 'critical' },
  { re: /\bCryptoMiner\b|\bminer\.start\s*\(/i, detail: 'Crypto miner signature', severity: 'critical' },
];

function hasObfuscatedVars(code: string): boolean {
  // Detect excessive single-letter variable declarations in sequence
  const singleLetterDecls = code.match(/\b(var|let|const)\s+[a-z]\b/gi) || [];
  return singleLetterDecls.length >= 6;
}

export function scanCode(message: string, jobCategory?: string): OutputFlag[] {
  const flags: OutputFlag[] = [];
  const isCodeJob = jobCategory ? CODE_CATEGORIES.has(jobCategory) : false;

  // Extract code blocks
  const codeBlocks: string[] = [];
  let m: RegExpExecArray | null;
  const re = new RegExp(CODE_BLOCK_RE.source, CODE_BLOCK_RE.flags);
  while ((m = re.exec(message)) !== null) {
    codeBlocks.push(m[0]);
  }

  // P2-OUT-4: For code jobs, still scan critical patterns (mining, CoinHive)
  // Only skip high/medium patterns since eval/exec/subprocess are expected in code discussion
  const patterns = isCodeJob
    ? MALICIOUS_PATTERNS.filter(p => p.severity === 'critical')
    : MALICIOUS_PATTERNS;

  // Always scan the full message for dangerous patterns (not just code blocks).
  // An agent outputting eval(atob(...)) or stratum+tcp:// in prose is still dangerous.
  const seenDetails = new Set<string>();
  for (const pat of patterns) {
    const match = message.match(pat.re);
    if (match) {
      seenDetails.add(pat.detail);
      flags.push({
        type: 'malicious_code',
        severity: pat.severity,
        detail: pat.detail,
        evidence: match[0],
        action: pat.severity === 'critical' ? 'block' : 'warn',
      });
    }
  }

  // Scan code blocks for additional patterns not yet found
  for (const block of codeBlocks) {
    for (const pat of patterns) {
      if (seenDetails.has(pat.detail)) continue;
      const match = block.match(pat.re);
      if (match) {
        seenDetails.add(pat.detail);
        flags.push({
          type: 'malicious_code',
          severity: pat.severity,
          detail: pat.detail,
          evidence: match[0],
          action: pat.severity === 'critical' ? 'block' : 'warn',
        });
      }
    }

    if (!isCodeJob && hasObfuscatedVars(block)) {
      flags.push({
        type: 'malicious_code',
        severity: 'medium',
        detail: 'Potentially obfuscated code — excessive single-letter variables',
        evidence: '(multiple single-letter vars)',
        action: 'warn',
      });
    }
  }

  return flags;
}
