/**
 * Outbound URL Scanner
 * Flags shorteners, IP URLs, homograph domains, suspicious domains.
 */

import type { OutputFlag } from '../types.js';
import { URL_RE } from './patterns.js';

// ── Agent Exfiltration Patterns (v0.2.0) ─────────────────────

const WEBHOOK_DOMAINS = new Set([
  'hooks.slack.com',
  'requestbin.com',
  'requestbin.net',
  'webhook.site',
  'hookbin.com',
  'beeceptor.com',
]);

/** Partial-match patterns for webhook/callback/bot domains */
const EXFIL_DOMAIN_PATTERNS = [
  /\.pipedream\.com$/i,
  /\.pipedream\.net$/i,
  /\.ngrok\.io$/i,
  /\.ngrok-free\.app$/i,
  /\.burpcollaborator\.net$/i,
  /\.oastify\.com$/i,
  /\.requestbin\./i,
];

const BOT_API_PATHS = [
  /discord\.com\/api\/webhooks\//i,
  /api\.telegram\.org\/bot/i,
];

/**
 * Detect base64-encoded query parameters (long b64 strings in URL params).
 */
function hasBase64QueryParam(url: string): boolean {
  try {
    const parsed = new URL(url);
    for (const [, value] of parsed.searchParams) {
      // 40+ chars of base64-like content in a single param value
      if (value.length >= 40 && /^[A-Za-z0-9+/=]{40,}$/.test(value)) {
        return true;
      }
    }
  } catch {
    // Invalid URL
  }
  return false;
}

function isExfilDomain(hostname: string): boolean {
  if (WEBHOOK_DOMAINS.has(hostname)) return true;
  for (const pattern of EXFIL_DOMAIN_PATTERNS) {
    if (pattern.test(hostname)) return true;
  }
  return false;
}

function isBotApiUrl(url: string): boolean {
  for (const pattern of BOT_API_PATHS) {
    if (pattern.test(url)) return true;
  }
  return false;
}

const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
  'buff.ly', 'adf.ly', 'tiny.cc', 'lnkd.in', 'db.tt', 'qr.ae',
  'cur.lv', 'rebrand.ly', 'bl.ink', 'short.io',
]);

const IP_URL_RE = /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}|https?:\/\/\[[0-9a-fA-F:]+\]/i;

// Cyrillic/Greek chars that look like Latin
const HOMOGRAPH_MAP: Record<string, string> = {
  '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p',
  '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u043D': 'h',
  '\u0456': 'i', '\u0458': 'j', '\u0455': 's', '\u0460': 'w',
  '\u03B1': 'a', '\u03BF': 'o', '\u03C1': 'p', '\u03B5': 'e',
};

function hasHomoglyphs(domain: string): boolean {
  for (const ch of domain) {
    if (HOMOGRAPH_MAP[ch]) return true;
  }
  return false;
}

function isSuspiciousDomain(hostname: string): boolean {
  // Random-looking: lots of consonant clusters or very long subdomain
  const parts = hostname.split('.');
  if (parts.length > 4) return true;
  const sub = parts.slice(0, -2).join('.');
  if (sub.length > 30) return true;
  // High entropy heuristic: many consonants in a row
  if (/[bcdfghjklmnpqrstvwxyz]{5,}/i.test(sub)) return true;
  return false;
}

export function scanURLs(message: string): OutputFlag[] {
  const flags: OutputFlag[] = [];

  // Dangerous URI schemes (XSS / local file access)
  const DANGEROUS_SCHEME_RE = /\b(?:javascript|vbscript|blob|file):/i;
  const schemeMatch = message.match(DANGEROUS_SCHEME_RE);
  if (schemeMatch) {
    flags.push({
      type: 'suspicious_url',
      severity: 'critical',
      detail: `Dangerous URI scheme detected: ${schemeMatch[0]}`,
      evidence: schemeMatch[0],
      action: 'block',
    });
  }

  // P3-SC-005: Check for data: URIs (can embed full HTML/JS payloads — with or without base64)
  if (/\bdata:[a-z/+.\-]{1,50}[,;]/i.test(message)) {
    flags.push({
      type: 'data_uri',
      severity: 'high',
      detail: 'data: URI detected — may embed malicious content',
      evidence: message.match(/\bdata:[^,\s]{0,80},?[^\s]{0,20}/i)?.[0] || 'data:...',
      action: 'block',
    });
  }

  const urlRe = new RegExp(URL_RE.source, URL_RE.flags);
  let m: RegExpExecArray | null;

  while ((m = urlRe.exec(message)) !== null) {
    const url = m[0];
    let hostname: string;
    let rawHost: string;
    try {
      const parsed = new URL(url);
      hostname = parsed.hostname.toLowerCase();
      // Extract raw host from URL string for homoglyph check (before punycode)
      rawHost = url.replace(/^https?:\/\//, '').split(/[/:?#]/)[0].toLowerCase();
    } catch {
      continue;
    }

    if (hasHomoglyphs(rawHost)) {
      flags.push({
        type: 'suspicious_url',
        severity: 'critical',
        detail: 'Homograph domain detected — possible phishing',
        evidence: url,
        action: 'block',
      });
      continue;
    }

    if (SHORTENERS.has(hostname)) {
      flags.push({
        type: 'suspicious_url',
        severity: 'medium',
        detail: 'URL shortener detected — destination unknown',
        evidence: url,
        action: 'warn',
      });
      continue;
    }

    if (IP_URL_RE.test(url)) {
      flags.push({
        type: 'suspicious_url',
        severity: 'high',
        detail: 'IP-address URL detected',
        evidence: url,
        action: 'block',
      });
      continue;
    }

    if (isSuspiciousDomain(hostname)) {
      flags.push({
        type: 'suspicious_url',
        severity: 'medium',
        detail: 'Suspicious domain structure',
        evidence: url,
        action: 'warn',
      });
      continue;
    }

    // Agent exfiltration: webhook/callback domains
    if (isExfilDomain(hostname)) {
      flags.push({
        type: 'agent_exfiltration',
        severity: 'critical',
        detail: 'Webhook/callback exfiltration URL detected',
        evidence: url,
        action: 'block',
      });
      continue;
    }

    // Agent exfiltration: bot API URLs
    if (isBotApiUrl(url)) {
      flags.push({
        type: 'agent_exfiltration',
        severity: 'critical',
        detail: 'Bot API exfiltration URL detected',
        evidence: url,
        action: 'block',
      });
      continue;
    }

    // Agent exfiltration: base64-encoded query parameters
    if (hasBase64QueryParam(url)) {
      flags.push({
        type: 'agent_exfiltration',
        severity: 'high',
        detail: 'Base64-encoded query parameter — possible data exfiltration',
        evidence: url,
        action: 'block',
      });
    }
  }

  return flags;
}
