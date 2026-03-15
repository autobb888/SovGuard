/**
 * Outbound Financial Scanner
 * Detects crypto wallets, payment requests in agent responses.
 */

import type { OutputFlag } from '../types.js';

// BTC: 1/3/bc1 addresses
const BTC_RE = /\b(1[1-9A-HJ-NP-Za-km-z]{25,34}|3[1-9A-HJ-NP-Za-km-z]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,87})\b/g;
// ETH: 0x + 40 hex
const ETH_RE = /\b0x[0-9a-fA-F]{40}\b/g;
// VRSC: R-address
const VRSC_RE = /\bR[1-9A-HJ-NP-Za-km-z]{25,34}\b/g;
// XMR: Monero mainnet (4 or 8 prefix, 95 chars)
const XMR_RE = /\b[48][0-9A-Za-z]{94}\b/g;
// LTC: Litecoin (L/M/ltc1 prefix)
const LTC_RE = /\b[LM][1-9A-HJ-NP-Za-km-z]{25,34}\b/g;

const PAYMENT_PATTERNS = [
  /send\s+(funds?|money|payment|crypto|coins?|tokens?)\s+to/i,
  /transfer\s+(funds?|money|payment)\s+to/i,
  /pay\s+(me|us|this\s+address)\b/i,
  /wire\s+(funds?|money)\s+to/i,
  /donate\s+(to|at)\s+/i,
  /\b(venmo|cashapp|zelle|paypal\.me)\s*[:\/@]/i,
];

/**
 * @param message - Agent response text
 * @param whitelistedAddresses - Addresses to skip (e.g., job's own payment address)
 */
export function scanFinancial(message: string, whitelistedAddresses?: Set<string>): OutputFlag[] {
  const flags: OutputFlag[] = [];
  const whitelist = whitelistedAddresses || new Set();

  // Crypto wallets
  for (const [re, label] of [
    [BTC_RE, 'BTC wallet'],
    [ETH_RE, 'ETH wallet'],
    [VRSC_RE, 'VRSC wallet'],
    [XMR_RE, 'XMR wallet'],
    [LTC_RE, 'LTC wallet'],
  ] as const) {
    const regex = new RegExp(re.source, re.flags);
    let m: RegExpExecArray | null;
    while ((m = regex.exec(message)) !== null) {
      // P2-OUT-3: Skip the job's own payment address
      if (whitelist.has(m[0])) continue;
      flags.push({
        type: 'financial_manipulation',
        severity: 'high',
        detail: `${label} address detected in output`,
        evidence: m[0],
        action: 'block',
      });
    }
  }

  // Payment requests
  for (const pat of PAYMENT_PATTERNS) {
    const m = message.match(pat);
    if (m) {
      flags.push({
        type: 'financial_manipulation',
        severity: 'high',
        detail: 'Payment/fund transfer request detected',
        evidence: m[0],
        action: 'block',
      });
    }
  }

  return flags;
}
