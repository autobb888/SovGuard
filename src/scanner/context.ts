/**
 * Source-trust-aware context scanning.
 *
 * scan() asks "is this text an injection?". scanContext() adds the question that
 * actually matters for agents: "where did this text come from, and what should
 * we DO about it?". Untrusted content (a tool result, a fetched file, an MCP
 * response, a job description) that trips the scanner is contained per policy
 * and always produces a notification; trusted user input is never muzzled.
 */

import { scan } from './index.js';
import { wrapMessage } from '../delivery/wrap.js';
import { scrubUntrustedIngress } from './boundary-scrub.js';
import { detectDelayedTrigger } from './delayed-trigger.js';
import { detectDecomposition, decompositionWatch } from './decomposition.js';
import { detectManyShot } from './many-shot.js';
import type { ScanResult, SovGuardConfig } from '../types.js';

/** Where a piece of text entered the agent's context, in increasing distrust. */
export type SourceTrust =
  | 'user'            // the operator/buyer's own instruction — trusted
  | 'job_description' // attacker-controllable: a job posted to a seller agent
  | 'workspace_file'  // file content read into context
  | 'mcp_result'      // result returned from an MCP/tool call
  | 'api_response'    // an external API response folded into context
  | 'other_agent'    // output from another agent
  | 'email'          // inbound email / recipient-framed content
  | 'web'            // fetched web content
  | 'file';          // uploaded/attached file content

/** What to do when UNTRUSTED content trips the scanner. */
export type TaintPolicy = 'block' | 'strip' | 'quarantine';

/** The decision scanContext made for this piece of text. */
export type TaintAction = 'allow' | 'block' | 'strip' | 'quarantine';

export interface ContextScanOptions extends SovGuardConfig {
  /** Required: where this text came from. Drives the trust decision. */
  source: SourceTrust;
  /** Containment policy for flagged untrusted content. Default: 'strip'. */
  policy?: TaintPolicy;
}

/** Routable notification emitted whenever content is contained. */
export interface TaintNotification {
  severity: 'low' | 'medium' | 'high' | 'critical';
  source: SourceTrust;
  action: TaintAction;
  score: number;
  flags: string[];
  /** Redacted/short evidence safe to surface to a human. */
  evidence: string;
  /** Human-readable summary for buyer/seller/operator. */
  message: string;
}

export interface ContextScanResult {
  source: SourceTrust;
  /** True only for sources we treat as the agent's own instructions. */
  trusted: boolean;
  /** True when untrusted content tripped the scanner. */
  flagged: boolean;
  action: TaintAction;
  /** The text to actually use downstream (sanitized when stripped/quarantined). */
  text: string;
  scan: ScanResult;
  /** Present whenever action !== 'allow'. */
  notify?: TaintNotification;
}

const TRUSTED_SOURCES: ReadonlySet<SourceTrust> = new Set<SourceTrust>(['user']);
const DEFAULT_POLICY: TaintPolicy = 'strip';
const REDACTION = '[redacted: suspected injected instruction]';

export async function scanContext(text: string, options: ContextScanOptions): Promise<ContextScanResult> {
  const { source, policy, ...config } = options;
  const scanResult = await scan(text, config);
  const trusted = TRUSTED_SOURCES.has(source);

  // DL-006: scrub → Unicode fixed-point → scrub on untrusted ingress only
  // so Tags/ZW/fullwidth cannot reconstitute delimiters after one pass.
  let working = text;
  if (!trusted) {
    working = scrubUntrustedIngress(text).text;
  }

  // DL-008: sleeping if/when+tool rules in untrusted memory → force contain
  const delayed = !trusted ? detectDelayedTrigger(text) : { found: false as const };
  const delayedForce = !!(delayed as { found: boolean }).found;

  // DL-009: reconstruct-then-execute / split-payload heuristics
  const decomp = !trusted ? detectDecomposition(text) : { found: false as const, kinds: [] as string[] };
  const decompForce = !!(decomp as { found: boolean }).found;

  // DL-010: many-shot comply-density (often inside a single user blob)
  const manyShot = detectManyShot(text);
  const manyShotForce = manyShot.found;
  if (manyShotForce) {
    scanResult.flags = [...scanResult.flags, 'many_shot', `many_shot:comply_${manyShot.complyCount}`];
    scanResult.safe = false;
    scanResult.classification = scanResult.classification === 'safe' ? 'suspicious' : scanResult.classification;
    scanResult.score = Math.max(scanResult.score, 0.55);
  }

  // Untrusted: many-shot forces contain. Trusted user: flag scan only (never muzzle).
  const flagged = !trusted && (!scanResult.safe || delayedForce || decompForce || manyShotForce);

  if (!flagged) {
    return { source, trusted, flagged, action: 'allow', text: working, scan: scanResult };
  }

  // Prefer quarantine for delayed triggers even when policy is strip
  if (delayedForce && (policy ?? DEFAULT_POLICY) === 'strip') {
    // fall through using quarantine-equivalent by upgrading policy locally
  }

  let effectivePolicy = policy ?? DEFAULT_POLICY;
  if ((delayedForce || decompForce || manyShotForce) && effectivePolicy === 'strip') {
    effectivePolicy = 'quarantine';
  }
  let outText = working;
  let action: TaintAction = effectivePolicy;
  if (effectivePolicy === 'strip') {
    const stripped = stripInjection(working, scanResult);
    if (stripped === working) {
      // Nothing localizable to redact (e.g. an encoded payload). Don't pass it
      // through unchanged — degrade to quarantine so it's still neutralized.
      outText = quarantineWrap(working, source, scanResult);
      action = 'quarantine';
    } else {
      outText = stripped;
    }
  } else if (effectivePolicy === 'quarantine') {
    outText = quarantineWrap(working, source, scanResult);
  }
  // 'block': outText stays scrubbed working; caller must refuse to use it.

  if (delayedForce) {
    scanResult.flags = [...scanResult.flags, 'delayed_trigger'];
    if (!scanResult.safe) {
      /* keep */
    } else {
      scanResult.safe = false;
      scanResult.classification = scanResult.classification === 'safe' ? 'suspicious' : scanResult.classification;
      scanResult.score = Math.max(scanResult.score, 0.45);
    }
  }
  if (decompForce) {
    scanResult.flags = [...scanResult.flags, 'decomposition', ...((decomp as { kinds?: string[] }).kinds ?? []).map((k) => `decomposition:${k}`)];
    scanResult.safe = false;
    scanResult.classification = scanResult.classification === 'safe' ? 'suspicious' : scanResult.classification;
    scanResult.score = Math.max(scanResult.score, 0.5);
  }
  return {
    source,
    trusted,
    flagged,
    action,
    text: outText,
    scan: scanResult,
    notify: buildNotification(source, action, scanResult),
  };
}

/** Literal matched substrings the scanner flagged, for redaction. */
function collectMatchSpans(scan: ScanResult): string[] {
  const spans: string[] = [];
  for (const layer of scan.layers) {
    const matches = (layer.details as { matches?: Array<{ matched?: unknown }> } | undefined)?.matches;
    if (!Array.isArray(matches)) continue;
    for (const m of matches) {
      if (typeof m?.matched === 'string') spans.push(m.matched);
    }
  }
  return spans;
}

/**
 * Quarantine untrusted content via Spotlight wrap (randomized USER_DATA markers,
 * HTML escape, rules-after-content). Replaces the old fixed <untrusted-data> fence.
 */
function quarantineWrap(text: string, source: SourceTrust, scan: ScanResult): string {
  return wrapMessage(text, scan, { role: `untrusted:${source}` }).formatted;
}

/** Redact the flagged spans we can localize from the text. */
function stripInjection(text: string, scan: ScanResult): string {
  let out = text;
  for (const span of collectMatchSpans(scan)) {
    if (span && out.includes(span)) {
      out = out.split(span).join(REDACTION);
    }
  }
  return out;
}

function buildNotification(source: SourceTrust, action: TaintAction, scan: ScanResult): TaintNotification {
  const severity: TaintNotification['severity'] =
    scan.score >= 0.7 ? 'high' : scan.score >= 0.3 ? 'medium' : 'low';
  return {
    severity,
    source,
    action,
    score: scan.score,
    flags: scan.flags,
    evidence: scan.flags.join(', ').slice(0, 120),
    message: `Untrusted ${source} content tripped SovGuard (score ${scan.score.toFixed(2)}); action taken: ${action}.`,
  };
}
