/**
 * DL-007 — Inter-agent envelopes (data ↛ instruction).
 * Peer `data` is always untrusted (scanContext source=other_agent + Spotlight).
 * It cannot promote to instruction/system or expand the user-origin ActionGuard plan.
 *
 * HTML comments are stripped from delivery; comment bodies are scanned for flags
 * only and never concatenated into dataText.
 */
import { scanContext, type ContextScanResult } from '../scanner/context.js';
import { scrubUntrustedIngress } from '../scanner/boundary-scrub.js';
import { wrapMessage } from './wrap.js';
import {
  actionGuard,
  type TrustedPlan,
  type ProposedAction,
  type ActionGuardResult,
} from './action-guard.js';

export interface PeerEnvelope {
  from?: string;
  /** Peer-supplied instruction is ignored unless allowPeerInstruction is explicitly set. */
  instruction?: string | null;
  data: string | Record<string, unknown> | unknown;
}

export interface PeerIngestOptions {
  trustedPlan?: TrustedPlan;
  /** Tool/URL actions the model proposes after reading peer data — gated by trustedPlan. */
  proposedActions?: ProposedAction[];
  /**
   * Dangerous escape hatch: allow a peer `instruction` field.
   * Default false — data never promotes to instruction.
   * When true, instruction still runs scrubUntrustedIngress + scanContext.
   */
  allowPeerInstruction?: boolean;
  policy?: 'block' | 'strip' | 'quarantine';
}

export interface PeerIngestResult {
  from?: string;
  /** Always null unless allowPeerInstruction was set AND envelope.instruction was a string. */
  instruction: string | null;
  /** Text delivered into the agent context (Spotlight / quarantine as needed). */
  dataText: string;
  role: 'untrusted:other_agent';
  scan: ContextScanResult;
  actionGuard?: ActionGuardResult;
  flags: string[];
}

const HIDDEN_DIRECTIVE =
  /ignore\s+(previous|prior|all)\b|system\s+prompt|send_email|treat this .{0,40}as .{0,20}(system|instruction)/i;

/** Extract HTML/XML comments; return visible text + comment bodies. */
export function stripHtmlComments(text: string): { text: string; comments: string[] } {
  const comments: string[] = [];
  const visible = text.replace(/<!--([\s\S]*?)-->/g, (_m, body: string) => {
    comments.push(body);
    return ' ';
  });
  return { text: visible, comments };
}

function dataToText(data: PeerEnvelope['data']): string {
  if (typeof data === 'string') return data;
  try {
    return JSON.stringify(data);
  } catch {
    return String(data);
  }
}

/**
 * Ingest a peer agent envelope.
 * - `data` always runs untrusted other_agent pipeline (boundary scrub + scan + Spotlight).
 * - HTML comment bodies are scanned for flags only — never delivered in dataText.
 * - `instruction` is dropped by default; when allowed, still scrubbed + scanned.
 * - Optional ActionGuard against the originating user's trustedPlan.
 */
export async function ingestPeerEnvelope(
  envelope: PeerEnvelope,
  opts: PeerIngestOptions = {},
): Promise<PeerIngestResult> {
  const flags: string[] = ['peer_envelope', 'source:other_agent'];
  const policy = opts.policy ?? 'quarantine';

  let instruction: string | null = null;
  if (opts.allowPeerInstruction && typeof envelope.instruction === 'string' && envelope.instruction.trim()) {
    const scrubbed = scrubUntrustedIngress(envelope.instruction).text;
    const instrScan = await scanContext(scrubbed, {
      source: 'other_agent',
      policy,
    });
    instruction = instrScan.text;
    flags.push('peer_instruction_allowed');
    if (instrScan.action !== 'allow') flags.push(`peer_instruction_contained:${instrScan.action}`);
  } else if (envelope.instruction != null && String(envelope.instruction).trim()) {
    flags.push('peer_instruction_dropped');
  }

  const raw = dataToText(envelope.data);
  const { text: visible, comments } = stripHtmlComments(raw);

  let hiddenDirective = false;
  for (const c of comments) {
    flags.push('html_comment_stripped');
    if (HIDDEN_DIRECTIVE.test(c)) {
      flags.push('hidden_peer_directive');
      hiddenDirective = true;
    }
  }
  if (HIDDEN_DIRECTIVE.test(visible)) flags.push('directive_language_in_data');

  // Deliver visible text only — never concatenate / substitute comment bodies.
  const visibleScan = await scanContext(visible, {
    source: 'other_agent',
    policy,
  });

  let commentFlagged = false;
  let maxCommentScore = 0;
  for (const c of comments) {
    if (!c.trim()) continue;
    const commentScan = await scanContext(c, {
      source: 'other_agent',
      policy,
    });
    if (commentScan.flagged || !commentScan.scan.safe) {
      commentFlagged = true;
      flags.push('comment_scan_flagged');
    }
    maxCommentScore = Math.max(maxCommentScore, commentScan.scan.score);
  }

  // Escalate scan metadata from comments without changing delivery text.
  const scan: ContextScanResult = {
    ...visibleScan,
    flagged: visibleScan.flagged || commentFlagged || hiddenDirective,
    scan: {
      ...visibleScan.scan,
      score: Math.max(visibleScan.scan.score, maxCommentScore),
      safe: visibleScan.scan.safe && !commentFlagged && !hiddenDirective,
      flags: [
        ...visibleScan.scan.flags,
        ...(hiddenDirective ? ['hidden_peer_directive'] : []),
        ...(commentFlagged ? ['comment_scan_flagged'] : []),
      ],
    },
  };

  const forceContain = hiddenDirective || commentFlagged;
  let dataText: string;

  if (forceContain) {
    flags.push(
      hiddenDirective
        ? 'forced_contain:hidden_peer_directive'
        : 'forced_contain:comment_scan_flagged',
    );
    // Always Spotlight-wrap visible-only text — never comment bodies.
    dataText = wrapMessage(visibleScan.text, scan.scan, {
      role: 'untrusted:other_agent',
    }).formatted;
    flags.push('contained:quarantine');
  } else if (visibleScan.action === 'allow') {
    dataText = wrapMessage(visibleScan.text, visibleScan.scan, {
      role: 'untrusted:other_agent',
    }).formatted;
    flags.push('spotlight_wrap');
  } else {
    // strip/quarantine/block from visible path only
    dataText = visibleScan.text;
    flags.push(`contained:${visibleScan.action}`);
  }

  // Hard guarantee: no HTML comment delimiters or comment-only payloads in delivery.
  dataText = dataText.replace(/<!--[\s\S]*?-->/g, ' ');
  for (const c of comments) {
    const trimmed = c.trim();
    if (!trimmed) continue;
    // Remove distinctive comment substrings that are not in visible text
    if (!visible.includes(trimmed) && dataText.includes(trimmed)) {
      dataText = dataText.split(trimmed).join('');
      flags.push('comment_leak_stripped');
    }
    // Also scrub shorter unique needles (emails etc.) from comments not in visible
    for (const token of trimmed.split(/\s+/)) {
      if (token.length >= 8 && token.includes('@') && !visible.includes(token) && dataText.includes(token)) {
        dataText = dataText.split(token).join('');
        flags.push('comment_leak_stripped');
      }
    }
  }

  let guard: ActionGuardResult | undefined;
  if (opts.trustedPlan && opts.proposedActions) {
    guard = actionGuard(opts.trustedPlan, opts.proposedActions, { source: 'other_agent' });
    if (guard.denied.length > 0) flags.push('action_guard_denied');
  }

  return {
    from: envelope.from,
    instruction,
    dataText,
    role: 'untrusted:other_agent',
    scan,
    actionGuard: guard,
    flags: [...new Set(flags)],
  };
}
