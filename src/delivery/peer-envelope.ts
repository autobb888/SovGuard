/**
 * DL-007 — Inter-agent envelopes (data ↛ instruction).
 * Peer `data` is always untrusted (scanContext source=other_agent + Spotlight).
 * It cannot promote to instruction/system or expand the user-origin ActionGuard plan.
 */
import { scanContext, type ContextScanResult } from '../scanner/context.js';
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
 * - `instruction` is dropped by default (cannot promote data→instruction).
 * - Optional ActionGuard against the originating user's trustedPlan.
 */
export async function ingestPeerEnvelope(
  envelope: PeerEnvelope,
  opts: PeerIngestOptions = {},
): Promise<PeerIngestResult> {
  const flags: string[] = ['peer_envelope', 'source:other_agent'];

  let instruction: string | null = null;
  if (opts.allowPeerInstruction && typeof envelope.instruction === 'string' && envelope.instruction.trim()) {
    instruction = envelope.instruction;
    flags.push('peer_instruction_allowed');
  } else if (envelope.instruction != null && String(envelope.instruction).trim()) {
    flags.push('peer_instruction_dropped');
  }

  const raw = dataToText(envelope.data);
  const { text: visible, comments } = stripHtmlComments(raw);
  for (const c of comments) {
    flags.push('html_comment_stripped');
    if (HIDDEN_DIRECTIVE.test(c)) flags.push('hidden_peer_directive');
  }
  if (HIDDEN_DIRECTIVE.test(visible)) flags.push('directive_language_in_data');

  // Scan visible + comment bodies so hidden HTML directives still trip the scanner.
  const scanInput = [visible, ...comments].filter(Boolean).join('\n');
  const scan = await scanContext(scanInput, {
    source: 'other_agent',
    policy: opts.policy ?? 'quarantine',
  });

  // Prefer scanContext output (already boundary-scrubbed); Spotlight-wrap when allowed
  // so role stays untrusted:other_agent even if classification is safe.
  let dataText = scan.text;
  if (scan.action === 'allow') {
    dataText = wrapMessage(scan.text, scan.scan, {
      role: 'untrusted:other_agent',
    }).formatted;
    flags.push('spotlight_wrap');
  } else {
    flags.push(`contained:${scan.action}`);
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
