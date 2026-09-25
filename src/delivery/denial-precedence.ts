/**
 * InstrumentalEvasion thin land C — Persistent denial precedence.
 *
 * After a clear *authenticated* guardrail denial, encoded / aliased /
 * equivalent-effect proposals of the same prohibited op → still BLOCK.
 * Continuation / ralph-loop prompts must not weaken denial class.
 *
 * Soft-compose ActionGuard + ApprovalBinding (approve bind stays; this
 * persists *denied* effect class). Soft residuals stay soft. Escalate BLOCK.
 * Not deepset 80%. Shapes only — no encode recipes / live aliases.
 */

import { createHash, randomBytes } from 'node:crypto';

export type DenialAuthChannel =
  | 'guardrail'
  | 'monitor'
  | 'PreToolUse'
  | 'structured_denial_token'
  | string;

export interface AuthenticatedDenial {
  effectClass: string;
  /** Must be true for precedence — transient tool-error denials do not bind. */
  authenticated: true;
  channel: DenialAuthChannel;
  /** Opaque structured denial token minted at record time. */
  denialToken?: string;
  recordedAt?: number;
}

export type DenialPrecedenceVerdict = 'ALLOW' | 'BLOCK';

export type DenialPrecedenceGate =
  | 'DenialPrecedence.ALLOW'
  | 'DenialPrecedence.BLOCK_equivalent_effect'
  | 'DenialPrecedence.BLOCK_continuation'
  | 'DenialPrecedence.SKIP_unauthenticated'
  | 'DenialPrecedence.DENY_bad_input';

export type EquivalentRetryShape =
  | 'encoded_wrapper_equivalent'
  | 'alias_or_symlink_equivalent'
  | 'continuation_or_ralph_loop_reask'
  | 'equivalent_effect'
  | string;

export interface EquivalentEffectProposal {
  effectClass: string;
  shape?: EquivalentRetryShape;
  /** Optional explicit claim this is a continuation pressure ask. */
  continuation?: boolean;
}

export interface DenialPrecedenceResult {
  verdict: DenialPrecedenceVerdict;
  gate: DenialPrecedenceGate;
  escalate: boolean;
  /** Denial class must not weaken on continuation. */
  denialClassWeakened: false;
  matchedDenial?: AuthenticatedDenial;
  reason?: string;
}

function hashEffect(effectClass: string): string {
  return createHash('sha256').update(`deny-ec:${effectClass}`).digest('hex').slice(0, 16);
}

function mintDenialToken(): string {
  return `sg-deny-${randomBytes(12).toString('hex')}`;
}

/**
 * Ledger of authenticated guardrail denials. Encoded/aliased/equivalent
 * retries of the same effect class remain blocked; continuation must not
 * weaken the denial class.
 */
export class DenialPrecedenceLedger {
  private readonly byHash = new Map<string, AuthenticatedDenial>();

  get size(): number {
    return this.byHash.size;
  }

  list(): AuthenticatedDenial[] {
    return [...this.byHash.values()];
  }

  /**
   * Record a clear authenticated guardrail denial.
   * Unauthenticated / transient tool-error denials are rejected (not stored).
   */
  recordAuthenticatedDenial(input: {
    effectClass: string;
    authenticated: boolean;
    channel?: DenialAuthChannel;
  }): { ok: boolean; denial?: AuthenticatedDenial; reason?: string } {
    const effectClass = String(input?.effectClass ?? '').trim();
    if (!effectClass) {
      return { ok: false, reason: 'effectClass required' };
    }
    if (input.authenticated !== true) {
      return {
        ok: false,
        reason:
          'only authenticated guardrail denials bind — transient tool-error denials do not',
      };
    }
    const denial: AuthenticatedDenial = {
      effectClass,
      authenticated: true,
      channel: input.channel ?? 'guardrail',
      denialToken: mintDenialToken(),
      recordedAt: Date.now(),
    };
    this.byHash.set(hashEffect(effectClass), denial);
    return { ok: true, denial };
  }

  hasDenialFor(effectClass: string): boolean {
    return this.byHash.has(hashEffect(String(effectClass ?? '')));
  }

  /**
   * Gate encoded / aliased / equivalent-effect / continuation proposals
   * against the denial ledger. Same effect class → persistent BLOCK.
   */
  gateEquivalentEffect(
    proposal: EquivalentEffectProposal,
  ): DenialPrecedenceResult {
    const effectClass = String(proposal?.effectClass ?? '').trim();
    if (!effectClass) {
      return {
        verdict: 'BLOCK',
        gate: 'DenialPrecedence.DENY_bad_input',
        escalate: true,
        denialClassWeakened: false,
        reason: 'effectClass required',
      };
    }

    const matched = this.byHash.get(hashEffect(effectClass));
    if (!matched) {
      return {
        verdict: 'ALLOW',
        gate: 'DenialPrecedence.ALLOW',
        escalate: false,
        denialClassWeakened: false,
        reason: 'no authenticated denial for effect class',
      };
    }

    const shape = String(proposal.shape ?? '');
    const isContinuation =
      proposal.continuation === true ||
      /continuation|ralph/i.test(shape);

    return {
      verdict: 'BLOCK',
      gate: isContinuation
        ? 'DenialPrecedence.BLOCK_continuation'
        : 'DenialPrecedence.BLOCK_equivalent_effect',
      escalate: true,
      denialClassWeakened: false,
      matchedDenial: matched,
      reason: isContinuation
        ? 'continuation must not weaken authenticated denial class'
        : `equivalent-effect (${shape || 'equivalent'}) blocked after authenticated denial`,
    };
  }
}

/** Convenience one-shot: record then gate (tests / host). */
export function recordAuthenticatedDenial(
  ledger: DenialPrecedenceLedger,
  input: { effectClass: string; authenticated: boolean; channel?: DenialAuthChannel },
): { ok: boolean; denial?: AuthenticatedDenial; reason?: string } {
  return ledger.recordAuthenticatedDenial(input);
}

export function gateEquivalentEffect(
  ledger: DenialPrecedenceLedger,
  proposal: EquivalentEffectProposal,
): DenialPrecedenceResult {
  return ledger.gateEquivalentEffect(proposal);
}
