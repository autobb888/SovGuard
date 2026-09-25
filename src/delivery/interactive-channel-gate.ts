/**
 * InstrumentalEvasion thin land B — Interactive channel close.
 *
 * Intercept write_stdin / post-launch interactive / child stdin under the
 * **same policy** as parent process launch. Parent ALLOW does not waive
 * follow-on prohibited effect ops on interactive channels.
 *
 * Soft-compose ActionGuard. Soft residuals stay soft. Escalate BLOCK.
 * Not deepset 80%. Shapes only — no live stdin payloads.
 */

export type InteractiveChannel =
  | 'write_stdin'
  | 'post_launch_interactive'
  | 'child_stdin'
  | 'write_stdin_or_post_launch_interactive_or_child_stdin';

export type InteractiveChannelVerdict = 'ALLOW' | 'BLOCK';

export type InteractiveChannelGateId =
  | 'InteractiveChannel.ALLOW'
  | 'InteractiveChannel.BLOCK_prohibited_effect'
  | 'InteractiveChannel.BLOCK_same_policy'
  | 'InteractiveChannel.DENY_bad_input';

export type ParentLaunchPolicy = 'ALLOW' | 'BLOCK' | 'DENY';

export interface ParentLaunchContext {
  /** Shape only — e.g. allowed_repl_or_process. */
  shape?: string;
  policy: ParentLaunchPolicy;
}

export interface InteractiveFollowOn {
  channel: InteractiveChannel;
  /**
   * Effect-class / ops shape carried on the channel.
   * "prohibited_effect_ops" → must be reviewed under parent policy.
   */
  payloadShape?: string;
  /** Explicit effect class if known. */
  effectClass?: string;
  /** Whether payload carries a prohibited effect (host/policy signal). */
  prohibitedEffect?: boolean;
}

export interface InteractiveChannelAttempt {
  parentLaunch: ParentLaunchContext;
  followOn: InteractiveFollowOn;
}

export interface InteractiveChannelGateResult {
  verdict: InteractiveChannelVerdict;
  gate: InteractiveChannelGateId;
  escalate: boolean;
  /** True — follow-on reviewed under same policy as parent launch. */
  reviewedUnderParentPolicy: true;
  channel: InteractiveChannel;
  reason?: string;
}

const INTERACTIVE_CHANNELS = new Set<string>([
  'write_stdin',
  'post_launch_interactive',
  'child_stdin',
  'write_stdin_or_post_launch_interactive_or_child_stdin',
]);

function isProhibitedFollowOn(followOn: InteractiveFollowOn): boolean {
  if (followOn.prohibitedEffect === true) return true;
  const shape = String(followOn.payloadShape ?? '').toLowerCase();
  const ec = String(followOn.effectClass ?? '').toLowerCase();
  return (
    shape.includes('prohibited') ||
    ec.includes('prohibited') ||
    shape === 'prohibited_effect_ops'
  );
}

/**
 * Gate write_stdin / post-launch interactive / child stdin under the same
 * policy as parent process launch. Parent ALLOW does not auto-ALLOW
 * prohibited follow-on effects on interactive channels.
 */
export function gateWriteStdin(
  attempt: InteractiveChannelAttempt,
): InteractiveChannelGateResult {
  return gateInteractiveChannel(attempt);
}

/** Alias — child stdin under same policy. */
export function gateChildStdin(
  attempt: InteractiveChannelAttempt,
): InteractiveChannelGateResult {
  return gateInteractiveChannel(attempt);
}

export function gateInteractiveChannel(
  attempt: InteractiveChannelAttempt,
): InteractiveChannelGateResult {
  const parent = attempt?.parentLaunch;
  const followOn = attempt?.followOn;
  const channel = followOn?.channel;

  if (!parent?.policy || !channel) {
    return {
      verdict: 'BLOCK',
      gate: 'InteractiveChannel.DENY_bad_input',
      escalate: true,
      reviewedUnderParentPolicy: true,
      channel: (channel ?? 'write_stdin') as InteractiveChannel,
      reason: 'parentLaunch.policy and followOn.channel required',
    };
  }

  if (!INTERACTIVE_CHANNELS.has(channel)) {
    return {
      verdict: 'BLOCK',
      gate: 'InteractiveChannel.DENY_bad_input',
      escalate: true,
      reviewedUnderParentPolicy: true,
      channel,
      reason: `unknown interactive channel: ${channel}`,
    };
  }

  // Parent launch BLOCK/DENY → follow-on blocked under same policy
  if (parent.policy === 'BLOCK' || parent.policy === 'DENY') {
    return {
      verdict: 'BLOCK',
      gate: 'InteractiveChannel.BLOCK_same_policy',
      escalate: true,
      reviewedUnderParentPolicy: true,
      channel,
      reason: 'parent launch policy BLOCK/DENY — interactive channel inherits',
    };
  }

  // Parent ALLOW but follow-on carries prohibited effect → BLOCK
  // (must not skip monitor solely because parent launch was ALLOW)
  if (isProhibitedFollowOn(followOn)) {
    return {
      verdict: 'BLOCK',
      gate: 'InteractiveChannel.BLOCK_prohibited_effect',
      escalate: true,
      reviewedUnderParentPolicy: true,
      channel,
      reason:
        'prohibited effect on interactive channel reviewed under parent policy — parent ALLOW does not waive',
    };
  }

  return {
    verdict: 'ALLOW',
    gate: 'InteractiveChannel.ALLOW',
    escalate: false,
    reviewedUnderParentPolicy: true,
    channel,
  };
}
