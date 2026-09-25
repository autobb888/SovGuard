/**
 * TraceIntegrity thin land D — Tool authenticity.
 *
 * Detect BASH_ENV / shell-snapshot mutation that redefines known tool
 * binaries → FLAG; subsequent results untrusted until absolute-path re-verify.
 *
 * Soft residuals stay soft. Escalate BLOCK. Not deepset 80%. Shapes only.
 * Do not reopen ControlToken / Chronos / A2A / A2M.
 */

export type ToolAuthenticityVerdict = 'OK' | 'FLAG' | 'UNTRUSTED';

export type ToolAuthenticityGate =
  | 'ToolAuthenticity.OK'
  | 'ToolAuthenticity.FLAG_redefine'
  | 'ToolAuthenticity.UNTRUSTED_pending_reverify'
  | 'ToolAuthenticity.REVERIFIED'
  | 'ToolAuthenticity.DENY_bad_input';

export type AuthenticityMutationChannel =
  | 'BASH_ENV'
  | 'shell_snapshot'
  | 'BASH_ENV_or_shell_snapshot'
  | string;

export interface ToolRedefineMutation {
  channel: AuthenticityMutationChannel;
  /** Tool binary name being redefined (e.g. curl). */
  toolName: string;
  /** Optional shadowed / fake path. */
  redefinedPath?: string;
  shape?: 'redefine_known_tool_binary' | string;
}

export interface ToolAuthenticityFlagResult {
  verdict: 'FLAG';
  gate: ToolAuthenticityGate;
  toolName: string;
  channel: string;
  escalate: boolean;
  reason: string;
}

export interface ToolResultAuthenticity {
  verdict: ToolAuthenticityVerdict;
  gate: ToolAuthenticityGate;
  toolName: string;
  trusted: boolean;
  requiresAbsolutePathReverify: boolean;
  reason?: string;
}

/** Default known binaries scoped for authenticity (FP mitigation). */
export const DEFAULT_KNOWN_TOOL_BINARIES: readonly string[] = [
  'curl',
  'wget',
  'ssh',
  'scp',
  'git',
  'python',
  'python3',
  'node',
  'npm',
  'bash',
  'sh',
  'jq',
  'tar',
  'openssl',
];

const MUTATION_CHANNELS = new Set([
  'BASH_ENV',
  'shell_snapshot',
  'BASH_ENV_or_shell_snapshot',
]);

export interface ToolAuthenticityOptions {
  knownBinaries?: readonly string[];
}

/**
 * Stateful authenticity tracker: FLAG on redefine; mark subsequent results
 * untrusted until absolute-path re-verify clears the flag for that tool.
 */
export class ToolAuthenticityTracker {
  private readonly known: Set<string>;
  /** Tools currently flagged as redefined / untrusted. */
  private flagged = new Map<string, { channel: string; redefinedPath?: string }>();

  constructor(opts?: ToolAuthenticityOptions) {
    this.known = new Set(
      (opts?.knownBinaries ?? DEFAULT_KNOWN_TOOL_BINARIES).map((t) => t.toLowerCase()),
    );
  }

  isKnownBinary(toolName: string): boolean {
    return this.known.has(String(toolName ?? '').toLowerCase());
  }

  /**
   * Observe a BASH_ENV / shell-snapshot mutation that redefines a known tool.
   * → FLAG; escalate.
   */
  observeMutation(mutation: ToolRedefineMutation): ToolAuthenticityFlagResult | { verdict: 'OK'; gate: ToolAuthenticityGate; reason?: string } {
    const toolName = String(mutation?.toolName ?? '').trim();
    const channel = String(mutation?.channel ?? '');
    if (!toolName || !channel) {
      return {
        verdict: 'OK',
        gate: 'ToolAuthenticity.DENY_bad_input',
        reason: 'toolName and channel required',
      };
    }
    if (!MUTATION_CHANNELS.has(channel) && !/BASH_ENV|shell.?snapshot/i.test(channel)) {
      return {
        verdict: 'OK',
        gate: 'ToolAuthenticity.OK',
        reason: 'channel not a shell-env redefine surface',
      };
    }
    if (!this.isKnownBinary(toolName)) {
      return {
        verdict: 'OK',
        gate: 'ToolAuthenticity.OK',
        reason: 'not a scoped known tool binary — benign BASH_ENV customization ignored',
      };
    }

    this.flagged.set(toolName.toLowerCase(), {
      channel,
      redefinedPath: mutation.redefinedPath,
    });

    return {
      verdict: 'FLAG',
      gate: 'ToolAuthenticity.FLAG_redefine',
      toolName: toolName.toLowerCase(),
      channel,
      escalate: true,
      reason: `${channel} redefines known tool ${toolName} — subsequent results untrusted until absolute-path re-verify`,
    };
  }

  /**
   * Assess a subsequent tool result. If tool was redefined and result did not
   * come via absolute-path re-verify → UNTRUSTED.
   */
  assessToolResult(input: {
    claimedTool: string;
    viaRedefinedPath?: boolean;
    absolutePathVerified?: boolean;
    absolutePath?: string;
  }): ToolResultAuthenticity {
    const toolName = String(input?.claimedTool ?? '').trim().toLowerCase();
    if (!toolName) {
      return {
        verdict: 'UNTRUSTED',
        gate: 'ToolAuthenticity.DENY_bad_input',
        toolName,
        trusted: false,
        requiresAbsolutePathReverify: true,
        reason: 'claimedTool required',
      };
    }

    const flag = this.flagged.get(toolName);
    if (!flag) {
      return {
        verdict: 'OK',
        gate: 'ToolAuthenticity.OK',
        toolName,
        trusted: true,
        requiresAbsolutePathReverify: false,
      };
    }

    if (input.absolutePathVerified && input.absolutePath && input.absolutePath.startsWith('/')) {
      this.flagged.delete(toolName);
      return {
        verdict: 'OK',
        gate: 'ToolAuthenticity.REVERIFIED',
        toolName,
        trusted: true,
        requiresAbsolutePathReverify: false,
        reason: 'absolute-path re-verify cleared redefine flag',
      };
    }

    return {
      verdict: 'UNTRUSTED',
      gate: 'ToolAuthenticity.UNTRUSTED_pending_reverify',
      toolName,
      trusted: false,
      requiresAbsolutePathReverify: true,
      reason: input.viaRedefinedPath
        ? 'result via redefined path after BASH_ENV/shell-snapshot mutation'
        : 'tool previously redefined — require absolute-path re-verify',
    };
  }

  isFlagged(toolName: string): boolean {
    return this.flagged.has(String(toolName ?? '').toLowerCase());
  }

  clear(toolName?: string): void {
    if (toolName) this.flagged.delete(String(toolName).toLowerCase());
    else this.flagged.clear();
  }
}

/** Stateless one-shot assess matching pack fixture shape. */
export function assessToolAuthenticityMutation(event: {
  mutation: ToolRedefineMutation;
  subsequentToolResult?: {
    claimedTool: string;
    viaRedefinedPath?: boolean;
    absolutePathVerified?: boolean;
    absolutePath?: string;
  };
}): {
  flag: ReturnType<ToolAuthenticityTracker['observeMutation']>;
  result?: ToolResultAuthenticity;
} {
  const tracker = new ToolAuthenticityTracker();
  const flag = tracker.observeMutation(event.mutation);
  if (!event.subsequentToolResult) return { flag };
  const result = tracker.assessToolResult(event.subsequentToolResult);
  return { flag, result };
}
