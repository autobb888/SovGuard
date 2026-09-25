/**
 * J41 opt-in data-protection — named product policy profiles.
 *
 * Productization only: maps buyer/host language (`flag` | `redact` | `block`)
 * onto existing `OutputFlag.action` vocabulary. Does **not** change detectors
 * or flip the global `dataProtection` default (remains OFF).
 *
 * When DP is ON and no profile override is supplied, hosts should keep today's
 * per-flag actions (SSN/CC/wallets → block, email/phone → warn, many API keys
 * → redact/block by severity). That default is **not** a single profile remap.
 *
 * Not a DLP product. Postal/mailing address pack remains HOLD. Not deepset 80%.
 * Escalate BLOCK.
 */

import type { OutputFlag } from '../types.js';

/** Named J41 product profiles (docs / types / host interpretation). */
export type J41PolicyProfile = 'flag' | 'redact' | 'block';

export const J41_POLICY_PROFILES = ['flag', 'redact', 'block'] as const satisfies readonly J41PolicyProfile[];

/**
 * Sentinel: engine/host default when `dataProtection` is ON with no profile
 * override — use each flag's existing `OutputFlag.action` (no remap).
 */
export const J41_POLICY_DEFAULT_PER_FLAG = 'per_flag_actions' as const;

export type J41PolicyDefault = typeof J41_POLICY_DEFAULT_PER_FLAG;

/**
 * Map a named product profile to the `OutputFlag.action` values it covers.
 * Hosts use this for UI/docs; the engine does not auto-apply a profile inside
 * `scanOutput`.
 */
export function j41ProfileToActions(
  profile: J41PolicyProfile,
): ReadonlyArray<OutputFlag['action']> {
  switch (profile) {
    case 'flag':
      // Deliver + surface to operator/UI (audit / soft-launch).
      return ['flag', 'warn'];
    case 'redact':
      // Replace evidence spans via optional `redactOutput` (host-callable).
      return ['redact'];
    case 'block':
      // Hold message; HITL / re-gen; compose ApprovalBinding if release is an act.
      return ['block'];
  }
}

/** True when profile is one of the three named J41 product profiles. */
export function isJ41PolicyProfile(value: unknown): value is J41PolicyProfile {
  return value === 'flag' || value === 'redact' || value === 'block';
}
