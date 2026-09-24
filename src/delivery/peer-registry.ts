/**
 * A2A NameCollision thin land A–B — origin-bound stable peer identity.
 *
 * A: Enroll peers under authenticated origin + opaque stable principal ID.
 *    Routes / tools / workflows / auth MUST resolve by stableId — never by
 *    AgentCard.name / display name.
 * B: Exact + normalization-equivalent name collisions from distinct origins
 *    → DENY second register (fail-closed). Dispatch by name is refused;
 *    enrolled origin sticks regardless of admission order.
 * NC3: Presentational rename updates displayName only — does not retarget
 *    enrolled principal / stableId / origin.
 *
 * Compose peer-envelope (data↛instruction; `from` is NOT authority).
 * Do NOT stretch resolveToolShadowing / A2M preferPinnedTool as identity fix.
 * Soft C–E (UI presentational, broker topics, authority-after-identity) =
 * document / host follow-on — helpers below are optional spell only.
 *
 * KPI = origin-bound stable ID + fail-closed duplicate names.
 * Not deepset 80%. Escalate BLOCK. No A2M reopen.
 */
import { createHash, randomUUID } from 'node:crypto';

/** AgentCard-shaped enrollment input (name is presentational metadata). */
export interface AgentCard {
  /** Human-readable display name — NOT an authority-bearing selector. */
  name: string;
  /** Authenticated transport origin (scheme+host[+port]). */
  origin: string;
  /** Host asserts transport auth for this origin. Default required true for enroll. */
  transportAuthenticated?: boolean;
}

/** Enrolled peer principal — identity is (stableId, origin). */
export interface EnrolledPeer {
  /** Opaque origin-bound principal ID (never derived from display name alone). */
  stableId: string;
  origin: string;
  /** Presentational only — mutable via updateDisplayName; never keys dispatch. */
  displayName: string;
  /** Normalized form used for collision DENY (exact + norm-equivalent). */
  normalizedName: string;
  originBound: true;
  enrolledAt: number;
}

export type PeerEnrollVerdict = 'ALLOW' | 'DENY';

export type PeerEnrollGate =
  | 'PeerEnrollment.origin_bound_stable_id'
  | 'PeerEnrollment.DENY_unauthenticated_origin'
  | 'PeerEnrollment.DENY_missing_origin'
  | 'PeerEnrollment.DENY_missing_name'
  | 'PeerEnrollment.DENY_duplicate_name_distinct_origin'
  | 'PeerEnrollment.ALLOW_same_origin_rebind';

export interface PeerEnrollResult {
  verdict: PeerEnrollVerdict;
  peer?: EnrolledPeer;
  reason?: string;
  gate?: PeerEnrollGate;
  /** When DENY due to name collision, the already-enrolled peer that sticks. */
  stuckPeer?: EnrolledPeer;
}

export type PeerResolveVerdict = 'ALLOW' | 'DENY';

export type PeerResolveGate =
  | 'PeerResolve.by_stableId'
  | 'PeerResolve.DENY_name_not_authority'
  | 'PeerResolve.DENY_missing'
  | 'PeerResolve.DENY_name_derived_broker_route';

export interface PeerResolveResult {
  verdict: PeerResolveVerdict;
  peer?: EnrolledPeer;
  reason?: string;
  gate?: PeerResolveGate;
  /** True when caller attempted name-keyed selection (must not be authority). */
  refusedNameAuthority?: boolean;
}

export interface PeerRenameResult {
  ok: boolean;
  peer?: EnrolledPeer;
  reason?: string;
  /** StableId / origin unchanged after presentational rename. */
  retarget: false;
  gate?: 'PeerRename.presentational_only' | 'PeerRename.DENY_missing' | 'PeerRename.DENY_collision';
}

/**
 * Normalize AgentCard.name for collision equivalence.
 * Lowercase; strip spaces, hyphens, underscores, dots — so
 * HelperAgent ≈ helper-agent ≈ Helper Agent ≈ helper_agent.
 */
export function normalizePeerName(name: string): string {
  return String(name ?? '')
    .normalize('NFKC')
    .toLowerCase()
    .replace(/[\s_\-.]+/g, '')
    .trim();
}

/** Normalize origin for compare (trim, lowercase host portion lightly). */
export function normalizePeerOrigin(origin: string): string {
  const s = String(origin ?? '').trim();
  if (!s) return '';
  try {
    const u = new URL(s);
    return `${u.protocol}//${u.host}`.toLowerCase();
  } catch {
    return s.toLowerCase();
  }
}

/**
 * Mint opaque origin-bound stable principal ID.
 * Never derived solely from display name (collision-safe).
 */
export function mintStablePeerId(origin: string, opaque?: string): string {
  const o = normalizePeerOrigin(origin) || 'unknown';
  const salt = opaque ?? randomUUID();
  const digest = createHash('sha256').update(`${o}\0${salt}`).digest('hex').slice(0, 16);
  return `peer:${digest}`;
}

/**
 * Soft D spell — reject broker topics derived from AgentCard.name.
 * Host follow-on; not thin-land A–B alone. Documented helper.
 */
export function isNameDerivedBrokerTopic(
  topic: string,
  displayName: string,
): boolean {
  const t = String(topic ?? '').toLowerCase();
  const n = normalizePeerName(displayName);
  if (!n || !t) return false;
  // Common name-derived shapes: agent.<Name>.inbox, agents/<Name>/...
  const raw = String(displayName ?? '').toLowerCase();
  if (t.includes(`.${raw}.`) || t.includes(`/${raw}/`) || t.endsWith(`.${raw}`)) {
    return true;
  }
  // Normalized token collapsed into topic path
  const collapsed = t.replace(/[\s_\-./]+/g, '');
  return collapsed.includes(n) && (t.includes('agent') || t.includes('peer'));
}

export interface PeerRegistryOptions {
  /**
   * Require transportAuthenticated === true on enroll (default true).
   * Unauthenticated cards → DENY.
   */
  requireAuthenticatedOrigin?: boolean;
}

/**
 * In-memory peer registry — enroll under origin-bound stable ID;
 * fail-closed on cross-origin name collisions.
 */
export class PeerRegistry {
  private readonly byId = new Map<string, EnrolledPeer>();
  private readonly byNormName = new Map<string, string>(); // normalizedName → stableId
  private readonly requireAuth: boolean;

  constructor(opts: PeerRegistryOptions = {}) {
    this.requireAuth = opts.requireAuthenticatedOrigin !== false;
  }

  /** Enroll peer — A + B. Distinct-origin name collision → DENY. */
  enroll(
    card: AgentCard,
    opts?: {
      /** Host-supplied opaque principal fragment (tests / pin). */
      stableId?: string;
      /** Host-supplied opaque salt when minting. */
      opaque?: string;
      now?: number;
    },
  ): PeerEnrollResult {
    const name = String(card?.name ?? '').trim();
    const originRaw = String(card?.origin ?? '').trim();
    if (!name) {
      return {
        verdict: 'DENY',
        reason: 'AgentCard.name required (presentational metadata)',
        gate: 'PeerEnrollment.DENY_missing_name',
      };
    }
    if (!originRaw) {
      return {
        verdict: 'DENY',
        reason: 'Authenticated origin required for enrollment',
        gate: 'PeerEnrollment.DENY_missing_origin',
      };
    }
    if (this.requireAuth && card.transportAuthenticated === false) {
      return {
        verdict: 'DENY',
        reason: 'transportAuthenticated required for origin-bound enroll',
        gate: 'PeerEnrollment.DENY_unauthenticated_origin',
      };
    }
    // Default: treat missing transportAuthenticated as host-authenticated when
    // requireAuth (host already authenticated the transport before calling enroll).
    if (this.requireAuth && card.transportAuthenticated === undefined) {
      // Allow — host enroll path implies auth. Explicit false already DENY above.
    }

    const origin = normalizePeerOrigin(originRaw) || originRaw;
    const normalizedName = normalizePeerName(name);
    const existingId = this.byNormName.get(normalizedName);

    if (existingId) {
      const existing = this.byId.get(existingId)!;
      if (existing.origin !== origin) {
        return {
          verdict: 'DENY',
          reason:
            'Duplicate AgentCard.name (exact or normalization-equivalent) from distinct origin — fail-closed',
          gate: 'PeerEnrollment.DENY_duplicate_name_distinct_origin',
          stuckPeer: existing,
        };
      }
      // Same origin re-enroll / rebind: keep stableId, refresh display name
      existing.displayName = name;
      existing.normalizedName = normalizedName;
      return {
        verdict: 'ALLOW',
        peer: existing,
        reason: 'Same-origin rebind; stableId sticks',
        gate: 'PeerEnrollment.ALLOW_same_origin_rebind',
      };
    }

    const stableId =
      opts?.stableId ?? mintStablePeerId(origin, opts?.opaque);
    const peer: EnrolledPeer = {
      stableId,
      origin,
      displayName: name,
      normalizedName,
      originBound: true,
      enrolledAt: opts?.now ?? Date.now(),
    };
    this.byId.set(stableId, peer);
    this.byNormName.set(normalizedName, stableId);
    return {
      verdict: 'ALLOW',
      peer,
      reason: 'Enrolled under origin-bound opaque stableId',
      gate: 'PeerEnrollment.origin_bound_stable_id',
    };
  }

  /** Resolve by opaque stable ID only (NC1). */
  resolveById(stableId: string): PeerResolveResult {
    const peer = this.byId.get(String(stableId ?? ''));
    if (!peer) {
      return {
        verdict: 'DENY',
        reason: 'Unknown stableId',
        gate: 'PeerResolve.DENY_missing',
      };
    }
    return {
      verdict: 'ALLOW',
      peer,
      gate: 'PeerResolve.by_stableId',
    };
  }

  /**
   * Selector resolve for routes/tools/workflows/auth.
   * stableId → ALLOW; name-only → DENY (name is not authority).
   */
  resolveSelector(selector: {
    stableId?: string;
    /** Presentational — NEVER authority for dispatch. */
    name?: string;
    /** Soft D — proposed broker topic. */
    brokerTopic?: string;
  }): PeerResolveResult {
    if (selector.stableId) {
      const byId = this.resolveById(selector.stableId);
      if (byId.verdict === 'ALLOW' && selector.brokerTopic && byId.peer) {
        if (isNameDerivedBrokerTopic(selector.brokerTopic, byId.peer.displayName)) {
          return {
            verdict: 'DENY',
            peer: byId.peer,
            reason: 'Name-derived broker topic rejected — use stable principal',
            gate: 'PeerResolve.DENY_name_derived_broker_route',
            refusedNameAuthority: true,
          };
        }
      }
      return byId;
    }

    if (selector.name != null && String(selector.name).trim()) {
      // Name must never be the authority-bearing selector for routes/tools/auth.
      // Even if a peer with that display name is enrolled, refuse name-keyed dispatch
      // so hosts cannot silently collapse colliding names onto last/first match.
      const norm = normalizePeerName(selector.name);
      const stuckId = this.byNormName.get(norm);
      const stuck = stuckId ? this.byId.get(stuckId) : undefined;
      return {
        verdict: 'DENY',
        peer: stuck,
        reason:
          'AgentCard.name / display name is not an authority-bearing selector — resolve by stableId',
        gate: 'PeerResolve.DENY_name_not_authority',
        refusedNameAuthority: true,
      };
    }

    return {
      verdict: 'DENY',
      reason: 'Selector requires stableId',
      gate: 'PeerResolve.DENY_missing',
    };
  }

  /**
   * NC3 — presentational rename. Updates displayName only.
   * Does NOT retarget stableId / origin. Collision with other origin → DENY rename.
   */
  updateDisplayName(stableId: string, newName: string): PeerRenameResult {
    const peer = this.byId.get(String(stableId ?? ''));
    if (!peer) {
      return {
        ok: false,
        reason: 'Unknown stableId',
        retarget: false,
        gate: 'PeerRename.DENY_missing',
      };
    }
    const name = String(newName ?? '').trim();
    if (!name) {
      return {
        ok: false,
        peer,
        reason: 'Empty display name',
        retarget: false,
        gate: 'PeerRename.DENY_missing',
      };
    }
    const nextNorm = normalizePeerName(name);
    const holderId = this.byNormName.get(nextNorm);
    if (holderId && holderId !== peer.stableId) {
      return {
        ok: false,
        peer,
        reason: 'Rename would collide with distinct enrolled peer — fail-closed',
        retarget: false,
        gate: 'PeerRename.DENY_collision',
      };
    }
    // Drop old norm mapping if changed
    if (peer.normalizedName !== nextNorm) {
      this.byNormName.delete(peer.normalizedName);
      this.byNormName.set(nextNorm, peer.stableId);
    }
    peer.displayName = name;
    peer.normalizedName = nextNorm;
    return {
      ok: true,
      peer,
      reason: 'Presentational rename only; stableId and origin unchanged',
      retarget: false,
      gate: 'PeerRename.presentational_only',
    };
  }

  /** Diagnostic — enrolled peers (do not use displayName as map key externally). */
  list(): EnrolledPeer[] {
    return [...this.byId.values()];
  }

  get(stableId: string): EnrolledPeer | undefined {
    return this.byId.get(stableId);
  }
}
