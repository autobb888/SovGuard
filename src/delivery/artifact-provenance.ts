/**
 * CFD ArtifactProvenance (thin land) — tag-on-write + inconsistent-tag compose gate.
 *
 * A: ArtifactProvenance tag-on-write — at artifact write (file/log/ticket/template),
 *    stamp {sessionId, intent, role, SourceTrust}. Host wires write hooks.
 * B: Inconsistent-tag compose gate — composed reads / outbound spanning inconsistent
 *    tags or cross-session plant→compose → DENY / re-approve.
 * C: KPI-C / AG composed egress — score compose with provenance; open plan + omitted
 *    origin insufficient when tags inconsistent (wired via actionGuard).
 *
 * KPI = artifact lineage + composed egress. Not deepset 80%. Not leaf lexicon.
 * Distinct from PMPA MemoryWriteGate / PreferenceRule. Keep GhostSplice /
 * Deadbugz / Loopjacking / CPE no-worsen. Soft residual: host must wire write hooks.
 */

/** Provenance stamped on every artifact write the host tags. */
export interface ArtifactProvenanceTag {
  /** Session that wrote the artifact. */
  sessionId: string;
  /** Write intent (e.g. user_backup | plant_buffer | draft). */
  intent?: string;
  /** Role of the writer (user | untrusted_tool | …). */
  role?: string;
  /**
   * Source trust at write time. Prefer `SourceTrust` (acceptance spelling);
   * `sourceTrust` accepted as alias on ingest.
   */
  SourceTrust: string;
}

export type ArtifactComposeVerdict =
  | 'ALLOW'
  | 'DENY_REAPPROVE'
  | 'NO_TRIP';

export interface ArtifactComposeGateResult {
  verdict: ArtifactComposeVerdict;
  /** True when CFD provenance gate trips (DENY / re-approve). */
  deny: boolean;
  reason?: string;
  /** Tags resolved for referenced artifacts (order matches found refs). */
  tags: ArtifactProvenanceTag[];
  /** Artifact refs that had a tag. */
  taggedRefs: string[];
  /** Artifact refs requested but untagged (host soft residual). */
  untaggedRefs: string[];
  /** Why the gate tripped (for tests / audit). */
  gate?:
    | 'ArtifactProvenance.inconsistent_or_cross_session_compose'
    | 'ArtifactProvenance.inconsistent_tag_compose'
    | 'ArtifactProvenance.fracture_compose'
    | 'ArtifactProvenance.compose'
    | 'ArtifactProvenance.cross_session_compose';
}

/** Arg keys that commonly carry artifact path / attachment refs. */
export const ARTIFACT_REF_ARG_KEYS = [
  'attachment',
  'attachments',
  'include',
  'file',
  'files',
  'path',
  'paths',
  'artifact',
  'artifacts',
  'manifest',
  'source_file',
  'sourceFile',
] as const;

const ARTIFACT_REF_KEY_SET = new Set<string>(
  ARTIFACT_REF_ARG_KEYS.map((s) => s.toLowerCase()),
);

/**
 * Collect artifact path/ref strings from proposed tool args.
 * Also expands ticket-like `id` into common path aliases for host lookups.
 */
export function collectArtifactRefsFromArgs(
  args: Record<string, unknown> | undefined,
): string[] {
  if (!args) return [];
  const out: string[] = [];
  const push = (v: unknown) => {
    if (typeof v === 'string' && v.trim()) out.push(v.trim());
    else if (Array.isArray(v)) {
      for (const el of v) {
        if (typeof el === 'string' && el.trim()) out.push(el.trim());
      }
    }
  };
  for (const [k, v] of Object.entries(args)) {
    const lk = k.toLowerCase();
    if (ARTIFACT_REF_KEY_SET.has(lk)) {
      push(v);
      continue;
    }
    // Ticket / export id — register common path aliases for lookup.
    if (lk === 'id' && typeof v === 'string' && v.trim()) {
      const id = v.trim();
      out.push(id);
      out.push(`tickets/${id}.json`);
      out.push(`tickets/${id}`);
    }
  }
  return [...new Set(out)];
}

function normalizeTag(
  tag: ArtifactProvenanceTag & { sourceTrust?: string },
): ArtifactProvenanceTag {
  const st = tag.SourceTrust ?? tag.sourceTrust ?? 'unknown';
  return {
    sessionId: tag.sessionId,
    intent: tag.intent,
    role: tag.role,
    SourceTrust: st,
  };
}

function trustOf(t: ArtifactProvenanceTag): string {
  return (t.SourceTrust ?? '').toLowerCase();
}

/**
 * Tags are consistent when all share the same sessionId and SourceTrust.
 * Intent/role drift alone does not trip when session + trust match (honest backup).
 */
export function tagsConsistent(tags: ArtifactProvenanceTag[]): boolean {
  if (tags.length <= 1) return true;
  const s0 = tags[0].sessionId;
  const t0 = trustOf(tags[0]);
  return tags.every((t) => t.sessionId === s0 && trustOf(t) === t0);
}

/**
 * Decide whether a composed egress / read spanning artifact refs may proceed.
 * - No tagged refs → NO_TRIP (soft-allow; host may not have wired hooks) — G6
 * - Tagged refs with inconsistent session/trust → DENY_REAPPROVE — G3 / fracture
 * - Any tagged sessionId ≠ composeSessionId → DENY_REAPPROVE — G1 cross-session
 * - All tagged, consistent, same compose session → ALLOW — G4
 */
export function checkComposeProvenance(
  store: ArtifactProvenanceStore,
  opts: {
    artifactRefs: string[];
    composeSessionId?: string;
  },
): ArtifactComposeGateResult {
  const taggedRefs: string[] = [];
  const untaggedRefs: string[] = [];
  const tags: ArtifactProvenanceTag[] = [];
  const seen = new Set<string>();

  for (const ref of opts.artifactRefs) {
    const hit = store.resolve(ref);
    if (!hit) {
      if (!seen.has(ref)) {
        untaggedRefs.push(ref);
        seen.add(ref);
      }
      continue;
    }
    if (seen.has(hit.key)) continue;
    seen.add(hit.key);
    taggedRefs.push(hit.key);
    tags.push(hit.tag);
  }

  if (tags.length === 0) {
    return {
      verdict: 'NO_TRIP',
      deny: false,
      reason: 'no tagged artifacts on compose — CFD gate does not trip',
      tags: [],
      taggedRefs: [],
      untaggedRefs,
    };
  }

  // Cross-session plant → compose (G1 / G2)
  if (opts.composeSessionId) {
    const foreign = tags.filter((t) => t.sessionId !== opts.composeSessionId);
    if (foreign.length > 0) {
      const sessions = [...new Set(tags.map((t) => t.sessionId))];
      const multi = sessions.length > 1;
      return {
        verdict: 'DENY_REAPPROVE',
        deny: true,
        reason: multi
          ? `ArtifactProvenance fracture_compose: composed egress spans sessions [${sessions.join(', ')}] vs compose session ${opts.composeSessionId} — DENY / re-approve`
          : `ArtifactProvenance cross_session_compose: artifact session ${foreign[0].sessionId} ≠ compose session ${opts.composeSessionId} — DENY / re-approve`,
        tags,
        taggedRefs,
        untaggedRefs,
        gate: multi
          ? 'ArtifactProvenance.fracture_compose'
          : 'ArtifactProvenance.cross_session_compose',
      };
    }
  }

  // Inconsistent tags among composed artifacts (G3) — even same compose session omitted
  if (!tagsConsistent(tags)) {
    const sessions = [...new Set(tags.map((t) => t.sessionId))];
    const trusts = [...new Set(tags.map((t) => trustOf(t)))];
    return {
      verdict: 'DENY_REAPPROVE',
      deny: true,
      reason: `ArtifactProvenance inconsistent_tag_compose: sessions=[${sessions.join(', ')}] SourceTrust=[${trusts.join(', ')}] — DENY / re-approve (open plan insufficient)`,
      tags,
      taggedRefs,
      untaggedRefs,
      gate:
        sessions.length > 1
          ? 'ArtifactProvenance.fracture_compose'
          : 'ArtifactProvenance.inconsistent_tag_compose',
    };
  }

  return {
    verdict: 'ALLOW',
    deny: false,
    reason: 'consistent ArtifactProvenance tags — compose ALLOW',
    tags,
    taggedRefs,
    untaggedRefs,
  };
}

/**
 * In-memory ArtifactProvenance store (host may swap durable backend).
 * Soft residual: host must call tagOnWrite at file/log/ticket/template write.
 */
export class ArtifactProvenanceStore {
  private byKey = new Map<string, ArtifactProvenanceTag>();

  /** Tag an artifact at write time. Returns the normalized tag. */
  tagOnWrite(
    path: string,
    tag: ArtifactProvenanceTag & { sourceTrust?: string },
  ): ArtifactProvenanceTag {
    const key = path.trim();
    const normalized = normalizeTag({ ...tag, sessionId: tag.sessionId });
    this.byKey.set(key, normalized);
    // Alias basename for loose host lookups
    const base = key.includes('/') ? key.slice(key.lastIndexOf('/') + 1) : key;
    if (base && base !== key && !this.byKey.has(base)) {
      this.byKey.set(base, normalized);
    }
    return normalized;
  }

  get(path: string): ArtifactProvenanceTag | undefined {
    return this.resolve(path)?.tag;
  }

  /** Resolve ref to stored tag (exact key, then basename, then suffix match). */
  resolve(
    ref: string,
  ): { key: string; tag: ArtifactProvenanceTag } | undefined {
    const r = ref.trim();
    if (!r) return undefined;
    const exact = this.byKey.get(r);
    if (exact) return { key: r, tag: exact };
    const base = r.includes('/') ? r.slice(r.lastIndexOf('/') + 1) : r;
    const byBase = this.byKey.get(base);
    if (byBase) return { key: base, tag: byBase };
    for (const [k, tag] of this.byKey) {
      if (k.endsWith(`/${r}`) || k.endsWith(r) || r.endsWith(k)) {
        return { key: k, tag };
      }
    }
    return undefined;
  }

  list(): Array<{ path: string; tag: ArtifactProvenanceTag }> {
    return [...this.byKey.entries()].map(([path, tag]) => ({ path, tag }));
  }

  clear(): void {
    this.byKey.clear();
  }

  size(): number {
    return this.byKey.size;
  }
}

/**
 * Deny helper for ActionGuard (C): composed egress with inconsistent / cross-session
 * provenance → DENY even when tool is on TrustedPlan (open plan insufficient).
 * Returns deny reason or null if allowed / no trip.
 */
export function denyInconsistentArtifactCompose(
  args: Record<string, unknown> | undefined,
  opts?: {
    store?: ArtifactProvenanceStore;
    composeSessionId?: string;
    artifactRefs?: string[];
  },
): string | null {
  if (!opts?.store) return null;
  const refs = [
    ...(opts.artifactRefs ?? []),
    ...collectArtifactRefsFromArgs(args),
  ];
  if (refs.length === 0 && !opts.composeSessionId) return null;
  const result = checkComposeProvenance(opts.store, {
    artifactRefs: [...new Set(refs)],
    composeSessionId: opts.composeSessionId,
  });
  if (!result.deny) return null;
  return result.reason ?? 'ArtifactProvenance compose DENY / re-approve';
}
