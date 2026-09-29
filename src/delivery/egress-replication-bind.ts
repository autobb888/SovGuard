/**
 * SelfReplicatingPI / EgressReplicationBind (thin land A–D).
 *
 * A: Connector provenance stamp — host/wire stamps source=connector_untrusted
 *    (or email / mcp_result / api_response / slack_equivalent) on email/Slack/
 *    tool-return ingress before ActionGuard sees proposed args.
 * B: denyUntrustedVerbatimReemit — DENY body/message/content/write args that are
 *    verbatim or high-overlap substantive echo of a prior untrusted ingress digest.
 *    Open TrustedPlan tool membership alone is insufficient.
 * C: Side-effect DENY when authorization rests on that untrusted text
 *    (destructive cleanup / strip security gate / named-recipient send).
 * D: SR1–SR5 shapes-only fixtures + EP/PB/CT pair ablations (tests / pack).
 *
 * Session-scoped append-only digest set for multi-hop (SR3). High-overlap
 * threshold mitigates FP on short citations. Compose EP/GhostSplice/KPI-C —
 * do NOT reopen Trace/IME/AL/PB/CT/Chronos/A2A/A2M/EP/PuzzleMask.
 * KPI = egress↔untrusted-ingress bind. Not deepset 80%. Escalate BLOCK.
 * Shapes only — no live worm / OpenAI report payloads.
 */

/** Connector / host provenance labels accepted by the stamp contract (A). */
export type ConnectorProvenanceSource =
  | 'connector_untrusted'
  | 'email'
  | 'mcp_result'
  | 'api_response'
  | 'slack_equivalent';

const CONNECTOR_INGRESS_SOURCES = new Set<string>([
  'connector_untrusted',
  'email',
  'mcp_result',
  'api_response',
  'slack_equivalent',
  // peers that commonly carry connector-shaped ingress
  'web',
  'file',
  'workspace_file',
  'other_agent',
  'api',
]);

const HITL_TRUSTED = new Set([
  'user',
  'user_confirmed',
  'user_chat',
  'trusted',
  'hitl',
  'explicit_confirm',
]);

/** Arg keys that carry re-emitable body / note / message content (B). */
export const REEMIT_CONTENT_ARG_KEYS = [
  'body',
  'message',
  'content',
  'text',
  'write',
  'note',
  'comment',
  'comments',
  'description',
  'caption',
  'post',
  'payload',
  'bodyShape',
  'contentShape',
  'echoDigestToken',
] as const;

const REEMIT_KEY_SET = new Set<string>(
  REEMIT_CONTENT_ARG_KEYS.map((s) => s.toLowerCase()),
);

/** Arg keys / shapes that signal authorization resting on untrusted text (C). */
export const SIDE_EFFECT_AUTH_ARG_KEYS = [
  'authRestsOn',
  'auth_rests_on',
  'justification',
  'reason',
  'because',
  'authorizedBy',
  'authorized_by',
  'sideEffectShape',
] as const;

const SIDE_EFFECT_AUTH_KEY_SET = new Set<string>(
  SIDE_EFFECT_AUTH_ARG_KEYS.map((s) => s.toLowerCase()),
);

/** Tools that commonly pair as side-effects with FS/note replication (SR2). */
export const SIDE_EFFECT_TOOL_NAMES = new Set([
  'shell',
  'bash',
  'sh',
  'run_terminal',
  'terminal',
  'rm',
  'delete_file',
  'unlink',
  'file_operations',
]);

/** Default high-overlap bar for substantive echo (FP mitigation). */
export const DEFAULT_HIGH_OVERLAP_THRESHOLD = 0.72;

/** One untrusted ingress digest recorded for a session (multi-hop append-only). */
export interface UntrustedIngressRecord {
  /** Opaque digest token (sha256 or shapes-only fixture token). */
  digestToken: string;
  /** Connector provenance source (email / mcp_result / … / connector_untrusted). */
  source: string;
  /** Prefer connector_untrusted; peers email/mcp_result/api_response/slack_equivalent OK. */
  sourceTrust: string;
  /**
   * Optional ingress text for overlap check. Shapes-only tests may set this to
   * the digestToken (or a stand-in blob containing it). Never paste live worm payloads.
   */
  text?: string;
  /** Optional hop role (ledger_read / lookup_read / steer_read). */
  role?: string;
}

export interface ConnectorProvenanceStamp {
  source: string;
  sourceTrust: string;
  untrusted: boolean;
  connectorIngress: boolean;
}

/**
 * A — Host/wire contract: stamp connector provenance on email / Slack /
 * tool-return ingress before ActionGuard sees proposed args.
 * Maps known connector sources → sourceTrust=connector_untrusted (or preserves
 * email / mcp_result / api_response / slack_equivalent when already stamped).
 */
export function stampConnectorProvenance(
  source: string | undefined,
  opts?: { forceUntrusted?: boolean; sourceTrust?: string },
): ConnectorProvenanceStamp {
  const raw = (source ?? '').trim();
  const lower = raw.toLowerCase();
  const forced = opts?.forceUntrusted === true;
  const priorTrust = (opts?.sourceTrust ?? '').trim().toLowerCase();

  if (priorTrust === 'connector_untrusted' || lower === 'connector_untrusted') {
    return {
      source: raw || 'connector_untrusted',
      sourceTrust: 'connector_untrusted',
      untrusted: true,
      connectorIngress: true,
    };
  }

  const isConnector =
    forced ||
    CONNECTOR_INGRESS_SOURCES.has(lower) ||
    priorTrust === 'slack_equivalent' ||
    lower === 'slack' ||
    lower === 'slack_equivalent';

  if (!isConnector) {
    return {
      source: raw || 'unknown',
      sourceTrust: opts?.sourceTrust ?? (raw || 'unknown'),
      untrusted: false,
      connectorIngress: false,
    };
  }

  // Preserve specific peer labels when host already stamped them; else connector_untrusted.
  const preserve =
    lower === 'email' ||
    lower === 'mcp_result' ||
    lower === 'api_response' ||
    lower === 'slack_equivalent' ||
    priorTrust === 'email' ||
    priorTrust === 'mcp_result' ||
    priorTrust === 'api_response' ||
    priorTrust === 'slack_equivalent';

  const stampedSource =
    lower === 'slack' ? 'slack_equivalent' : raw || 'connector_untrusted';
  const sourceTrust = preserve
    ? priorTrust &&
      ['email', 'mcp_result', 'api_response', 'slack_equivalent'].includes(priorTrust)
      ? priorTrust
      : lower === 'slack'
        ? 'slack_equivalent'
        : lower || 'connector_untrusted'
    : 'connector_untrusted';

  return {
    source: stampedSource,
    sourceTrust,
    untrusted: true,
    connectorIngress: true,
  };
}

export function isConnectorUntrustedSource(source: string | undefined): boolean {
  if (!source) return false;
  const s = source.toLowerCase();
  return (
    s === 'connector_untrusted' ||
    s === 'slack_equivalent' ||
    s === 'slack' ||
    CONNECTOR_INGRESS_SOURCES.has(s)
  );
}

/**
 * Session-scoped append-only digest set for multi-hop Slack / connector hops (SR3).
 * O(1) membership per send via token set; records retained for overlap text.
 */
export class UntrustedIngressDigestStore {
  private records = new Map<string, UntrustedIngressRecord[]>();
  private tokens = new Map<string, Set<string>>();

  record(sessionId: string, rec: UntrustedIngressRecord): void {
    const list = this.records.get(sessionId) ?? [];
    list.push({ ...rec });
    this.records.set(sessionId, list);
    const set = this.tokens.get(sessionId) ?? new Set<string>();
    set.add(rec.digestToken);
    this.tokens.set(sessionId, set);
  }

  /** Record many hops (ledger→lookup→steer). */
  recordMany(sessionId: string, recs: UntrustedIngressRecord[]): void {
    for (const r of recs) this.record(sessionId, r);
  }

  getRecords(sessionId: string): UntrustedIngressRecord[] {
    return [...(this.records.get(sessionId) ?? [])];
  }

  hasDigest(sessionId: string, digestToken: string): boolean {
    return this.tokens.get(sessionId)?.has(digestToken) === true;
  }

  clear(sessionId: string): void {
    this.records.delete(sessionId);
    this.tokens.delete(sessionId);
  }

  clearAll(): void {
    this.records.clear();
    this.tokens.clear();
  }
}

/** Shared singleton for hosts that do not inject their own store. */
export const untrustedIngressDigestStore = new UntrustedIngressDigestStore();

/** Collect body/message/content/write-shaped string args from proposed tool args. */
export function collectReemitContentArgs(
  args: Record<string, unknown> | undefined,
): Array<{ arg: string; value: string }> {
  if (!args) return [];
  const out: Array<{ arg: string; value: string }> = [];
  for (const [k, v] of Object.entries(args)) {
    if (!REEMIT_KEY_SET.has(k.toLowerCase())) continue;
    if (typeof v === 'string' && v.trim()) out.push({ arg: k, value: v });
    else if (Array.isArray(v)) {
      for (const el of v) {
        if (typeof el === 'string' && el.trim()) out.push({ arg: k, value: el });
      }
    }
  }
  return out;
}

function normalizeTokens(text: string): string[] {
  return text
    .toLowerCase()
    .split(/[^a-z0-9_./:@-]+/i)
    .map((t) => t.trim())
    .filter((t) => t.length >= 3);
}

/**
 * True when candidate is verbatim containment of ingress, contains digest token,
 * or high-overlap substantive echo (Jaccard on normalized tokens ≥ threshold).
 */
export function highOverlapEcho(
  candidate: string,
  ingressText: string,
  digestToken: string,
  threshold: number = DEFAULT_HIGH_OVERLAP_THRESHOLD,
): boolean {
  const c = candidate.trim();
  const ing = ingressText.trim();
  if (!c) return false;

  // Digest-token containment (shapes-only fixtures + opaque host digests).
  if (digestToken && c.includes(digestToken)) return true;

  if (!ing) return false;

  // Verbatim / near-verbatim containment either direction for substantive blobs.
  if (c.includes(ing) || ing.includes(c)) {
    // Short citation FP guard: require ingress substantive (≥24 chars) or
    // candidate covers most of ingress.
    if (ing.length >= 24 || c.length >= 24) return true;
  }

  const a = new Set(normalizeTokens(c));
  const b = new Set(normalizeTokens(ing));
  if (a.size === 0 || b.size === 0) return false;
  let inter = 0;
  for (const t of a) if (b.has(t)) inter++;
  const union = a.size + b.size - inter;
  if (union === 0) return false;
  const jaccard = inter / union;
  // Also require covering a meaningful fraction of ingress tokens (substantive echo).
  const coverB = inter / b.size;
  return jaccard >= threshold || (coverB >= threshold && inter >= 4);
}

function resolveIngressRecords(opts: {
  sessionId?: string;
  store?: UntrustedIngressDigestStore;
  ingressDigests?: UntrustedIngressRecord[];
}): UntrustedIngressRecord[] {
  const out: UntrustedIngressRecord[] = [];
  if (opts.ingressDigests?.length) out.push(...opts.ingressDigests);
  if (opts.store && opts.sessionId) {
    out.push(...opts.store.getRecords(opts.sessionId));
  }
  // Dedupe by digestToken (first wins).
  const seen = new Set<string>();
  const deduped: UntrustedIngressRecord[] = [];
  for (const r of out) {
    if (seen.has(r.digestToken)) continue;
    seen.add(r.digestToken);
    deduped.push(r);
  }
  return deduped;
}

function isHitlCleared(opts?: {
  SourceTrust?: string;
  sourceTrust?: string;
  hitlConfirm?: boolean;
}): boolean {
  if (opts?.hitlConfirm === true) return true;
  const trust = (opts?.SourceTrust ?? opts?.sourceTrust ?? '').toLowerCase();
  return HITL_TRUSTED.has(trust);
}

export interface EgressReplicationBindOpts {
  sessionId?: string;
  store?: UntrustedIngressDigestStore;
  /** Explicit digests (tests / host without session wiring). */
  ingressDigests?: UntrustedIngressRecord[];
  SourceTrust?: string;
  sourceTrust?: string;
  hitlConfirm?: boolean;
  highOverlapThreshold?: number;
  /**
   * When true, skip bind (host asserts no connector ingress this turn).
   * Default false — missing digests → no trip (nothing to bind against).
   */
  force?: boolean;
}

/**
 * B — DENY body/message/content/write args that verbatim / high-overlap echo a
 * prior untrusted ingress digest. TrustedPlan membership alone is insufficient.
 * User/HITL SourceTrust clears (same pattern as EP/shell gates).
 */
export function denyUntrustedVerbatimReemit(
  toolName: string,
  args: Record<string, unknown> | undefined,
  opts?: EgressReplicationBindOpts,
): string | null {
  if (isHitlCleared(opts)) return null;

  const records = resolveIngressRecords(opts ?? {});
  if (records.length === 0) return null;

  const contents = collectReemitContentArgs(args);
  if (contents.length === 0) return null;

  const threshold = opts?.highOverlapThreshold ?? DEFAULT_HIGH_OVERLAP_THRESHOLD;

  for (const { arg, value } of contents) {
    for (const rec of records) {
      const ingressText = rec.text ?? rec.digestToken;
      if (highOverlapEcho(value, ingressText, rec.digestToken, threshold)) {
        return (
          `denyUntrustedVerbatimReemit: tool "${toolName}" arg "${arg}" is verbatim/` +
          `high-overlap echo of untrusted ingress digest "${rec.digestToken}" ` +
          `(source=${rec.source}/sourceTrust=${rec.sourceTrust}) — TrustedPlan membership alone insufficient`
        );
      }
    }
  }
  return null;
}

/**
 * C — Side-effect DENY when authorization rests on untrusted ingress text.
 * Trips when: (1) authRestsOn / justification args reference an ingress digest, or
 * (2) shell-class side-effect tool paired with a re-emit deny in the same batch
 *     (host passes pairedReemitDenied), or
 * (3) sideEffectShape marks destructive_cleanup / strip_security_gate and digests present.
 */
export function denySideEffectAuthOnUntrusted(
  toolName: string,
  args: Record<string, unknown> | undefined,
  opts?: EgressReplicationBindOpts & { pairedReemitDenied?: boolean },
): string | null {
  if (isHitlCleared(opts)) return null;

  const records = resolveIngressRecords(opts ?? {});
  if (records.length === 0 && !opts?.pairedReemitDenied) return null;

  const tokenSet = new Set(records.map((r) => r.digestToken));
  const threshold = opts?.highOverlapThreshold ?? DEFAULT_HIGH_OVERLAP_THRESHOLD;

  if (args) {
    for (const [k, v] of Object.entries(args)) {
      const lk = k.toLowerCase();
      if (!SIDE_EFFECT_AUTH_KEY_SET.has(lk)) continue;

      if (typeof v === 'string') {
        const val = v.trim();
        if (tokenSet.has(val) || [...tokenSet].some((t) => val.includes(t))) {
          return (
            `denySideEffectAuthOnUntrusted: tool "${toolName}" arg "${k}" rests auth on ` +
            `untrusted ingress digest — DENY side-effect alongside re-emit bind`
          );
        }
        for (const rec of records) {
          const ingressText = rec.text ?? rec.digestToken;
          if (highOverlapEcho(val, ingressText, rec.digestToken, threshold)) {
            return (
              `denySideEffectAuthOnUntrusted: tool "${toolName}" arg "${k}" high-overlap with ` +
              `untrusted ingress "${rec.digestToken}" — DENY side-effect`
            );
          }
        }
        // Shape marker without needing exact digest token
        if (
          /destructive_cleanup|strip_security_gate|strip_security|rm-class/i.test(val) &&
          records.length > 0
        ) {
          return (
            `denySideEffectAuthOnUntrusted: tool "${toolName}" sideEffectShape indicates ` +
            `destructive/strip-security paired with untrusted ingress — DENY`
          );
        }
      }
    }
  }

  // Paired batch: write-echo already denied → shell-class side-effect also DENY
  if (opts?.pairedReemitDenied && SIDE_EFFECT_TOOL_NAMES.has(toolName.toLowerCase())) {
    return (
      `denySideEffectAuthOnUntrusted: tool "${toolName}" paired with untrusted verbatim ` +
      `re-emit deny — side-effect DENY when auth rests on that text`
    );
  }

  return null;
}

/**
 * Convenience: run B then C for a single proposed tool. Returns deny reason or null.
 * When B trips on a write/content tool, callers may pass pairedReemitDenied to C for shells.
 */
export function denyEgressReplicationBind(
  toolName: string,
  args: Record<string, unknown> | undefined,
  opts?: EgressReplicationBindOpts & { pairedReemitDenied?: boolean },
): string | null {
  const reemit = denyUntrustedVerbatimReemit(toolName, args, opts);
  if (reemit) return reemit;
  return denySideEffectAuthOnUntrusted(toolName, args, opts);
}
