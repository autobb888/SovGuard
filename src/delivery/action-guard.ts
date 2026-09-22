/**
 * DL-004 — Provenance-gated ActionGuard (SAFE-DELIVERY).
 * Proposed tools/URLs must be ⊆ the trusted user plan. Untrusted ingress
 * (email/file/web/mcp/other_agent/…) cannot expand the plan.
 */

import { scanSecrets, scanSensitivePathMarkers } from '../outbound/secrets.js';
import {
  ApprovalBindingStore,
  approvalVectorFromToolAction,
  compareApprovalAtUse,
} from './approval-binding.js';
import {
  collectSideRecipients,
  preferenceRuleActTrust,
  type PreferenceRuleProvenance,
} from './memory-write-gate.js';
import {
  denyInconsistentArtifactCompose,
  type ArtifactProvenanceStore,
} from './artifact-provenance.js';
import {
  denyDelayedPlantBind,
  type DelayedArm,
  type DelayedTriggerWatch,
} from '../scanner/delayed-trigger.js';


export type UntrustedActionSource =
  | 'email'
  | 'web'
  | 'file'
  | 'workspace_file'
  | 'mcp_result'
  | 'api_response'
  | 'other_agent'
  | 'job_description'
  | 'api'
  | 'job';

export interface TrustedPlan {
  /** Logical actions the user authorized (e.g. summarize). */
  actions?: string[];
  /** Tool names the user authorized (e.g. send_email). */
  tools?: string[];
  /** URL prefixes/origins the user authorized. */
  urls?: string[];
  /**
   * Optional per-tool arg allowlists.
   * Flat: `"toolName.argName": string[]` or nested: `{ toolName: { argName: string[] } }`.
   */
  argAllowlist?: Record<string, string[] | Record<string, string[]>> | Record<string, unknown>;
  /** Fixture alias for argAllowlist (flat or nested). */
  allowlist?: Record<string, string[] | Record<string, string[]>> | Record<string, unknown>;
}

export type ProposedAction =
  | { type: 'tool'; name: string; args?: Record<string, unknown> }
  | { type: 'action'; name: string }
  | { type: 'fetch'; url: string };

export interface DeniedAction {
  action: ProposedAction;
  reason: string;
}

export interface ActionGuardResult {
  allowed: ProposedAction[];
  denied: DeniedAction[];
}

const UNTRUSTED_SOURCES = new Set<string>([
  'email',
  'web',
  'file',
  'workspace_file',
  'mcp_result',
  'api_response',
  'other_agent',
  'job_description',
  'api',
  'job',
]);

export function isUntrustedActionSource(source: string | undefined): boolean {
  return !!source && UNTRUSTED_SOURCES.has(source);
}

/** Resolve . / .. in a pathname without touching the host. */
export function normalizeUrlPathname(pathname: string): string {
  const parts = pathname.split('/');
  const out: string[] = [];
  for (const p of parts) {
    if (p === '' || p === '.') continue;
    if (p === '..') {
      out.pop();
      continue;
    }
    out.push(p);
  }
  return '/' + out.join('/');
}

/**
 * Safe allowlist match: parse with URL; hostname/port/protocol must match exactly
 * (no bare string startsWith on the full href for host trust). Path checks only
 * after normalizing `.` / `..` within the same origin.
 */
export function urlOnTrustedAllowlist(candidate: string, allowlist: string[]): boolean {
  let cand: URL;
  try {
    cand = new URL(candidate.trim());
  } catch {
    return false;
  }
  if (cand.protocol !== 'http:' && cand.protocol !== 'https:') return false;
  const candPath = normalizeUrlPathname(cand.pathname);

  for (const entry of allowlist) {
    const e = entry.trim();
    if (!e) continue;
    let allowed: URL;
    try {
      allowed = new URL(e.includes('://') ? e : `https://${e}`);
    } catch {
      continue;
    }
    if (allowed.protocol !== 'http:' && allowed.protocol !== 'https:') continue;
    // Exact host trust — blocks good.example.evil.test when allowlist is good.example
    if (cand.protocol !== allowed.protocol) continue;
    if (cand.hostname !== allowed.hostname) continue;
    if (cand.port !== allowed.port) continue;

    const allowedPath = normalizeUrlPathname(allowed.pathname);
    // Origin-only allowlist entry (path /) → any path on that origin
    if (allowedPath === '/') return true;
    if (candPath === allowedPath) return true;
    const prefix = allowedPath.endsWith('/') ? allowedPath : `${allowedPath}/`;
    if (candPath.startsWith(prefix)) return true;
  }
  return false;
}

/**
 * Authorize proposed tool/URL actions against the user-origin trusted plan.
 * Untrusted sources never expand the plan — they can only be checked against it.
 */
const EMAIL_ARGS = new Set(["to", "cc", "bcc", "invitees", "attendees", "sync", "synctargets", "sync_targets", "sharewith", "share_with"]);

/**
 * Flatten nested Threat Scout / host shape `{ tool: { arg: vals } }` into
 * `"tool.arg": vals`. Flat `"tool.arg": vals` entries pass through.
 */
export function flattenArgAllowlist(raw: unknown): Record<string, string[]> {
  if (!raw || typeof raw !== 'object') return {};
  const out: Record<string, string[]> = {};
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (Array.isArray(v)) {
      out[k] = v.map(String);
    } else if (v && typeof v === 'object') {
      for (const [arg, vals] of Object.entries(v as Record<string, unknown>)) {
        if (Array.isArray(vals)) out[`${k}.${arg}`] = vals.map(String);
      }
    }
  }
  return out;
}

/** Merge argAllowlist + fixture alias `allowlist` (supports nested + flat). */
export function resolveArgAllowlist(plan: TrustedPlan): Record<string, string[]> {
  return {
    ...flattenArgAllowlist(plan.allowlist),
    ...flattenArgAllowlist(plan.argAllowlist),
  };
}

function normalizeArgValue(argName: string, raw: string): string {
  const v = raw.trim();
  return EMAIL_ARGS.has(argName.toLowerCase()) ? v.toLowerCase() : v;
}

/**
 * If the plan constrains `${tool}.${arg}`, enforce exact membership.
 * Missing/empty/non-string values fail closed when a key is present.
 * Returns a deny reason or null if allowed.
 */
export function denyArgAllowlist(
  toolName: string,
  args: Record<string, unknown> | undefined,
  argAllowlist: Record<string, string[]>,
): string | null {
  const prefix = `${toolName}.`;
  const keys = Object.keys(argAllowlist).filter((k) => k.startsWith(prefix));
  if (keys.length === 0) return null;

  for (const key of keys) {
    const argName = key.slice(prefix.length);
    if (!argName || argName.includes(".")) {
      // v1: top-level arg names only
      continue;
    }
    const allowedVals = (argAllowlist[key] ?? []).map((s) => normalizeArgValue(argName, String(s)));
    const raw = args?.[argName];
    if (raw === undefined || raw === null) {
      return `arg "${argName}" required by plan allowlist`;
    }
    if (allowedVals.length === 0) {
      return `arg "${argName}" denied by empty plan allowlist`;
    }
    if (Array.isArray(raw)) {
      // RA BLOCK 09defd2: empty [] made the per-element loop a no-op (vacuous ALLOW).
      if (raw.length === 0) {
        return `arg "${argName}" empty array denied by plan allowlist`;
      }
      for (const el of raw) {
        if (typeof el !== "string") {
          return `arg "${argName}" has non-string value (fail closed)`;
        }
        const n = normalizeArgValue(argName, el);
        if (!allowedVals.includes(n)) {
          return `arg "${argName}" value not on plan allowlist: ${el}`;
        }
      }
      continue;
    }
    if (typeof raw !== "string") {
      return `arg "${argName}" has non-string value (fail closed)`;
    }
    const n = normalizeArgValue(argName, raw);
    if (!allowedVals.includes(n)) {
      return `arg "${argName}" value not on plan allowlist: ${raw}`;
    }
  }
  return null;
}


/** Sources that trigger GhostSplice arg-content gate before AG allow. */
const ARG_CONTENT_GATE_SOURCES = new Set<string>(['mcp_result', 'api_response']);

export function isArgContentGateSource(source: string | undefined): boolean {
  return !!source && ARG_CONTENT_GATE_SOURCES.has(source);
}

export interface ProposedToolArgsHit {
  kind: 'secret' | 'sensitive_path';
  label: string;
}

export interface ProposedToolArgsScanResult {
  /** True when args look like secret/path exfil — DENY or require re-approval. */
  deny: boolean;
  reason?: string;
  hits: ProposedToolArgsHit[];
}

/** Stable stringify for proposed tool args (shapes only; no live secrets required). */
export function stringifyProposedToolArgs(args: Record<string, unknown> | undefined): string {
  if (args === undefined || args === null) return '';
  try {
    return JSON.stringify(args);
  } catch {
    return String(args);
  }
}

/**
 * GhostSplice thin land (A): scan proposed tool arg *contents* via existing
 * outbound scanSecrets + sensitive-path markers (.ssh, id_rsa, .env, PEM, cloud keys).
 * No new PI lexicon. Call before AG allow when source ∈ {mcp_result, api_response}.
 */
export function scanProposedToolArgs(
  args: Record<string, unknown> | undefined,
): ProposedToolArgsScanResult {
  const text = stringifyProposedToolArgs(args);
  if (!text) return { deny: false, hits: [] };

  const hits: ProposedToolArgsHit[] = [];
  for (const f of scanSecrets(text)) {
    const label = (f.detail.match(/Possible (\S+)/)?.[1]) ?? 'secret';
    hits.push({ kind: 'secret', label });
  }
  for (const f of scanSensitivePathMarkers(text)) {
    const label = (f.detail.match(/\(([^)]+)\)/)?.[1]) ?? 'sensitive_path';
    hits.push({ kind: 'sensitive_path', label });
  }

  if (hits.length === 0) return { deny: false, hits: [] };

  const labels = [...new Set(hits.map((h) => h.label))].join(', ');
  return {
    deny: true,
    reason: `proposed tool args look like secret/path exfil (${labels}) — deny/re-approval required even if tool is on TrustedPlan`,
    hits,
  };
}

/**
 * PMPA C — side-recipient bind for acts driven by recalled PreferenceRules.
 * When preference provenance is untrusted (or host opts.sideRecipientBind),
 * invitees/cc/bcc/sync must ⊆ TrustedPlan argAllowlist. Open plan (tool allowed,
 * no allowlist key for the side-recipient arg) is insufficient → DENY.
 * Returns deny reason or null if allowed.
 */
export function denySideRecipientBind(
  toolName: string,
  args: Record<string, unknown> | undefined,
  argAllowlist: Record<string, string[]>,
  opts?: { force?: boolean; preferenceProvenance?: PreferenceRuleProvenance },
): string | null {
  const force =
    opts?.force === true ||
    (opts?.preferenceProvenance
      ? preferenceRuleActTrust(opts.preferenceProvenance).untrustedForAct
      : false);
  if (!force) return null;

  const sides = collectSideRecipients(args);
  if (sides.length === 0) return null;

  for (const { arg, values } of sides) {
    const key = `${toolName}.${arg}`;
    const allowedRaw = argAllowlist[key];
    if (allowedRaw === undefined) {
      return `side_recipient_bind: arg "${arg}" present but not on TrustedPlan argAllowlist (open plan insufficient for preference-driven side recipients)`;
    }
    if (allowedRaw.length === 0) {
      return `side_recipient_bind: arg "${arg}" denied by empty plan allowlist`;
    }
    if (values.length === 0) {
      return `side_recipient_bind: arg "${arg}" empty array denied by plan allowlist`;
    }
    const allowedVals = allowedRaw.map((s) => s.trim().toLowerCase());
    for (const el of values) {
      if (!allowedVals.includes(el.trim().toLowerCase())) {
        return `side_recipient_bind: arg "${arg}" value not on plan allowlist: ${el}`;
      }
    }
  }
  return null;
}


/**
 * EP / DL-008 C — KPI-C compose for goal destinations/recipients on EP-armed acts.
 * When a delayed plant is armed (untrusted), side recipients + primary `to`/`destination`
 * must ⊆ TrustedPlan argAllowlist. Open plan (tool allowed, no allowlist key) → DENY.
 * User/HITL SourceTrust skips (G4). Distinct from PMPA preferenceProvenance.
 */
export function denyEpGoalDestinationBind(
  toolName: string,
  args: Record<string, unknown> | undefined,
  argAllowlist: Record<string, string[]>,
  opts?: {
    plantArmed?: boolean;
    SourceTrust?: string;
    sourceTrust?: string;
    hitlConfirm?: boolean;
  },
): string | null {
  if (!opts?.plantArmed) return null;
  const trust = opts.SourceTrust ?? opts.sourceTrust;
  if (
    opts.hitlConfirm === true ||
    (trust &&
      ['user', 'user_confirmed', 'user_chat', 'trusted', 'hitl', 'explicit_confirm'].includes(
        trust.toLowerCase(),
      ))
  ) {
    return null;
  }

  const GOAL_DEST_ARGS = new Set([
    'to',
    'cc',
    'bcc',
    'invitees',
    'attendees',
    'destination',
    'recipient',
    'recipients',
    'sync',
    'syncTargets',
    'sync_targets',
    'shareWith',
    'share_with',
  ]);

  if (!args) return null;
  const present: Array<{ arg: string; values: string[] }> = [];
  for (const [k, v] of Object.entries(args)) {
    if (!GOAL_DEST_ARGS.has(k) && !GOAL_DEST_ARGS.has(k.toLowerCase())) continue;
    const values: string[] = [];
    if (typeof v === 'string') values.push(v);
    else if (Array.isArray(v)) {
      for (const el of v) {
        if (typeof el === 'string') values.push(el);
      }
    }
    present.push({ arg: k, values });
  }
  // Also pull side recipients (PMPA helper) — union
  for (const s of collectSideRecipients(args)) {
    if (!present.some((p) => p.arg === s.arg)) present.push(s);
  }
  if (present.length === 0) return null;

  for (const { arg, values } of present) {
    const key = `${toolName}.${arg}`;
    const allowedRaw = argAllowlist[key];
    if (allowedRaw === undefined) {
      return `ep_goal_destination_bind: arg "${arg}" present on EP-armed act but not on TrustedPlan argAllowlist (open plan insufficient)`;
    }
    if (allowedRaw.length === 0) {
      return `ep_goal_destination_bind: arg "${arg}" denied by empty plan allowlist`;
    }
    if (values.length === 0) {
      return `ep_goal_destination_bind: arg "${arg}" empty array denied by plan allowlist`;
    }
    const allowedVals = allowedRaw.map((s) => s.trim().toLowerCase());
    for (const el of values) {
      if (!allowedVals.includes(el.trim().toLowerCase())) {
        return `ep_goal_destination_bind: arg "${arg}" value not on plan allowlist: ${el}`;
      }
    }
  }
  return null;
}

export interface ActionGuardApprovalBindingOpts {
  store: ApprovalBindingStore;
  ticketId: string;
  /** Destination bound at approve / rechecked at use-time. */
  destination?: string;
  /** Scope bound at approve / rechecked at use-time. */
  scope?: string;
}

export function actionGuard(
  trustedPlan: TrustedPlan,
  proposedActions: ProposedAction[],
    opts?: {
    source?: string;
    /** Loopjacking ApprovalBinding: use-time digest compare + one-shot consume on allow. */
    approvalBinding?: ActionGuardApprovalBindingOpts;
    /**
     * PMPA: recalled PreferenceRule provenance. When untrusted, force side-recipient
     * bind (invitees/cc/bcc/sync ⊆ argAllowlist; open plan DENY).
     */
    preferenceProvenance?: PreferenceRuleProvenance;
    /** Force side-recipient bind even without preferenceProvenance (tests / host). */
    sideRecipientBind?: boolean;
    /**
     * CFD ArtifactProvenance: composed egress spanning inconsistent / cross-session
     * artifact tags → DENY / re-approve (open plan insufficient). Distinct from PMPA.
     */
    artifactProvenance?: {
      store: ArtifactProvenanceStore;
      composeSessionId?: string;
      /** Explicit artifact refs (host may supply; else extracted from tool args). */
      artifactRefs?: string[];
    };
    /**
     * ExplosivePrompt / DL-008 plant-provenance bind: proposed tool matching armed
     * deferred action from untrusted ingest → DENY / escalate. Closing alone
     * insufficient. Open TrustedPlan does not clear the bind.
     * User / HITL (SourceTrust=user or hitlConfirm) → ALLOW (G4).
     */
    delayedPlant?: {
      watch?: DelayedTriggerWatch;
      sessionId?: string;
      plantArms?: DelayedArm[];
      SourceTrust?: string;
      sourceTrust?: string;
      hitlConfirm?: boolean;
    };
  },
): ActionGuardResult {
  const allowedTools = new Set<string>([
    ...(trustedPlan.tools ?? []),
    ...(trustedPlan.actions ?? []),
  ]);
  const allowedUrls = [...(trustedPlan.urls ?? [])];
  const argAllowlist = resolveArgAllowlist(trustedPlan);

  // Document: untrusted content cannot expand the plan (integrator must not
  // merge tools/urls extracted from email/file into trustedPlan).
  if (opts?.source && isUntrustedActionSource(opts.source)) {
    // no-op on plan — plan is caller-supplied and must remain user-origin
  }

  const allowed: ProposedAction[] = [];
  const denied: DeniedAction[] = [];

  for (const action of proposedActions) {
    if (action.type === 'tool' || action.type === 'action') {
      const name = action.name;
      if (!allowedTools.has(name)) {
        denied.push({
          action,
          reason: `tool/action "${name}" not in trusted plan`,
        });
        continue;
      }
      const toolArgs = action.type === 'tool' ? action.args : undefined;
      const argDeny = denyArgAllowlist(name, toolArgs, argAllowlist);
      if (argDeny) {
        denied.push({ action, reason: argDeny });
        continue;
      }
      // PMPA C: side-recipient bind when preference recall is untrusted / forced
      const sideDeny = denySideRecipientBind(name, toolArgs, argAllowlist, {
        force: opts?.sideRecipientBind === true,
        preferenceProvenance: opts?.preferenceProvenance,
      });
      if (sideDeny) {
        denied.push({ action, reason: sideDeny });
        continue;
      }
      // CFD ArtifactProvenance B/C: inconsistent / cross-session compose → DENY (open plan insufficient)
      if (action.type === 'tool' && opts?.artifactProvenance?.store) {
        const cfdDeny = denyInconsistentArtifactCompose(toolArgs, {
          store: opts.artifactProvenance.store,
          composeSessionId: opts.artifactProvenance.composeSessionId,
          artifactRefs: opts.artifactProvenance.artifactRefs,
        });
        if (cfdDeny) {
          denied.push({ action, reason: cfdDeny });
          continue;
        }
      }
      // ExplosivePrompt / DL-008 B: plant-provenance bind — tool fire ↔ untrusted delayed plant
      if (action.type === 'tool' && opts?.delayedPlant) {
        const dp = opts.delayedPlant;
        const plantDeny = denyDelayedPlantBind(name, {
          watch: dp.watch,
          sessionId: dp.sessionId,
          plantArms: dp.plantArms,
          SourceTrust: dp.SourceTrust,
          sourceTrust: dp.sourceTrust,
          hitlConfirm: dp.hitlConfirm,
        });
        if (plantDeny) {
          denied.push({ action, reason: plantDeny });
          continue;
        }
        // C: KPI-C goal destination/recipient bind when plant armed
        const armed =
          (dp.plantArms && dp.plantArms.length > 0) ||
          (dp.watch && dp.sessionId ? dp.watch.hasArms(dp.sessionId) : false);
        if (armed) {
          const destDeny = denyEpGoalDestinationBind(name, toolArgs, argAllowlist, {
            plantArmed: true,
            SourceTrust: dp.SourceTrust,
            sourceTrust: dp.sourceTrust,
            hitlConfirm: dp.hitlConfirm,
          });
          if (destDeny) {
            denied.push({ action, reason: destDeny });
            continue;
          }
        }
      }
      // GhostSplice A: arg-content gate for mcp_result / api_response — even on TrustedPlan
      if (action.type === 'tool' && isArgContentGateSource(opts?.source)) {
        const contentScan = scanProposedToolArgs(toolArgs);
        if (contentScan.deny) {
          denied.push({
            action,
            reason: contentScan.reason ?? 'proposed tool args denied by arg-content gate',
          });
          continue;
        }
      }
      // Loopjacking ApprovalBinding: use-time digest vs HITL-approved ticket
      if (action.type === 'tool' && opts?.approvalBinding) {
        const ab = opts.approvalBinding;
        const useVec = approvalVectorFromToolAction(name, toolArgs, {
          destination: ab.destination,
          scope: ab.scope,
        });
        const cmp = compareApprovalAtUse(ab.store, ab.ticketId, useVec);
        if (!cmp.match) {
          denied.push({
            action,
            reason: cmp.reason ?? 'approval binding mismatch — deny / require re-approval',
          });
          continue;
        }
        // C: one-shot consume after successful release (allow path)
        if (!ab.store.consume(ab.ticketId)) {
          denied.push({
            action,
            reason: 'approval ticket already consumed — replay denied',
          });
          continue;
        }
      }
      allowed.push(action);
      continue;
    }
    if (action.type === 'fetch') {
      if (urlOnTrustedAllowlist(action.url, allowedUrls)) {
        allowed.push(action);
      } else {
        denied.push({
          action,
          reason: `url not on trusted plan allowlist: ${action.url}`,
        });
      }
    }
  }

  return { allowed, denied };
}

/** Extract http(s) URLs from markdown images, reference defs, and raw links. */
export function extractRemoteUrls(text: string): string[] {
  const urls: string[] = [];
  const patterns = [
    /!\[[^\]]*\]\(\s*(https?:\/\/[^)\s]+)\s*\)/gi,
    /\[[^\]]*\]:\s*(https?:\/\/\S+)/gi,
    /<img\b[^>]*\bsrc\s*=\s*["']?(https?:\/\/[^"'\s>]+)/gi,
    /<a\b[^>]*\bhref\s*=\s*["']?(https?:\/\/[^"'\s>]+)/gi,
    /<link\b[^>]*\bhref\s*=\s*["']?(https?:\/\/[^"'\s>]+)/gi,
    /url\(\s*['"]?(https?:\/\/[^'")\s]+)/gi,
  ];
  for (const re of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      urls.push(m[1]);
    }
  }
  const metaRe = /<meta\b[^>]*>/gi;
  let mm: RegExpExecArray | null;
  while ((mm = metaRe.exec(text)) !== null) {
    const tag = mm[0];
    if (!/http-equiv\s*=\s*["']?refresh\b/i.test(tag)) continue;
    const um = /url\s*=\s*["']?(https?:\/\/[^"'\s>;]+)/i.exec(tag);
    if (um) urls.push(um[1]);
  }
  return [...new Set(urls)];
}

/**
 * Flag model output that echoes remote image/URLs introduced only by untrusted
 * context and not present on the trusted plan URL allowlist.
 * Never throws on invalid introduced URL strings.
 */
export function flagUntrustedUrlEcho(
  output: string,
  trustedPlan: TrustedPlan,
  untrustedIntroducedUrls: string[],
): Array<{ url: string; reason: string }> {
  const echoed = extractRemoteUrls(output);
  const allow = trustedPlan.urls ?? [];
  const hits: Array<{ url: string; reason: string }> = [];

  const introducedHosts: string[] = [];
  const introducedHrefs: string[] = [];
  for (const raw of untrustedIntroducedUrls) {
    try {
      const u = new URL(raw.trim());
      introducedHosts.push(u.hostname);
      introducedHrefs.push(u.href);
    } catch {
      // skip invalid — never throw
    }
  }

  for (const url of echoed) {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      continue;
    }
    const fromUntrusted =
      introducedHosts.includes(parsed.hostname) ||
      introducedHrefs.some((h) => parsed.href.startsWith(h) || h.startsWith(parsed.origin));
    if (!fromUntrusted) continue;
    if (!urlOnTrustedAllowlist(url, allow)) {
      hits.push({
        url,
        reason: 'untrusted-introduced URL echoed without trusted-plan allowlist entry',
      });
    }
  }
  return hits;
}
