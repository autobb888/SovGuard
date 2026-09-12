/**
 * DL-004 — Provenance-gated ActionGuard (SAFE-DELIVERY).
 * Proposed tools/URLs must be ⊆ the trusted user plan. Untrusted ingress
 * (email/file/web/mcp/other_agent/…) cannot expand the plan.
 */
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
  /** Optional per-tool arg allowlists. Key = "toolName.argName" (dot path). */
  argAllowlist?: Record<string, string[]>;
  /** Fixture alias for argAllowlist (e.g. allowlist["send_email.to"]). */
  allowlist?: Record<string, string[]>;
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
const EMAIL_ARGS = new Set(["to", "cc", "bcc"]);

/** Merge argAllowlist + fixture alias `allowlist`. */
export function resolveArgAllowlist(plan: TrustedPlan): Record<string, string[]> {
  return { ...(plan.allowlist ?? {}), ...(plan.argAllowlist ?? {}) };
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

export function actionGuard(
  trustedPlan: TrustedPlan,
  proposedActions: ProposedAction[],
  opts?: { source?: string },
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
      const argDeny = denyArgAllowlist(name, action.type === 'tool' ? action.args : undefined, argAllowlist);
      if (argDeny) {
        denied.push({ action, reason: argDeny });
      } else {
        allowed.push(action);
      }
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
  ];
  for (const re of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      urls.push(m[1]);
    }
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
