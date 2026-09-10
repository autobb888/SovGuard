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

function urlAllowed(url: string, allowlist: string[]): boolean {
  const normalized = url.trim();
  for (const entry of allowlist) {
    const e = entry.trim();
    if (!e) continue;
    if (normalized === e || normalized.startsWith(e)) return true;
    try {
      const u = new URL(normalized);
      const a = new URL(e.includes('://') ? e : `https://${e}`);
      if (u.origin === a.origin && (e.endsWith('/') ? u.href.startsWith(a.href) : u.href.startsWith(e) || u.origin === a.origin && e === a.origin)) {
        return true;
      }
      // prefix match on href
      if (u.href.startsWith(e) || u.href.startsWith(a.href)) return true;
    } catch {
      /* ignore */
    }
  }
  return false;
}

/**
 * Authorize proposed tool/URL actions against the user-origin trusted plan.
 * Untrusted sources never expand the plan — they can only be checked against it.
 */
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
      if (allowedTools.has(name)) {
        allowed.push(action);
      } else {
        denied.push({
          action,
          reason: `tool/action "${name}" not in trusted plan`,
        });
      }
      continue;
    }
    if (action.type === 'fetch') {
      if (urlAllowed(action.url, allowedUrls)) {
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
 */
export function flagUntrustedUrlEcho(
  output: string,
  trustedPlan: TrustedPlan,
  untrustedIntroducedUrls: string[],
): Array<{ url: string; reason: string }> {
  const echoed = extractRemoteUrls(output);
  const allow = trustedPlan.urls ?? [];
  const introduced = untrustedIntroducedUrls.map((u) => u.trim());
  const hits: Array<{ url: string; reason: string }> = [];
  for (const url of echoed) {
    const fromUntrusted = introduced.some((u) => url.startsWith(u) || u.startsWith(url) || url.includes(new URL(u).host));
    if (!fromUntrusted) continue;
    if (!urlAllowed(url, allow)) {
      hits.push({
        url,
        reason: 'untrusted-introduced URL echoed without trusted-plan allowlist entry',
      });
    }
  }
  return hits;
}
