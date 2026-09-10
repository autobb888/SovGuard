/**
 * Shared /v1/wrap orchestration: optional scanContext, SessionScorer, auto-canary.
 */
import type { SovGuardEngine } from './index.js';
import type { AttackCategory, CanaryToken, Classification, ScanResult, WrappedMessage } from './types.js';
import type { SessionEscalation, SessionScorer } from './scanner/session-scorer.js';
import type { SourceTrust, TaintAction, TaintNotification, TaintPolicy } from './scanner/context.js';

export interface WrapRouteBody {
  text: string;
  role?: string;
  jobId?: string;
  sessionId?: string;
  source?: SourceTrust;
  policy?: TaintPolicy;
}

export interface WrapRouteResult {
  scan: ScanResult;
  wrapped?: WrappedMessage;
  action?: TaintAction;
  notify?: TaintNotification;
  session?: {
    escalated: boolean;
    rollingSum: number;
    windowSize: number;
  };
  canary?: CanaryToken;
  error?: string;
  statusCode?: number;
}

/** Force classification to at least suspicious when the session has escalated. */
export function bumpClassification(scan: ScanResult): ScanResult {
  if (scan.classification === 'likely_injection') {
    return {
      ...scan,
      flags: scan.flags.includes('session_escalated')
        ? scan.flags
        : [...scan.flags, 'session_escalated'],
    };
  }
  return {
    ...scan,
    safe: false,
    classification: 'suspicious' satisfies Classification,
    score: Math.max(scan.score, 0.3),
    flags: scan.flags.includes('session_escalated')
      ? scan.flags
      : [...scan.flags, 'session_escalated'],
  };
}

function primaryCategory(scan: ScanResult): AttackCategory | undefined {
  for (const flag of scan.flags) {
    const cat = flag.split(':')[0];
    if (cat) return cat as AttackCategory;
  }
  return undefined;
}

export async function handleWrapRoute(
  engine: SovGuardEngine,
  sessionScorer: SessionScorer,
  body: WrapRouteBody,
): Promise<WrapRouteResult> {
  let textForWrap = body.text;
  let scan: ScanResult;
  let action: TaintAction | undefined;
  let notify: TaintNotification | undefined;

  if (body.source) {
    const ctx = await engine.scanContext(body.text, {
      source: body.source,
      policy: body.policy,
    });
    scan = ctx.scan;
    action = ctx.action;
    notify = ctx.notify;
    if (ctx.action === 'block') {
      return {
        scan,
        action,
        notify,
        error: 'blocked by scanContext policy',
        statusCode: 422,
      };
    }
    // strip → wrap sanitized plaintext; quarantine/allow → wrap original (Spotlight once)
    textForWrap = ctx.action === 'strip' ? ctx.text : body.text;
  } else {
    scan = await engine.scan(body.text);
  }

  let session: WrapRouteResult['session'];
  let canary: CanaryToken | undefined;

  if (body.sessionId) {
    const esc: SessionEscalation = sessionScorer.record(
      body.sessionId,
      scan.score,
      primaryCategory(scan),
    );
    session = {
      escalated: esc.escalated,
      rollingSum: esc.rollingSum,
      windowSize: esc.windowSize,
    };
    if (esc.escalated) {
      scan = bumpClassification(scan);
    }
    canary = engine.createCanary(body.sessionId);
  }

  const wrapped = engine.wrap(textForWrap, scan, {
    role: body.role ?? (body.source && body.source !== 'user' ? `untrusted:${body.source}` : undefined),
    jobId: body.jobId,
    sessionId: body.sessionId,
    canaryToken: canary?.token,
  });

  return { scan, wrapped, action, notify, session, canary };
}
