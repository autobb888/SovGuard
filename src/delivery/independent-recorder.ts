/**
 * TraceIntegrity thin land A — Independent recorder helper.
 *
 * Append-only record of model request/response/stream chunks into a store
 * **conceptually outside** the agent sandbox (`outsideSandbox: true`).
 * Fail-closed if append fails (block privileged continue).
 *
 * Agent wipe of harness session paths must leave this recorder intact.
 * Explicit: in-sandbox `scan_log` / `audit_log` ≠ this recorder.
 *
 * Soft residual (NOT this land): host wire for independent gateway product.
 * Orthogonal: ControlToken CoT / Chronos order / A2A identity / A2M IFC.
 *
 * KPI = outside-sandbox append-only + fail-closed. Not deepset 80%.
 * Escalate BLOCK. Shapes only — no Trace Tampering kit/PoC.
 */

export type RecorderRecordKind =
  | 'model_request'
  | 'model_response'
  | 'stream_chunk';

export interface RecorderEntry {
  id: string;
  kind: RecorderRecordKind;
  payload: unknown;
  recordedAt: number;
  sessionId?: string;
}

export interface RecorderStoreMeta {
  /** Must be true — store is conceptually outside agent sandbox control. */
  outsideSandbox: true;
  /** Path/token marker; not writable via session-path APIs. */
  storeToken: string;
}

export type RecordVerdict = 'RECORDED' | 'FAIL_CLOSED';

export type IndependentRecorderGate =
  | 'IndependentRecorder.RECORDED'
  | 'IndependentRecorder.FAIL_CLOSED_append'
  | 'IndependentRecorder.FAIL_CLOSED_sandbox_store'
  | 'IndependentRecorder.DENY_bad_input';

export interface RecordResult {
  verdict: RecordVerdict;
  gate: IndependentRecorderGate;
  /** When FAIL_CLOSED, privileged continue must be blocked. */
  blockPrivilegedContinue: boolean;
  entryId?: string;
  reason?: string;
}

export interface IndependentRecorderOptions {
  storeToken?: string;
  /**
   * Injected append hook for tests / host wires.
   * Return false or throw → fail-closed.
   */
  appendFn?: (entry: RecorderEntry) => boolean | void;
}

/**
 * In-memory append-only store marked outsideSandbox.
 * Tests may wipe a separate "harness session path" map without touching this.
 */
export class IndependentRecorder {
  readonly meta: RecorderStoreMeta;
  private readonly entries: RecorderEntry[] = [];
  private readonly appendFn?: (entry: RecorderEntry) => boolean | void;
  private failNextAppend = false;
  private seq = 0;

  constructor(opts?: IndependentRecorderOptions) {
    this.meta = {
      outsideSandbox: true,
      storeToken: opts?.storeToken ?? 'sg-independent-recorder-outside-sandbox',
    };
    this.appendFn = opts?.appendFn;
  }

  /** Force next record() to fail (tests / host fault injection). */
  simulateAppendFailure(once = true): void {
    this.failNextAppend = once;
  }

  /**
   * Append a model I/O record. Fail-closed on append failure —
   * caller must not silently continue privileged acts without audit.
   */
  record(kind: RecorderRecordKind, payload: unknown, sessionId?: string): RecordResult {
    if (!kind || !['model_request', 'model_response', 'stream_chunk'].includes(kind)) {
      return {
        verdict: 'FAIL_CLOSED',
        gate: 'IndependentRecorder.DENY_bad_input',
        blockPrivilegedContinue: true,
        reason: 'invalid record kind',
      };
    }
    if (!this.meta.outsideSandbox) {
      return {
        verdict: 'FAIL_CLOSED',
        gate: 'IndependentRecorder.FAIL_CLOSED_sandbox_store',
        blockPrivilegedContinue: true,
        reason: 'recorder store must be outsideSandbox — scan_log/audit_log are not substitutes',
      };
    }

    const entry: RecorderEntry = {
      id: `rec-${++this.seq}`,
      kind,
      payload,
      recordedAt: Date.now(),
      sessionId,
    };

    try {
      if (this.failNextAppend) {
        this.failNextAppend = false;
        throw new Error('simulated append failure');
      }
      if (this.appendFn) {
        const ok = this.appendFn(entry);
        if (ok === false) {
          throw new Error('appendFn returned false');
        }
      }
      this.entries.push(entry);
    } catch (err) {
      return {
        verdict: 'FAIL_CLOSED',
        gate: 'IndependentRecorder.FAIL_CLOSED_append',
        blockPrivilegedContinue: true,
        reason: err instanceof Error ? err.message : 'append failed',
      };
    }

    return {
      verdict: 'RECORDED',
      gate: 'IndependentRecorder.RECORDED',
      blockPrivilegedContinue: false,
      entryId: entry.id,
    };
  }

  /** Snapshot of recorded entries (read-only copy). */
  list(): readonly RecorderEntry[] {
    return this.entries.slice();
  }

  get size(): number {
    return this.entries.length;
  }

  /** True iff store is marked outside sandbox (never agent-writable). */
  isOutsideSandbox(): boolean {
    return this.meta.outsideSandbox === true;
  }
}

/**
 * Simulate agent wipe of harness session paths without destroying recorder.
 * Returns wiped harness map; recorder list must remain intact.
 */
export function simulateHarnessSessionWipe(
  harnessPaths: Record<string, string>,
  targets: string[],
): Record<string, string> {
  const next = { ...harnessPaths };
  for (const t of targets) {
    delete next[t];
  }
  return next;
}

/**
 * Explicit honesty helper: in-sandbox scan_log/audit_log are NOT the
 * independent recorder. Hosts must not treat them as substitutes.
 */
export function isIndependentRecorderSubstitute(name: string): boolean {
  const n = String(name ?? '').toLowerCase().replace(/[-_]/g, '');
  return n === 'scanlog' || n === 'auditlog';
}
