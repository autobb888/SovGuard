/**
 * Inference gate (M9) — bounds concurrent ONNX inference and per-run wall-clock.
 *
 * Two models now run per scan (DeBERTa classifier + multilingual MiniLM
 * semantic). Without a cap, a burst of concurrent scans spawns unbounded
 * native inference runs, thrashing CPU and memory (each run allocates tensors
 * and spins ORT threads). The gate limits how many run at once — excess runs
 * queue FIFO — and rejects any run that exceeds the timeout so the caller can
 * degrade (the classifier/semantic layers already fail open to score 0).
 *
 * Note: a timed-out run's underlying native op cannot be cancelled; the timeout
 * frees the JS-side slot so the scan can proceed degraded. Inputs are
 * token-truncated upstream, so the timeout is a safety valve, not the norm.
 */

export interface InferenceGate {
  /** Run fn under the concurrency cap + timeout. Rejects on timeout. */
  run<T>(fn: () => Promise<T>, opts?: { timeoutMs?: number }): Promise<T>;
  /** Number of runs currently executing (tests / observability). */
  inflight(): number;
  /** Number of runs waiting for a slot. */
  queued(): number;
}

export function createInferenceGate(config: { maxConcurrent: number; timeoutMs: number }): InferenceGate {
  const maxConcurrent = Math.max(1, config.maxConcurrent);
  const defaultTimeout = config.timeoutMs;

  let active = 0;
  const waiters: Array<() => void> = [];

  function acquire(): Promise<void> {
    if (active < maxConcurrent) {
      active++;
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => waiters.push(resolve));
  }

  function release(): void {
    const next = waiters.shift();
    if (next) next();   // hand the slot directly to the next waiter; active unchanged
    else active--;
  }

  async function run<T>(fn: () => Promise<T>, opts?: { timeoutMs?: number }): Promise<T> {
    await acquire();
    try {
      return await withTimeout(fn(), opts?.timeoutMs ?? defaultTimeout);
    } finally {
      release();
    }
  }

  return { run, inflight: () => active, queued: () => waiters.length };
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  if (!ms || ms <= 0) return p;
  return new Promise<T>((resolve, reject) => {
    // Short-lived: cleared the moment fn settles, or fires after at most `ms`.
    const timer = setTimeout(() => reject(new Error(`inference timed out after ${ms}ms`)), ms);
    p.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}

const DEFAULT_MAX = Number(process.env.SOVGUARD_INFERENCE_CONCURRENCY) || 4;
const DEFAULT_TIMEOUT = Number(process.env.SOVGUARD_INFERENCE_TIMEOUT_MS) || 10_000;

/** Process-wide default gate, shared by the classifier + semantic layers. */
export const inferenceGate = createInferenceGate({ maxConcurrent: DEFAULT_MAX, timeoutMs: DEFAULT_TIMEOUT });
