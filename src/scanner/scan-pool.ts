/**
 * Scan worker pool (H3). Runs the pure-JS scan layers off the main event loop.
 * Workers carry NO models (regex/indirect/perplexity are pure JS) so they are
 * cheap. Full input is always scanned — there is no truncation, length cap, or
 * timeout here. The only refusal is a bounded queue: when full, runJsLayers
 * rejects with ScanPoolSaturatedError BEFORE scanning (servers map it to 503).
 * Any worker fault falls back to an inline scan so detection is never dropped.
 */
import { Worker } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import os from 'node:os';
import type { LayerResult } from '../types.js';
import { runJsLayersSync } from './js-layers.js';

// --- worker spawn (ESM variant) ---
// VERIFIED Node 22 + tsx 4.x (Task 1): new Worker(path,{execArgv:['--import','tsx']})
// fails for a .ts ENTRY (ERR_UNKNOWN_FILE_EXTENSION). Dev/test loads the .ts worker
// via an eval bootstrap using tsImport; production spawns the compiled .js directly.
const _self = fileURLToPath(import.meta.url);
const _isTs = _self.endsWith('.ts');
const _workerTs = join(dirname(_self), 'scan-worker.ts').replace(/\\/g, '/');
const _workerJs = join(dirname(_self), 'scan-worker.js');

function spawnWorker(): Worker {
  if (_isTs) {
    const boot = `import { tsImport } from 'tsx/esm/api';\nawait tsImport('file://${_workerTs}', import.meta.url);`;
    return new Worker(boot, { eval: true });
  }
  return new Worker(_workerJs);
}

export class ScanPoolSaturatedError extends Error {
  constructor() {
    super('scan worker pool saturated');
    this.name = 'ScanPoolSaturatedError';
  }
}

interface PoolTask {
  id: number;
  input: string;
  enablePerplexity: boolean;
  resolve: (layers: LayerResult[]) => void;
}
interface WorkerHandle { worker: Worker; current: PoolTask | null; }

export interface ScanPoolConfig { size: number; threshold: number; maxQueue: number; }

export class ScanPool {
  /** Inputs longer than this go to a worker; shorter run inline (read by scan()). */
  readonly threshold: number;
  private readonly size: number;
  private readonly maxQueue: number;
  private workers: WorkerHandle[] = [];
  private idle: WorkerHandle[] = [];
  private queue: PoolTask[] = [];
  private nextId = 1;
  private started = false;
  private stopped = false;

  constructor(cfg: ScanPoolConfig) {
    this.size = cfg.size;
    this.threshold = cfg.threshold;
    this.maxQueue = cfg.maxQueue;
  }

  /** Run the JS layers on a worker if enabled, else inline. Full scan either way. */
  runJsLayers(input: string, enablePerplexity: boolean): Promise<LayerResult[]> {
    // Disabled or already shut down -> always inline (full scan; never refuse a real scan).
    if (this.size <= 0 || this.stopped) {
      return Promise.resolve(runJsLayersSync(input, enablePerplexity));
    }
    this.start();
    const handle = this.idle.pop();
    // Only refuse when there's genuinely no capacity: no idle worker AND the queue is full.
    if (!handle && this.queue.length >= this.maxQueue) {
      return Promise.reject(new ScanPoolSaturatedError());
    }
    return new Promise<LayerResult[]>((resolve) => {
      const task: PoolTask = { id: this.nextId++, input, enablePerplexity, resolve };
      if (handle) this.dispatch(handle, task);
      else this.queue.push(task);
    });
  }

  inflight(): number { return this.workers.filter((h) => h.current).length; }
  queued(): number { return this.queue.length; }
  isSaturated(): boolean { return this.queue.length >= this.maxQueue; }

  async shutdown(): Promise<void> {
    this.started = false;
    this.stopped = true;   // a late runJsLayers() after shutdown falls back to inline, not a respawn
    const ws = this.workers;
    // Resolve any queued tasks inline before discarding them — never drop detection.
    for (const t of this.queue) {
      t.resolve(runJsLayersSync(t.input, t.enablePerplexity));
    }
    this.workers = []; this.idle = []; this.queue = [];
    await Promise.all(ws.map((h) => h.worker.terminate()));
  }

  private start(): void {
    if (this.started) return;
    this.started = true;
    for (let i = 0; i < this.size; i++) this.spawn();
  }

  private spawn(): void {
    const worker = spawnWorker();
    const handle: WorkerHandle = { worker, current: null };
    worker.on('message', (resp: { id: number; layers?: LayerResult[]; error?: string }) => {
      const task = handle.current;
      if (!task || task.id !== resp.id) return;
      handle.current = null;
      if (resp.layers) {
        task.resolve(resp.layers);
      } else {
        // Worker-side error -> inline fallback (never drop detection), but surface it.
        console.error('[scan-pool] worker reported an error; scanning inline:', resp.error);
        task.resolve(runJsLayersSync(task.input, task.enablePerplexity));
      }
      this.release(handle);
    });
    worker.on('error', (err) => { console.error('[scan-pool] worker crashed; scanning inline:', err); this.faultInline(handle); });
    worker.on('exit', () => this.handleExit(handle));
    this.workers.push(handle);
    // Pick up any queued task immediately (matters when respawning after a crash).
    const next = this.queue.shift();
    if (next) this.dispatch(handle, next);
    else this.idle.push(handle);
  }

  private dispatch(handle: WorkerHandle, task: PoolTask): void {
    handle.current = task;
    handle.worker.postMessage({ id: task.id, input: task.input, enablePerplexity: task.enablePerplexity });
  }

  private release(handle: WorkerHandle): void {
    const next = this.queue.shift();
    if (next) this.dispatch(handle, next);
    else this.idle.push(handle);
  }

  /** 'error' event (uncaught worker exception): complete the in-flight task inline. */
  private faultInline(handle: WorkerHandle): void {
    const task = handle.current;
    if (!task) return;
    handle.current = null;
    task.resolve(runJsLayersSync(task.input, task.enablePerplexity));
  }

  /** Worker exited: complete any in-flight task inline, drop it, respawn to keep size. */
  private handleExit(handle: WorkerHandle): void {
    this.workers = this.workers.filter((h) => h !== handle);
    this.idle = this.idle.filter((h) => h !== handle);
    const task = handle.current;
    if (task) {
      handle.current = null;
      task.resolve(runJsLayersSync(task.input, task.enablePerplexity));
    }
    if (this.started) this.spawn();
  }
}

function envInt(name: string, def: number): number {
  const raw = process.env[name];
  if (raw === undefined) return def;
  const v = Number(raw);
  return Number.isFinite(v) && v >= 0 ? v : def;
}

const DEFAULT_SIZE = Math.min(Math.max(os.cpus().length - 1, 1), 8);
const SIZE = envInt('SOVGUARD_SCAN_WORKERS', DEFAULT_SIZE);
/** Process-wide pool, shared by scan(). size 0 disables (always-inline). */
export const scanPool = new ScanPool({
  size: SIZE,
  threshold: envInt('SOVGUARD_SCAN_WORKER_THRESHOLD', 16384),
  maxQueue: envInt('SOVGUARD_SCAN_QUEUE_MAX', SIZE * 64),
});
