/**
 * Scan worker (H3) — runs the pure-JS scan layers off the main event loop.
 * No models, no DB: only regex/indirect/perplexity, which are pure functions.
 */
import { parentPort } from 'node:worker_threads';
import { runJsLayersSync } from './js-layers.js';

interface WorkerRequest { id: number; input: string; enablePerplexity: boolean; }

if (!parentPort) {
  throw new Error('scan-worker.ts must be run as a worker thread');
}

parentPort.on('message', (req: WorkerRequest) => {
  try {
    const layers = runJsLayersSync(req.input, req.enablePerplexity);
    parentPort!.postMessage({ id: req.id, layers });
  } catch (err) {
    parentPort!.postMessage({ id: req.id, error: err instanceof Error ? err.message : 'worker scan failed' });
  }
});
