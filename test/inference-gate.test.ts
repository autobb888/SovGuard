import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createInferenceGate } from '../src/scanner/inference-gate.js';

function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

const tick = () => new Promise((r) => setImmediate(r));

describe('inference-gate (M9: ONNX concurrency + timeout)', () => {
  it('caps concurrent runs and queues the excess', async () => {
    const gate = createInferenceGate({ maxConcurrent: 2, timeoutMs: 0 });
    const d1 = deferred<string>();
    const d2 = deferred<string>();
    const d3 = deferred<string>();

    const r1 = gate.run(() => d1.promise);
    const r2 = gate.run(() => d2.promise);
    const r3 = gate.run(() => d3.promise);
    await tick();

    assert.equal(gate.inflight(), 2, 'only 2 may run at once');
    assert.equal(gate.queued(), 1, 'the 3rd must wait');

    d1.resolve('a');
    await r1;
    await tick();

    assert.equal(gate.inflight(), 2, 'the queued run takes the freed slot');
    assert.equal(gate.queued(), 0);

    d2.resolve('b');
    d3.resolve('c');
    assert.deepEqual(await Promise.all([r2, r3]), ['b', 'c']);
    assert.equal(gate.inflight(), 0);
  });

  it('rejects a run that exceeds the timeout and frees the slot', async () => {
    const gate = createInferenceGate({ maxConcurrent: 1, timeoutMs: 20 });
    await assert.rejects(gate.run(() => new Promise(() => { /* never settles */ })), /timed out/);
    assert.equal(gate.inflight(), 0, 'a timed-out run must not leak its slot');

    // gate is still usable afterwards
    assert.equal(await gate.run(() => Promise.resolve('ok')), 'ok');
  });

  it('frees the slot when the run throws', async () => {
    const gate = createInferenceGate({ maxConcurrent: 1, timeoutMs: 0 });
    await assert.rejects(gate.run(() => Promise.reject(new Error('boom'))), /boom/);
    assert.equal(gate.inflight(), 0);
  });
});
