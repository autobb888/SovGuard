import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { detectDegradation, scan } from '../src/scanner/index.js';
import type { LayerResult } from '../src/types.js';

const ok = (layer: string): LayerResult => ({ layer, score: 0, flags: [], details: { available: true } });
const down = (layer: string): LayerResult => ({ layer, score: 0, flags: [`${layer}_unavailable`], details: { available: false } });
const noDetails = (layer: string): LayerResult => ({ layer, score: 0, flags: [] });

describe('detectDegradation', () => {
  it('flags degraded when a layer that ran reports unavailable', () => {
    const d = detectDegradation([ok('regex'), down('classifier')]);
    assert.equal(d.degraded, true);
    assert.deepEqual(d.degradedLayers, ['classifier']);
  });

  it('is not degraded when all present layers are available', () => {
    const d = detectDegradation([ok('regex'), ok('classifier')]);
    assert.equal(d.degraded, false);
    assert.deepEqual(d.degradedLayers, []);
  });

  it('treats layers without a details.available field as fine (not degraded)', () => {
    const d = detectDegradation([noDetails('regex'), noDetails('perplexity')]);
    assert.equal(d.degraded, false);
  });
});

describe('scan() surfaces degraded when the classifier cannot run', () => {
  it('reports degraded:true with classifier unavailable (lakera mode, no key)', async (t) => {
    if (process.env.LAKERA_API_KEY) return t.skip('LAKERA_API_KEY set — would hit real API');
    const result = await scan('hello world', { classifierMode: 'lakera' });
    assert.equal(result.degraded, true);
    assert.ok(result.degradedLayers?.includes('classifier'));
  });

  it('is not degraded when the model layers are intentionally disabled', async () => {
    // Disable every model-dependent layer; only regex + indirect run, both of
    // which are always available, so the scan is not degraded.
    const result = await scan('hello world', { enableClassifier: false, enablePerplexity: false, enableSemantic: false });
    assert.equal(result.degraded, false);
  });
});
