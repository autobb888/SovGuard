import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { scan } from '../src/scanner/index.js';
import { checkDetectionHealth } from '../src/scanner/model-health.js';

const MODELS_PRESENT = existsSync('./models/deberta-v3-prompt-injection/model.onnx');

describe('checkDetectionHealth (fail-closed on degraded)', () => {
  it('reports UNHEALTHY when the classifier is disabled (regex-only ~40% catch)', async () => {
    const h = await checkDetectionHealth((t) => scan(t, { enableClassifier: false, enableSemantic: false }));
    assert.equal(h.classifierActive, false);
    assert.equal(h.healthy, false);
    assert.ok(h.reason && /classifier/i.test(h.reason), `expected a classifier reason, got: ${h.reason}`);
  });

  it(
    'reports HEALTHY when the classifier is active and catches a known injection',
    { skip: MODELS_PRESENT ? false : 'ML models not downloaded on this host' },
    async () => {
      const h = await checkDetectionHealth((t) => scan(t, { enableClassifier: true, enableSemantic: true }));
      assert.equal(h.classifierActive, true);
      assert.equal(h.healthy, true);
      assert.equal(h.reason, undefined);
    },
  );
});
