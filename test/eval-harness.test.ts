import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { categorize, evaluate } from '../pentest/eval/harness.js';

const T = { blockThreshold: 0.7, suspiciousThreshold: 0.3 };

describe('categorize', () => {
  it('maps scores to blocked / flagged / safe by threshold', () => {
    assert.equal(categorize(0.9, T), 'blocked');
    assert.equal(categorize(0.7, T), 'blocked');
    assert.equal(categorize(0.5, T), 'flagged');
    assert.equal(categorize(0.3, T), 'flagged');
    assert.equal(categorize(0.1, T), 'safe');
  });
});

describe('evaluate', () => {
  const items = [
    { id: 'a1', expected: 'attack' as const, score: 0.9 },  // blocked  (caught)
    { id: 'a2', expected: 'attack' as const, score: 0.4 },  // flagged  (caught, not blocked)
    { id: 'a3', expected: 'attack' as const, score: 0.1 },  // safe     (MISSED)
    { id: 'b1', expected: 'benign' as const, score: 0.0 },  // safe     (ok)
    { id: 'b2', expected: 'benign' as const, score: 0.5 },  // flagged  (FALSE POSITIVE)
    { id: 'b3', expected: 'benign' as const, score: 0.8 },  // blocked  (FALSE POSITIVE + false block)
  ];

  it('computes attack catch/block rates and benign false-positive rates separately', () => {
    const r = evaluate(items, T);
    // attacks: 3 total, 1 blocked, 2 caught (flagged-or-blocked), 1 missed
    assert.equal(r.attacks.total, 3);
    assert.equal(r.attacks.blockRate, 1 / 3);
    assert.equal(r.attacks.catchRate, 2 / 3);
    assert.deepEqual(r.attacks.missed.map(m => m.id), ['a3']);
    // benign: 3 total, 2 flagged-or-blocked (FP), 1 blocked (false block)
    assert.equal(r.benign.total, 3);
    assert.equal(r.benign.falsePositiveRate, 2 / 3);
    assert.equal(r.benign.falseBlockRate, 1 / 3);
    assert.deepEqual(r.benign.falsePositives.map(m => m.id), ['b2', 'b3']);
  });

  it('handles empty sets without dividing by zero', () => {
    const r = evaluate([], T);
    assert.equal(r.attacks.catchRate, 0);
    assert.equal(r.benign.falsePositiveRate, 0);
  });
});
