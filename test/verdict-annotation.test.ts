import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { resolveMode, annotateVerdict } from '../src/verdict-annotation.js';

describe('resolveMode', () => {
  it('returns monitor only for the exact string "monitor"', () => {
    assert.equal(resolveMode('monitor'), 'monitor');
  });
  it('defaults to enforce when unset', () => {
    assert.equal(resolveMode(undefined), 'enforce');
  });
  it('defaults to enforce for any other value', () => {
    assert.equal(resolveMode('enforce'), 'enforce');
    assert.equal(resolveMode('observe'), 'enforce');
    assert.equal(resolveMode(''), 'enforce');
  });
});

describe('annotateVerdict', () => {
  it('monitor + a blocking result → wouldBlock:true, mode:monitor, verdict unchanged', () => {
    const result = { safe: false, score: 0.92 };
    const annotated = annotateVerdict(result, 'monitor');
    assert.equal(annotated.mode, 'monitor');
    assert.equal(annotated.wouldBlock, true);
    // Pure annotation: never mutates the underlying verdict.
    assert.equal(annotated.safe, false);
    assert.equal(annotated.score, 0.92);
    assert.equal(result.safe, false);
    assert.equal(result.score, 0.92);
  });

  it('enforce + benign result → wouldBlock:false', () => {
    const annotated = annotateVerdict({ safe: true, score: 0.05 }, 'enforce');
    assert.equal(annotated.mode, 'enforce');
    assert.equal(annotated.wouldBlock, false);
  });

  it('unsafe but below block threshold → wouldBlock:false', () => {
    const annotated = annotateVerdict({ safe: false, score: 0.4 }, 'enforce');
    assert.equal(annotated.wouldBlock, false);
  });

  it('respects a custom block threshold', () => {
    const annotated = annotateVerdict({ safe: false, score: 0.5 }, 'enforce', 0.4);
    assert.equal(annotated.wouldBlock, true);
  });

  it('passes degraded through, defaulting to false', () => {
    assert.equal(annotateVerdict({ safe: true, score: 0.1 }, 'enforce').degraded, false);
    assert.equal(annotateVerdict({ safe: true, score: 0.1, degraded: true }, 'enforce').degraded, true);
  });
});
