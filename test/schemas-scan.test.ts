import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ScanBody, ScanOutputBody } from '../src/schemas.js';

describe('ScanBody', () => {
  it('accepts text with an optional sessionId (C4 crescendo detection)', () => {
    const parsed = ScanBody.parse({ text: 'hi', sessionId: 's1' });
    assert.equal(parsed.text, 'hi');
    assert.equal(parsed.sessionId, 's1');
  });

  it('treats sessionId as optional', () => {
    const parsed = ScanBody.parse({ text: 'hi' });
    assert.equal(parsed.sessionId, undefined);
  });

  it('rejects an empty sessionId', () => {
    assert.throws(() => ScanBody.parse({ text: 'hi', sessionId: '' }));
  });
});

describe('ScanOutputBody', () => {
  it('accepts canaryToken + jobFingerprints (C3 egress/contamination over HTTP)', () => {
    const parsed = ScanOutputBody.parse({
      text: 'x',
      jobId: 'j',
      canaryToken: 'c',
      jobFingerprints: ['f'],
    });
    assert.equal(parsed.canaryToken, 'c');
    assert.deepEqual(parsed.jobFingerprints, ['f']);
  });

  it('keeps canaryToken and jobFingerprints optional', () => {
    const parsed = ScanOutputBody.parse({ text: 'x', jobId: 'j' });
    assert.equal(parsed.canaryToken, undefined);
    assert.equal(parsed.jobFingerprints, undefined);
  });

  it('rejects more than 50 jobFingerprints', () => {
    assert.throws(() => ScanOutputBody.parse({
      text: 'x',
      jobId: 'j',
      jobFingerprints: Array.from({ length: 51 }, (_, i) => `f${i}`),
    }));
  });
});
