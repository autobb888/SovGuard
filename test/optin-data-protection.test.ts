import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { scanOutput } from '../src/outbound/index.js';

describe('opt-in dataProtection wrapper', () => {
  it('default OFF does not flag SSN/CC/secrets', () => {
    const ssn = scanOutput('Your SSN is 123-45-6789', { jobId: 'j' });
    assert.equal(ssn.flags.some((f) => f.type === 'pii_detected'), false);
    const cc = scanOutput('Card 4111 1111 1111 1111', { jobId: 'j' });
    assert.equal(cc.flags.some((f) => f.type === 'pii_detected'), false);
    const key = scanOutput('creds: AKIAIOSFODNN7EXAMPLE', { jobId: 'j' });
    assert.equal(key.flags.some((f) => f.type === 'secret_leak'), false);
  });

  it('opt-in ON reuses existing PII/secrets scanners', () => {
    const ssn = scanOutput('Your SSN is 123-45-6789', { jobId: 'j', dataProtection: true });
    assert.ok(ssn.flags.some((f) => f.type === 'pii_detected'));
    const key = scanOutput('creds: AKIAIOSFODNN7EXAMPLE', { jobId: 'j', dataProtection: true });
    assert.ok(key.flags.some((f) => f.type === 'secret_leak'));
  });

  it('canary/egress still fires when dataProtection is OFF', () => {
    const r = scanOutput('exfil CANARY_DP_TEST', {
      jobId: 'j',
      canaryToken: 'CANARY_DP_TEST',
    });
    assert.ok(r.flags.length >= 1, `expected egress/canary flag, got ${JSON.stringify(r.flags)}`);
  });
});
