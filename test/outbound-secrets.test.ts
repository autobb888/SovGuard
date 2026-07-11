import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSecrets } from '../src/outbound/secrets.js';
import { scanFileContent } from '../src/file/content-scanner.js';

test('flags AWS access key id', () => {
  assert.equal(scanSecrets('creds: AKIAIOSFODNN7EXAMPLE').some(x => x.type === 'secret_leak'), true);
});
test('flags private key header', () => {
  assert.equal(scanSecrets('-----BEGIN RSA PRIVATE KEY-----\nMIIE...').length >= 1, true);
});
test('flags provider token shapes (sk-, ghp_)', () => {
  assert.equal(scanSecrets('OPENAI=sk-abcdefghijklmnopqrstuvwxyz0123').length >= 1, true);
  assert.equal(scanSecrets('token ghp_abcdefghijklmnopqrstuvwxyzABCDEF0123').length >= 1, true);
});
test('does not flag ordinary prose', () => {
  assert.equal(scanSecrets('The secret to good soup is patience.').length, 0);
});

// File-content path: a secret value in an uploaded file must be flagged through
// the file-content scanner (scanSecrets is merged into its string[] flags).
test('file-content scanner flags an AWS key in a text file', () => {
  const buf = Buffer.from('config file\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\n', 'utf-8');
  const result = scanFileContent(buf, 'text/plain');
  assert.equal(result.safe, false);
  assert.equal(result.flags.some(f => f.includes('secret_leak')), true);
  assert.equal(result.action, 'block');
});
test('file-content scanner flags a private-key header in a text file', () => {
  const buf = Buffer.from('-----BEGIN RSA PRIVATE KEY-----\nMIIEabc...\n', 'utf-8');
  const result = scanFileContent(buf, 'text/plain');
  assert.equal(result.safe, false);
  assert.equal(result.flags.some(f => f.includes('secret_leak')), true);
});
