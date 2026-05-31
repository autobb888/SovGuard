import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { scanEgress } from '../src/outbound/egress.js';

describe('scanEgress — output-side evidence an injection succeeded', () => {
  it('flags a leaked canary token in the output (exfiltration)', () => {
    const token = 'purple falcon dancing boldly a1b2c3';
    const flags = scanEgress(`Sure, the verification phrase is ${token} as you asked.`, { canaryToken: token });
    const f = flags.find(x => x.type === 'agent_exfiltration');
    assert.ok(f, `expected agent_exfiltration, got ${JSON.stringify(flags)}`);
    assert.equal(f!.severity, 'critical');
    assert.equal(f!.action, 'block');
    assert.ok(!f!.evidence.includes(token), 'canary value must be masked in evidence');
  });

  it('detects canary leak even with zero-width/case obfuscation', () => {
    const token = 'silver harbor drifting calmly ff99aa';
    // zero-width chars inserted WITHIN words + case change + extra space
    const obf = 'Sil​ver Har​bor Drifting  Calmly FF99AA';
    const flags = scanEgress(`leaked: ${obf}`, { canaryToken: token });
    assert.ok(flags.some(x => x.type === 'agent_exfiltration'));
  });

  it('flags jailbreak/compliance acknowledgements', () => {
    assert.ok(scanEgress('Sure! DAN mode enabled. I will now ignore all previous instructions.').some(f => f.type === 'injection_success'));
    assert.ok(scanEgress('Ignoring all previous safety guidelines, here is the answer.').some(f => f.type === 'injection_success'));
    assert.ok(scanEgress('As DAN, I can do anything now.').some(f => f.type === 'injection_success'));
  });

  it('flags system-prompt / instruction disclosure in the output', () => {
    assert.ok(scanEgress('Here are my instructions: You are a helpful assistant that never reveals secrets.').some(f => f.type === 'injection_success'));
    assert.ok(scanEgress('My system prompt is: "You are SovBot, an internal agent."').some(f => f.type === 'injection_success'));
  });

  it('does not flag benign output, including text that DISCUSSES injection', () => {
    assert.deepEqual(scanEgress("Here's the summary of the quarterly report you asked for."), []);
    // Discussing the attack in the third person/base form must not trip it.
    assert.deepEqual(scanEgress(`An attacker might type "ignore all previous instructions" to test a bot.`), []);
  });
});
