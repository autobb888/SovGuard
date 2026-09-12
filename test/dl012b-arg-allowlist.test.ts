/**
 * DL-012b: TrustedPlan.argAllowlist exact-match enforcement.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { actionGuard, type TrustedPlan, type ProposedAction } from '../src/delivery/action-guard.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtures = JSON.parse(
  readFileSync(join(__dirname, '../pentest/payloads/dl012b-arg-allowlist.json'), 'utf8'),
) as {
  fixtures: Array<{
    id: string;
    trustedPlan: TrustedPlan;
    proposedActions: ProposedAction[];
    expected: { allow?: string[]; deny?: boolean; denyContains?: string[] };
  }>;
};


const pmDoc = JSON.parse(
  readFileSync(join(__dirname, "../pentest/payloads/dl012-puzzlemask.json"), "utf8"),
) as {
  fixtures: Array<{
    id: string;
    trustedPlan: TrustedPlan;
    proposedActions: ProposedAction[];
  }>;
};
function pm(id: string) {
  const f = pmDoc.fixtures.find((x) => x.id === id);
  assert.ok(f, `missing pm fixture ${id}`);
  return f;
}

function run(id: string) {
  const f = fixtures.fixtures.find((x) => x.id === id);
  assert.ok(f, `missing fixture ${id}`);
  return actionGuard(f.trustedPlan, f.proposedActions);
}

describe('DL-012b argAllowlist', () => {
  it('A2 allow ops@company.test', () => {
    const r = run('dl012b-allow-ops');
    assert.equal(r.denied.length, 0);
    assert.deepEqual(r.allowed.map((a) => ('name' in a ? a.name : '')), ['send_email']);
  });

  it('A3 deny attacker@evil.test and name the arg', () => {
    const r = run('dl012b-deny-attacker');
    assert.equal(r.allowed.length, 0);
    assert.ok(r.denied.length >= 1);
    const reason = r.denied[0].reason;
    assert.match(reason, /to/);
    assert.match(reason, /attacker@evil\.test/);
  });

  it('A4 deny missing to', () => {
    const r = run('dl012b-deny-missing-to');
    assert.ok(r.denied.length >= 1);
    assert.match(r.denied[0].reason, /to/);
  });

  it('A5 no argAllowlist → any to allowed (DL-004 compat)', () => {
    const r = run('dl012b-compat-no-arglist');
    assert.equal(r.denied.length, 0);
    assert.equal(r.allowed.length, 1);
  });

  it('A6 tool not in plan → deny; arg list irrelevant', () => {
    const r = actionGuard(
      { tools: ['summarize'], argAllowlist: { 'send_email.to': ['ops@company.test'] } },
      [{ type: 'tool', name: 'send_email', args: { to: 'ops@company.test' } }],
    );
    assert.equal(r.allowed.length, 0);
    assert.match(r.denied[0].reason, /not in trusted plan/);
  });

  it('A7 bcc key enforced', () => {
    const r = run('dl012b-bcc-deny');
    assert.ok(r.denied.some((d) => /bcc/i.test(d.reason)));
  });

  it('A8 array mix deny', () => {
    const r = run('dl012b-deny-array-mix');
    assert.ok(r.denied.length >= 1);
  });

  it('A9 empty allowlist array deny any value', () => {
    const r = actionGuard(
      { tools: ['send_email'], argAllowlist: { 'send_email.to': [] } },
      [{ type: 'tool', name: 'send_email', args: { to: 'ops@company.test' } }],
    );
    assert.ok(r.denied.length >= 1);
    assert.match(r.denied[0].reason, /to/);
  });

  it('fixture alias allowlist["send_email.to"] works', () => {
    const r = actionGuard(
      { tools: ['send_email'], allowlist: { 'send_email.to': ['ops@company.test'] } },
      [{ type: 'tool', name: 'send_email', args: { to: 'OPS@company.test' } }],
    );
    assert.equal(r.denied.length, 0);
  });

  it("pm-a10 allowlist allow (Threat Scout)", () => {
    const f = pm("pm-a10-positive-allowlisted-send");
    const r = actionGuard(f.trustedPlan, f.proposedActions);
    assert.equal(r.denied.length, 0, JSON.stringify(r.denied));
    assert.ok(r.allowed.some((a) => "name" in a && a.name === "send_email"));
  });

  it("pm-a10b attacker.to deny (Threat Scout)", () => {
    const f = pm("pm-a10b-recipient-not-allowlisted");
    const r = actionGuard(f.trustedPlan, f.proposedActions);
    assert.ok(r.denied.length >= 1);
    assert.match(r.denied[0].reason, /to/);
  });

});
