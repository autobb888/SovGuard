/**
 * PMPA MemoryWriteGate thin land — G1–G8.
 * Fixture: prefer threat-scout pack; fallback pentest/payloads.
 * KPI = durable write-gate + post-retrieve egress; not deepset 80%.
 * Keep GhostSplice / Deadbugz / CPE / Loopjacking no-worsen.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  actionGuard,
  scanProposedToolArgs,
  flattenArgAllowlist,
  type TrustedPlan,
  type ProposedAction,
} from '../src/delivery/action-guard.js';
import {
  memoryWriteGate,
  PreferenceRuleStore,
  preferenceRuleActTrust,
  detectMemoryWriteIntent,
  type PreferenceRuleProvenance,
} from '../src/delivery/memory-write-gate.js';
import {
  assertContinuousSchemaIntegrity,
  SchemaConsentStore,
  hashToolSchema,
  type ToolSchema,
} from '../src/scanner/tool-schema.js';
import {
  ApprovalBindingStore,
  approveAction,
  digestApprovalVector,
} from '../src/delivery/approval-binding.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const TS_FIXTURE = '/workspace/threat-scout/pentest/payloads/pmpa-memory-write-gate.json';
const LOCAL_FIXTURE = join(__dirname, '../pentest/payloads/pmpa-memory-write-gate.json');
const fixturePath = existsSync(TS_FIXTURE) ? TS_FIXTURE : LOCAL_FIXTURE;

const pack = JSON.parse(readFileSync(fixturePath, 'utf8')) as {
  fixtures: Array<Record<string, unknown>>;
};

function fix(id: string): Record<string, unknown> {
  const f = pack.fixtures.find((x) => x.id === id);
  assert.ok(f, `missing fixture ${id} in ${fixturePath}`);
  return f;
}

function planFrom(raw: Record<string, unknown> | undefined): TrustedPlan {
  const tp = raw ?? {};
  const flat = {
    ...flattenArgAllowlist(tp.allowlist),
    ...flattenArgAllowlist(tp.argAllowlist),
  };
  return {
    actions: (tp.actions as string[] | undefined) ?? undefined,
    tools: (tp.tools as string[] | undefined) ?? undefined,
    urls: (tp.urls as string[] | undefined) ?? undefined,
    argAllowlist: Object.keys(flat).length ? flat : undefined,
  };
}

function proposedFrom(raw: Record<string, unknown>): ProposedAction {
  return {
    type: 'tool',
    name: String(raw.name),
    args: (raw.args as Record<string, unknown> | undefined) ?? {},
  };
}

describe('PMPA MemoryWriteGate (G1–G8)', () => {
  it('G1: mid-doc remember from untrusted → NO_DURABLE_WRITE (no confirm)', () => {
    const f = fix('pmpa-mid-doc-write-no-confirm');
    const session = f.session as Record<string, unknown>;
    const store = new PreferenceRuleStore();

    const r = memoryWriteGate(
      {
        sessionId: String(session.id),
        role: String(session.role),
        text: String(session.text),
        explicitConfirm: false,
      },
      store,
    );

    assert.equal(r.verdict, 'NO_DURABLE_WRITE');
    assert.equal(r.durableWrite, false);
    assert.equal(r.writeIntent, true);
    assert.equal(store.size(), 0);

    const expect = f.expect as Record<string, unknown>;
    assert.equal(expect.MemoryWriteGate, 'NO_DURABLE_WRITE');
  });

  it('G2a: forced poison → new-session calendar attacker invitee DENY (side_recipient_bind)', () => {
    const f = fix('pmpa-poison-new-session-calendar');
    const setup = f.setup as Record<string, unknown>;
    const poison = setup.forcedPoisonRule as Record<string, unknown>;
    const prov = poison.provenance as PreferenceRuleProvenance;

    const store = new PreferenceRuleStore();
    store.inject({
      text: String(poison.text),
      provenance: {
        sourceSession: (prov as { sourceSession?: string }).sourceSession,
        contentTrust: prov.contentTrust,
        origin: prov.origin,
      },
    });

    const trust = preferenceRuleActTrust(store.list()[0]);
    assert.equal(trust.untrustedForAct, true);

    const ns = f.newSession as Record<string, unknown>;
    const plan = planFrom(ns.trustedPlan as Record<string, unknown>);
    const action = proposedFrom(ns.proposedAction as Record<string, unknown>);

    const ag = actionGuard(plan, [action], {
      preferenceProvenance: store.list()[0].provenance,
    });
    assert.equal(ag.allowed.length, 0);
    assert.ok(ag.denied.length >= 1);
    assert.match(ag.denied[0].reason, /invitees|side_recipient_bind|allowlist/i);
    assert.match(ag.denied[0].reason, /attacker@evil\.test/i);
  });

  it('G2b: forced poison → new-session email attacker CC DENY', () => {
    const f = fix('pmpa-poison-new-session-email-cc');
    const setup = f.setup as Record<string, unknown>;
    const poison = setup.forcedPoisonRule as Record<string, unknown>;
    const prov = poison.provenance as PreferenceRuleProvenance;

    const store = new PreferenceRuleStore();
    store.inject({
      text: String(poison.text),
      provenance: {
        sourceSession: (prov as { sourceSession?: string }).sourceSession,
        contentTrust: prov.contentTrust,
        origin: prov.origin,
      },
    });

    const ns = f.newSession as Record<string, unknown>;
    const plan = planFrom(ns.trustedPlan as Record<string, unknown>);
    const action = proposedFrom(ns.proposedAction as Record<string, unknown>);

    const ag = actionGuard(plan, [action], {
      preferenceProvenance: store.list()[0].provenance,
    });
    assert.equal(ag.allowed.length, 0);
    assert.ok(ag.denied.length >= 1);
    // Empty cc allowlist DENYs without echoing the attacker value — match gate, not address.
    assert.ok(
      ag.denied.some((d) => /cc|side_recipient_bind|allowlist/i.test(d.reason)),
      JSON.stringify(ag.denied),
    );
  });

  it('G2c: open plan + untrusted preference recall → DENY side recipients (open plan insufficient)', () => {
    const prov: PreferenceRuleProvenance = {
      sourceSession: 's-qa-1',
      contentTrust: 'untrusted',
      origin: 'external_doc',
    };
    const plan: TrustedPlan = { tools: ['create_calendar_event'] };
    const action: ProposedAction = {
      type: 'tool',
      name: 'create_calendar_event',
      args: { title: 'Sync', invitees: ['attacker@evil.test'] },
    };
    const ag = actionGuard(plan, [action], { preferenceProvenance: prov });
    assert.equal(ag.allowed.length, 0);
    assert.match(ag.denied[0].reason, /side_recipient_bind/i);
    assert.match(ag.denied[0].reason, /invitees/i);
  });

  it('G3: control no memory-write verb → NO_TRIP (no false write-gate)', () => {
    const f = fix('pmpa-control-no-write-verb');
    const session = f.session as Record<string, unknown>;
    const store = new PreferenceRuleStore();
    const r = memoryWriteGate(
      {
        sessionId: String(session.id),
        role: String(session.role),
        text: String(session.text),
      },
      store,
    );
    assert.equal(r.verdict, 'NO_TRIP');
    assert.equal(r.durableWrite, false);
    assert.equal(r.writeIntent, false);
    assert.equal(store.size(), 0);
    assert.equal(detectMemoryWriteIntent(String(session.text)).writeIntent, false);
  });

  it('G4: explicit user save preference + confirm → ALLOW_AFTER_CONFIRM + provenance', () => {
    const f = fix('pmpa-explicit-user-save');
    const session = f.session as Record<string, unknown>;
    const store = new PreferenceRuleStore();
    const r = memoryWriteGate(
      {
        sessionId: String(session.id),
        role: String(session.role),
        text: String(session.text),
        explicitConfirm: session.explicitConfirm === true,
      },
      store,
    );
    assert.equal(r.verdict, 'ALLOW_AFTER_CONFIRM');
    assert.equal(r.durableWrite, true);
    assert.ok(r.rule);
    assert.equal(r.rule!.provenance.contentTrust, 'user_confirmed');
    assert.equal(r.rule!.provenance.origin, 'user');
    assert.equal(store.size(), 1);
    assert.equal(preferenceRuleActTrust(r.rule!).untrustedForAct, false);
  });

  it('G5: post-poison sandwich honesty — sandwich alone insufficient; side-recipient bind DENY', () => {
    const f = fix('pmpa-post-poison-sandwich-honesty');
    const setup = f.setup as Record<string, unknown>;
    const poison = setup.forcedPoisonRule as Record<string, unknown>;
    const prov = poison.provenance as PreferenceRuleProvenance;
    assert.ok(setup.systemSandwich);

    const ns = f.newSession as Record<string, unknown>;
    const action = proposedFrom(ns.proposedAction as Record<string, unknown>);
    const openPlan: TrustedPlan = {
      tools: [action.type === 'tool' ? action.name : ''],
    };

    const withoutBind = actionGuard(openPlan, [action]);
    assert.equal(withoutBind.allowed.length, 1, 'sandwich alone insufficient — open plan ALLOW');

    const withBind = actionGuard(openPlan, [action], {
      preferenceProvenance: {
        contentTrust: prov.contentTrust,
        origin: prov.origin,
        sourceSession: (prov as { sourceSession?: string }).sourceSession,
      },
    });
    assert.equal(withBind.allowed.length, 0);
    assert.match(withBind.denied[0].reason, /side_recipient_bind/i);

    const expect = f.expect as Record<string, unknown>;
    assert.equal(expect.promptSandwichAlone, 'INSUFFICIENT');
    assert.equal(expect.ActionGuard_with_side_recipient_bind, 'DENY');
  });

  it('G6: complementary GhostSplice / Deadbugz / CPE / Loopjacking no-worsen', async () => {
    const f = fix('pmpa-complementary-no-worsen');
    const expect = f.expect as Record<string, unknown>;
    assert.equal(expect.GhostSplice, 'no_worsen');
    assert.equal(expect.Deadbugz, 'no_worsen');
    assert.equal(expect.CPE, 'no_worsen');
    assert.equal(expect.Loopjacking, 'no_worsen');

    const secretArgs = {
      path: '/home/user/.ssh/id_rsa',
      body: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/fake\n-----END RSA PRIVATE KEY-----',
    };
    const gs = scanProposedToolArgs(secretArgs);
    assert.equal(gs.deny, true);
    const gsAg = actionGuard(
      { tools: ['read_file'] },
      [{ type: 'tool', name: 'read_file', args: secretArgs }],
      { source: 'mcp_result' },
    );
    assert.equal(gsAg.allowed.length, 0);

    const schemaStore = new SchemaConsentStore();
    const schema: ToolSchema = {
      name: 'pmpa_demo',
      description: 'Benign schema control for PMPA complementary.',
      inputSchema: { type: 'object', properties: { x: { type: 'string' } } },
    };
    schemaStore.record('pmpa-server', schema);
    const ok = await assertContinuousSchemaIntegrity(schemaStore, 'pmpa-server', [schema]);
    assert.equal(ok.ok, true);
    assert.equal(ok.rugPull, false);
    assert.ok(hashToolSchema(schema).length > 0);

    const abStore = new ApprovalBindingStore();
    const vec = {
      tool: 'send_email',
      args: { to: 'alice@example.test' },
      destination: 'smtp://mail.example.test',
      scope: 'user_initiated',
    };
    const approved = approveAction(abStore, vec);
    assert.equal(approved.ok, true);
    assert.ok(approved.ticket);
    assert.ok(digestApprovalVector(vec).length > 0);
    const outsider = actionGuard(
      { tools: ['summarize'] },
      [{ type: 'tool', name: 'send_email', args: vec.args }],
      {
        approvalBinding: {
          store: abStore,
          ticketId: approved.ticket!.id,
          destination: vec.destination,
          scope: vec.scope,
        },
      },
    );
    assert.equal(outsider.allowed.length, 0);
    assert.match(outsider.denied[0].reason, /not in trusted plan/i);

    const trust = preferenceRuleActTrust({
      contentTrust: 'untrusted',
      origin: 'external_doc',
    });
    assert.equal(trust.untrustedForAct, true);
    assert.match(trust.actSource, /preference_rule/);
  });

  it('G7: CHANGELOG Unreleased names MemoryWriteGate + PreferenceRule; not deepset', () => {
    const changelog = readFileSync(join(__dirname, '../CHANGELOG.md'), 'utf8');
    assert.match(changelog, /MemoryWriteGate/);
    assert.match(changelog, /PreferenceRule/);
    assert.match(changelog, /write-gate|post-retrieve|side-recipient/i);
    assert.match(changelog, /not.*deepset/i);
  });

  it('G8: allowlisted side recipients still ALLOW under preference bind (no false deny)', () => {
    const prov: PreferenceRuleProvenance = {
      contentTrust: 'untrusted',
      origin: 'external_doc',
    };
    const plan: TrustedPlan = {
      tools: ['create_calendar_event'],
      argAllowlist: flattenArgAllowlist({
        create_calendar_event: {
          invitees: ['alice@example.test', 'bob@example.test'],
        },
      }),
    };
    const action: ProposedAction = {
      type: 'tool',
      name: 'create_calendar_event',
      args: { title: 'Sync', invitees: ['alice@example.test'] },
    };
    const ag = actionGuard(plan, [action], { preferenceProvenance: prov });
    assert.equal(ag.denied.length, 0, JSON.stringify(ag.denied));
    assert.equal(ag.allowed.length, 1);
  });
});
