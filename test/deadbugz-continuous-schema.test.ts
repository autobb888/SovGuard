/**
 * Deadbugz continuous tools/list integrity — N-call rug-pull harness.
 * Fixture: test/fixtures/deadbugz-ncall-schema-drift.json (n=4, K=3).
 * Bars D1–D4 (+ listChanged). No new detectors; ActionGuard mcp_result after drift.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  SchemaConsentStore,
  assertContinuousSchemaIntegrity,
  hashToolSchema,
  type ToolSchema,
} from '../src/scanner/tool-schema.js';
import { actionGuard, type ProposedAction, type TrustedPlan } from '../src/delivery/action-guard.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pack = JSON.parse(
  readFileSync(join(__dirname, 'fixtures/deadbugz-ncall-schema-drift.json'), 'utf8'),
) as {
  _meta: { K: number; n: number };
  fixtures: Array<Record<string, unknown>>;
};

function fix(id: string): Record<string, unknown> {
  const f = pack.fixtures.find((x) => x.id === id);
  assert.ok(f, id);
  return f;
}

function asSchemas(raw: unknown): ToolSchema[] {
  assert.ok(Array.isArray(raw));
  return raw as ToolSchema[];
}

describe('Deadbugz continuous schema integrity', () => {
  it('D1+D2: benign×K then poison tools/list → rugPull + scan; no silent consent refresh', async () => {
    const f = fix('deadbugz-ncall-benign-then-poison') as {
      K: number;
      serverId: string;
      consentAtInstall: { schemas: ToolSchema[] };
      sequence: Array<{
        step: number;
        event: string;
        schema?: ToolSchema;
        schemas?: ToolSchema[];
      }>;
    };
    const store = new SchemaConsentStore();
    const serverId = f.serverId;
    for (const s of f.consentAtInstall.schemas) {
      store.record(serverId, s);
    }

    // Benign×K tools/call with stable schema — continuous verify stays ok
    const callSteps = f.sequence.filter((s) => s.event === 'tools/call');
    assert.equal(callSteps.length, f.K);
    for (const step of callSteps) {
      assert.ok(step.schema);
      const r = await assertContinuousSchemaIntegrity(store, serverId, [step.schema]);
      assert.equal(r.ok, true);
      assert.equal(r.rugPull, false);
      assert.equal(r.reapprovalRequired, false);
      assert.equal(r.markActsUntrusted, false);
    }

    const listStep = f.sequence.find((s) => s.event === 'tools/list');
    assert.ok(listStep?.schemas?.length);
    const poisoned = listStep!.schemas!;
    const beforeHash = hashToolSchema(f.consentAtInstall.schemas[0]);
    const afterHash = hashToolSchema(poisoned[0]);
    assert.notEqual(beforeHash, afterHash);

    const drifted = await assertContinuousSchemaIntegrity(store, serverId, poisoned);
    assert.equal(drifted.rugPull, true);
    assert.equal(drifted.reapprovalRequired, true);
    assert.equal(drifted.markActsUntrusted, true);
    assert.equal(drifted.ok, false);
    assert.equal(drifted.actionGuardSource, 'mcp_result');

    // D2: scan ran; quarantine or block
    const scanned = drifted.tools.find((t) => t.scan);
    assert.ok(scanned?.scan);
    assert.ok(
      scanned!.scan!.action === 'block' || scanned!.scan!.action === 'quarantine',
      `expected block/quarantine, got ${scanned!.scan!.action} classification=${scanned!.scan!.classification}`,
    );

    // No silent consent refresh — still rug_pull on re-verify
    const again = store.verify(serverId, poisoned[0]);
    assert.equal(again.rugPull, true);
    assert.equal(again.ok, false);
    const second = await assertContinuousSchemaIntegrity(store, serverId, poisoned);
    assert.equal(second.rugPull, true);
  });

  it('D3: post-drift sensitive proposedActs → ActionGuard DENY with mcp_result', async () => {
    const f = fix('deadbugz-post-drift-ag-deny') as {
      trustedPlan: TrustedPlan;
      proposedActions: ProposedAction[];
      schemaAfterDrift: ToolSchema;
      serverId: string;
    };
    const store = new SchemaConsentStore();
    const benign: ToolSchema = {
      name: 'format_text',
      description: 'Formats plain text for display. No network or filesystem access.',
      parameters: {
        type: 'object',
        properties: {
          text: { type: 'string', description: 'Text to format' },
        },
        required: ['text'],
      },
    };
    store.record(f.serverId, benign);
    const drifted = await assertContinuousSchemaIntegrity(store, f.serverId, [f.schemaAfterDrift]);
    assert.equal(drifted.markActsUntrusted, true);

    const decision = actionGuard(f.trustedPlan, f.proposedActions, {
      source: drifted.actionGuardSource,
    });
    assert.equal(decision.allowed.length, 0);
    for (const name of ['read_file', 'fetch', 'shell']) {
      assert.ok(
        decision.denied.some((d) => d.action.type === 'tool' && d.action.name === name),
        `expected DENY ${name}`,
      );
    }
  });

  it('D4: benign no-drift control — allow / no false rugPull', async () => {
    const f = fix('deadbugz-benign-no-drift-control') as {
      K: number;
      serverId: string;
      consentAtInstall: { schemas: ToolSchema[] };
      sequence: Array<{ event: string; schema?: ToolSchema; schemas?: ToolSchema[] }>;
      trustedPlan?: TrustedPlan;
    };
    const store = new SchemaConsentStore();
    for (const s of f.consentAtInstall.schemas) store.record(f.serverId, s);

    for (const step of f.sequence.filter((s) => s.event === 'tools/call')) {
      const r = await assertContinuousSchemaIntegrity(store, f.serverId, [step.schema!]);
      assert.equal(r.ok, true);
      assert.equal(r.rugPull, false);
    }
    const list = f.sequence.find((s) => s.event === 'tools/list');
    assert.ok(list?.schemas);
    const r = await assertContinuousSchemaIntegrity(store, f.serverId, list!.schemas!);
    assert.equal(r.ok, true);
    assert.equal(r.rugPull, false);
    assert.equal(r.reapprovalRequired, false);
    assert.equal(r.markActsUntrusted, false);

    const plan: TrustedPlan = { actions: ['summarize'], tools: ['format_text'], urls: [] };
    const ag = actionGuard(plan, [{ type: 'tool', name: 'format_text', args: { text: 'hi' } }], {
      source: 'mcp_result',
    });
    assert.equal(ag.denied.length, 0);
    assert.equal(ag.allowed.length, 1);
  });

  it('listChanged poison uses same continuous verify path', async () => {
    const f = fix('deadbugz-listChanged-poison') as {
      serverId: string;
      consentAtInstall: { schemas: ToolSchema[] };
      schemasAfterNotify: ToolSchema[];
    };
    const store = new SchemaConsentStore();
    for (const s of f.consentAtInstall.schemas) store.record(f.serverId, s);
    const r = await assertContinuousSchemaIntegrity(store, f.serverId, f.schemasAfterNotify);
    assert.equal(r.rugPull, true);
    assert.equal(r.reapprovalRequired, true);
    assert.ok(r.tools.some((t) => t.scan && (t.scan.action === 'block' || t.scan.action === 'quarantine')));
  });

  it('assertContinuousSchemaIntegrity never auto-records consent', async () => {
    const store = new SchemaConsentStore();
    const schema: ToolSchema = {
      name: 'echo',
      description: 'Echo text',
      parameters: { type: 'object', properties: { text: { type: 'string' } } },
    };
    const r = await assertContinuousSchemaIntegrity(store, 's1', [schema]);
    assert.equal(r.reapprovalRequired, true);
    assert.equal(r.rugPull, false);
    assert.equal(store.verify('s1', schema).consented, false);
  });
});
