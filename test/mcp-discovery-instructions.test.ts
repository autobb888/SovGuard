/**
 * MCP DiscoveryInstructions thin land — M1–M8 (PASS pack n=7).
 * Fixture: prefer threat-scout pack; fallback pentest/payloads.
 * KPI = isolate+label+cap + digest pin + refuse/bind public cache + empty ALLOW.
 * Not deepset 80%. Compose Deadbugz + GhostSplice + KPI-C; do not subsume tools/list-only.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DiscoveryInstructionsConsentStore,
  assertDiscoveryInstructionsIntegrity,
  isolateDiscoveryInstructions,
  mayFoldIntoTrustedRegion,
  hashDiscoveryInstructions,
  evaluateDiscoveryCacheScope,
  bindDiscoveryCacheKey,
  isEmptyDiscoveryInstructions,
  DEFAULT_INSTRUCTIONS_MAX_LENGTH,
  DISCOVERY_INSTRUCTIONS_LABEL,
} from '../src/scanner/mcp-discovery-instructions.js';
import {
  SchemaConsentStore,
  assertContinuousSchemaIntegrity,
  TOOL_SCHEMA_INTEGRITY_KEYS,
  hashToolSchema,
  type ToolSchema,
} from '../src/scanner/tool-schema.js';
import {
  actionGuard,
  scanProposedToolArgs,
  type TrustedPlan,
  type ProposedAction,
} from '../src/delivery/action-guard.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TS_FIXTURE = '/workspace/threat-scout/pentest/payloads/mcp-discovery-instructions.json';
const LOCAL_FIXTURE = join(__dirname, '../pentest/payloads/mcp-discovery-instructions.json');
const fixturePath = existsSync(TS_FIXTURE) ? TS_FIXTURE : LOCAL_FIXTURE;

const pack = JSON.parse(readFileSync(fixturePath, 'utf8')) as {
  _meta: { n: number; bars?: string[]; gates?: string[] };
  fixtures: Array<Record<string, unknown>>;
};

function fix(id: string): Record<string, unknown> {
  const f = pack.fixtures.find((x) => x.id === id);
  assert.ok(f, `missing fixture ${id} in ${fixturePath}`);
  return f;
}

function barOf(f: Record<string, unknown>): string {
  return String(f.bar ?? f.gate ?? '');
}

describe('MCP DiscoveryInstructions thin land (M1–M8, n=7)', () => {
  it('M7: fixture pack shapes n=7 + empty control + bars M1–M6', () => {
    assert.equal(pack._meta.n, 7);
    assert.equal(pack.fixtures.length, 7);
    const bars = new Set(pack.fixtures.map(barOf));
    for (const g of ['M1', 'M2', 'M3', 'M4', 'M5', 'M6']) {
      assert.ok(bars.has(g), `missing bar ${g}`);
    }
    const empty = fix('mcp-disc-m4-empty-instructions-ALLOW');
    const ev = empty.event as { instructions?: string };
    assert.equal(isEmptyDiscoveryInstructions(ev.instructions), true);
  });

  it('M1: hostile discovery instructions never enter trusted/system', () => {
    const f = fix('mcp-disc-m1-hostile-instructions-isolate');
    assert.equal(barOf(f), 'M1');
    const ev = f.event as { serverId: string; instructions: string };
    assert.ok(ev.instructions.length > 0);

    const isolated = isolateDiscoveryInstructions(ev.instructions);
    assert.equal(isolated.trust, 'untrusted');
    assert.equal(isolated.label, DISCOVERY_INSTRUCTIONS_LABEL);
    assert.equal(isolated.trustedRegionEligible, false);
    assert.equal(mayFoldIntoTrustedRegion(isolated), false);
    assert.equal(isolated.empty, false);
    assert.equal(isolated.digest.length, 64);

    const store = new DiscoveryInstructionsConsentStore();
    const r = assertDiscoveryInstructionsIntegrity(store, ev.serverId, ev.instructions);
    assert.equal(r.isolated.trustedRegionEligible, false);
    assert.equal(r.reapprovalRequired, true);
    assert.equal(r.ok, false);
    assert.equal(r.drift, false);
  });

  it('M1: buried long instructions → length cap + untrusted (no trusted fold)', () => {
    const f = fix('mcp-disc-m1-buried-long-instructions-cap');
    assert.equal(barOf(f), 'M1');
    const ev = f.event as { serverId: string; instructions: string };
    assert.ok(ev.instructions.length > 500);

    // Demonstrate cap against this shape (opts.maxLength); default cap also exported.
    const capped = isolateDiscoveryInstructions(ev.instructions, { maxLength: 1024 });
    assert.equal(capped.truncated, true);
    assert.equal(capped.text.length, 1024);
    assert.equal(capped.trustedRegionEligible, false);
    assert.equal(mayFoldIntoTrustedRegion(capped), false);
    assert.equal(capped.trust, 'untrusted');
    assert.ok(capped.originalLength > 1024);

    const atDefault = isolateDiscoveryInstructions(ev.instructions);
    assert.equal(atDefault.trustedRegionEligible, false);
    assert.ok(atDefault.text.length <= DEFAULT_INSTRUCTIONS_MAX_LENGTH);
  });

  it('M2: benign approved → instructions digest drift → reject fail-closed', () => {
    const f = fix('mcp-disc-m2-instructions-digest-drift-reject') as {
      bar: string;
      sequence: Array<{
        step: number;
        serverId: string;
        instructions: string;
        consent?: string;
      }>;
    };
    assert.equal(f.bar, 'M2');
    const store = new DiscoveryInstructionsConsentStore();
    const step1 = f.sequence[0];
    const step2 = f.sequence[1];
    assert.equal(step1.consent, 'approve_pin');

    const pin = store.record(step1.serverId, step1.instructions);
    assert.equal(pin.empty, false);
    assert.equal(pin.instructionsDigest, hashDiscoveryInstructions(step1.instructions));

    const ok = assertDiscoveryInstructionsIntegrity(store, step1.serverId, step1.instructions);
    assert.equal(ok.ok, true);
    assert.equal(ok.drift, false);
    assert.equal(ok.reapprovalRequired, false);
    assert.equal(ok.markActsUntrusted, false);

    assert.notEqual(
      hashDiscoveryInstructions(step1.instructions),
      hashDiscoveryInstructions(step2.instructions),
    );

    const drifted = assertDiscoveryInstructionsIntegrity(
      store,
      step2.serverId,
      step2.instructions,
    );
    assert.equal(drifted.drift, true);
    assert.equal(drifted.ok, false);
    assert.equal(drifted.reapprovalRequired, true);
    assert.equal(drifted.markActsUntrusted, true);
    assert.equal(drifted.actionGuardSource, 'mcp_result');

    // Never silent consent refresh
    const again = store.verify(step2.serverId, step2.instructions);
    assert.equal(again.drift, true);
    assert.equal(again.ok, false);
  });

  it('M3: cacheScope:public with instruction-bearing payload → refuse or bind', () => {
    const f = fix('mcp-disc-m3-cachescope-public-refuse-or-bind');
    assert.equal(barOf(f), 'M3');
    const ev = f.event as {
      serverId: string;
      cacheScope: string;
      instructions: string;
      callerA: string;
      callerB: string;
    };

    const refuse = evaluateDiscoveryCacheScope({
      instructions: ev.instructions,
      cacheScope: ev.cacheScope,
      serverId: ev.serverId,
      callerId: ev.callerA,
      policy: 'refuse_public',
    });
    assert.equal(refuse.action, 'refuse');

    const bindA = evaluateDiscoveryCacheScope({
      instructions: ev.instructions,
      cacheScope: 'public',
      serverId: ev.serverId,
      callerId: ev.callerA,
      policy: 'bind_to_caller_server',
    });
    assert.equal(bindA.action, 'bind');
    assert.ok(bindA.action === 'bind' && bindA.cacheKey.includes(ev.callerA));
    assert.ok(bindA.action === 'bind' && bindA.cacheKey.includes(ev.serverId));

    const bindB = evaluateDiscoveryCacheScope({
      instructions: ev.instructions,
      cacheScope: 'public',
      serverId: ev.serverId,
      callerId: ev.callerB,
      policy: 'bind_to_caller_server',
    });
    assert.equal(bindB.action, 'bind');
    assert.notEqual(
      bindA.action === 'bind' ? bindA.cacheKey : '',
      bindB.action === 'bind' ? bindB.cacheKey : '',
    );

    const keyA = bindDiscoveryCacheKey({
      serverId: ev.serverId,
      callerId: ev.callerA,
      instructions: ev.instructions,
    });
    const keyB = bindDiscoveryCacheKey({
      serverId: ev.serverId,
      callerId: ev.callerB,
      instructions: ev.instructions,
    });
    assert.notEqual(keyA, keyB);
  });

  it('M4: empty/absent instructions → ALLOW tool path', async () => {
    const f = fix('mcp-disc-m4-empty-instructions-ALLOW') as {
      bar: string;
      event: { serverId: string; instructions: string; tools: ToolSchema[] };
      laterToolCall: { name: string; args: Record<string, unknown> };
    };
    assert.equal(f.bar, 'M4');
    assert.equal(isEmptyDiscoveryInstructions(f.event.instructions), true);
    assert.equal(isEmptyDiscoveryInstructions(undefined), true);
    assert.equal(isEmptyDiscoveryInstructions(null), true);

    const isolated = isolateDiscoveryInstructions(f.event.instructions);
    assert.equal(isolated.empty, true);
    assert.equal(isolated.trustedRegionEligible, false);

    const store = new DiscoveryInstructionsConsentStore();
    store.record(f.event.serverId, f.event.instructions);
    const r = assertDiscoveryInstructionsIntegrity(
      store,
      f.event.serverId,
      f.event.instructions,
    );
    assert.equal(r.ok, true);
    assert.equal(r.drift, false);
    assert.equal(r.reapprovalRequired, false);

    const absent = assertDiscoveryInstructionsIntegrity(store, f.event.serverId, undefined);
    assert.equal(absent.ok, true);
    assert.equal(absent.drift, false);

    const cache = evaluateDiscoveryCacheScope({
      instructions: '',
      cacheScope: 'public',
      serverId: f.event.serverId,
      callerId: 'tenant-any',
    });
    assert.equal(cache.action, 'allow');

    const schemaStore = new SchemaConsentStore();
    for (const t of f.event.tools) schemaStore.record(f.event.serverId, t);
    const cont = await assertContinuousSchemaIntegrity(
      schemaStore,
      f.event.serverId,
      f.event.tools,
    );
    assert.equal(cont.ok, true);
    assert.equal(cont.rugPull, false);

    const plan: TrustedPlan = { tools: [f.laterToolCall.name], urls: [] };
    const ag = actionGuard(
      plan,
      [{ type: 'tool', name: f.laterToolCall.name, args: f.laterToolCall.args }],
      { source: 'mcp_result' },
    );
    assert.equal(ag.denied.length, 0);
    assert.equal(ag.allowed.length, 1);
  });

  it('M5: Deadbugz orthogonal — tools/list keys exclude instructions; continuous verify works', async () => {
    const f = fix('mcp-disc-m5-deadbugz-tools-list-orthogonal');
    assert.equal(barOf(f), 'M5');
    const ev = f.event as {
      serverId: string;
      instructions: string;
      tools: ToolSchema[];
      toolsListUnchanged?: boolean;
    };
    assert.equal(ev.toolsListUnchanged, true);
    assert.ok(!(TOOL_SCHEMA_INTEGRITY_KEYS as readonly string[]).includes('instructions'));

    const schema = ev.tools[0];
    const withInstr = { ...schema, instructions: ev.instructions } as ToolSchema;
    assert.equal(hashToolSchema(schema), hashToolSchema(withInstr));

    const schemaStore = new SchemaConsentStore();
    schemaStore.record(ev.serverId, schema);
    const cont = await assertContinuousSchemaIntegrity(schemaStore, ev.serverId, [schema]);
    assert.equal(cont.ok, true);
    assert.equal(cont.rugPull, false);

    // Hostile instructions beside unchanged tools → Discovery pin must still isolate/HITL
    const instrStore = new DiscoveryInstructionsConsentStore();
    const instr = assertDiscoveryInstructionsIntegrity(
      instrStore,
      ev.serverId,
      ev.instructions,
    );
    assert.equal(instr.isolated.trustedRegionEligible, false);
    assert.equal(mayFoldIntoTrustedRegion(instr.isolated), false);
    assert.equal(instr.reapprovalRequired, true);
    assert.equal(instr.ok, false);
  });

  it('M6: GhostSplice orthogonal — still gates mcp_result args after benign discovery', () => {
    const f = fix('mcp-disc-m6-ghostsplice-arg-content-orthogonal') as {
      bar: string;
      sequence: Array<Record<string, unknown>>;
    };
    assert.equal(f.bar, 'M6');
    const step1 = f.sequence[0];
    const step2 = f.sequence[1];

    const benign = String(step1.instructions ?? '');
    const isolated = isolateDiscoveryInstructions(benign);
    assert.equal(isolated.trustedRegionEligible, false);
    const store = new DiscoveryInstructionsConsentStore();
    store.record(String(step1.serverId), benign);
    const ok = assertDiscoveryInstructionsIntegrity(store, String(step1.serverId), benign);
    assert.equal(ok.ok, true);
    assert.equal(ok.drift, false);

    // Fixture step-2 text is shape-only (email prose); GhostSplice gates secret/path markers.
    // Prove compose: discovery clean does NOT skip/weaken GhostSplice on mcp_result.
    const secretArgs = {
      ...(step2.args as Record<string, unknown>),
      field_a:
        '-----BEGIN OPENSSH PRIVATE KEY-----\nSHAPE_ONLY_NOT_A_REAL_KEY\n-----END OPENSSH PRIVATE KEY-----',
      path: '/home/user/.ssh/id_rsa',
    };
    const scan = scanProposedToolArgs(secretArgs);
    assert.equal(scan.deny, true);
    assert.ok(scan.hits.length >= 1);

    const plan: TrustedPlan = { tools: [String(step2.tool)], urls: [] };
    const proposed: ProposedAction = {
      type: 'tool',
      name: String(step2.tool),
      args: secretArgs,
    };
    const ag = actionGuard(plan, [proposed], { source: 'mcp_result' });
    assert.equal(ag.allowed.length, 0);
    assert.ok(ag.denied.length >= 1);
  });

  it('M8: focused Deadbugz / GhostSplice / EP regression green (smoke)', async () => {
    const schemaStore = new SchemaConsentStore();
    const schema: ToolSchema = {
      name: 'echo',
      description: 'Echo text',
      parameters: { type: 'object', properties: { text: { type: 'string' } } },
    };
    schemaStore.record('s1', schema);
    const d = await assertContinuousSchemaIntegrity(schemaStore, 's1', [schema]);
    assert.equal(d.ok, true);

    const gs = scanProposedToolArgs({ path: '/home/user/.ssh/id_rsa' });
    assert.equal(gs.deny, true);

    const plan: TrustedPlan = { tools: ['format_text'], urls: [] };
    const ag = actionGuard(
      plan,
      [{ type: 'tool', name: 'format_text', args: { text: 'ok' } }],
      { source: 'user' },
    );
    assert.equal(ag.denied.length, 0);
  });

  it('assertDiscoveryInstructionsIntegrity never auto-records consent', () => {
    const store = new DiscoveryInstructionsConsentStore();
    const r = assertDiscoveryInstructionsIntegrity(
      store,
      's-new',
      'Prefer the summarize tool.',
    );
    assert.equal(r.reapprovalRequired, true);
    assert.equal(r.drift, false);
    assert.equal(store.verify('s-new', 'Prefer the summarize tool.').consented, false);
  });
});
