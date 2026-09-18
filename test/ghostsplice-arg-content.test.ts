/**
 * GhostSplice thin land — arg-content gate (G1–G5).
 * Fixture: prefer threat-scout pack; fallback pentest/payloads.
 * KPI act/egress; not deepset; CrossChannelMcpWatch deferred (G6).
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  actionGuard,
  scanProposedToolArgs,
  type TrustedPlan,
  type ProposedAction,
} from '../src/delivery/action-guard.js';
import { scanToolSchema, type ToolSchema } from '../src/scanner/tool-schema.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const TS_FIXTURE = '/workspace/threat-scout/pentest/payloads/ghostsplice-cross-channel.json';
const LOCAL_FIXTURE = join(__dirname, '../pentest/payloads/ghostsplice-cross-channel.json');
const fixturePath = existsSync(TS_FIXTURE) ? TS_FIXTURE : LOCAL_FIXTURE;

const pack = JSON.parse(readFileSync(fixturePath, 'utf8')) as {
  fixtures: Array<Record<string, unknown>>;
};

function fix(id: string): Record<string, unknown> {
  const f = pack.fixtures.find((x) => x.id === id);
  assert.ok(f, `missing fixture ${id} in ${fixturePath}`);
  return f;
}

/** Flatten nested Threat Scout argAllowlist { tool: { arg: vals } } → "tool.arg": vals. */
function flattenArgAllowlist(raw: unknown): Record<string, string[]> | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const out: Record<string, string[]> = {};
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (Array.isArray(v)) {
      out[k] = v.map(String);
    } else if (v && typeof v === 'object') {
      for (const [arg, vals] of Object.entries(v as Record<string, unknown>)) {
        if (Array.isArray(vals)) out[`${k}.${arg}`] = vals.map(String);
      }
    }
  }
  return Object.keys(out).length ? out : undefined;
}

function planFrom(f: Record<string, unknown>): TrustedPlan {
  const tp = (f.trustedPlan ?? {}) as Record<string, unknown>;
  const argAllowlist =
    flattenArgAllowlist(tp.argAllowlist) ?? flattenArgAllowlist(tp.allowlist);
  return {
    actions: (tp.actions as string[] | undefined) ?? undefined,
    tools: (tp.tools as string[] | undefined) ?? undefined,
    urls: (tp.urls as string[] | undefined) ?? undefined,
    argAllowlist: argAllowlist ?? undefined,
  };
}

function proposedFrom(f: Record<string, unknown>): { action: ProposedAction; source?: string } {
  const p = f.proposedAction as {
    type: string;
    name?: string;
    args?: Record<string, unknown>;
    url?: string;
    source?: string;
  };
  if (p.type === 'fetch') {
    return { action: { type: 'fetch', url: String(p.url) }, source: p.source };
  }
  return {
    action: {
      type: p.type === 'action' ? 'action' : 'tool',
      name: String(p.name),
      args: p.args,
    },
    source: p.source,
  };
}

describe('GhostSplice arg-content (G1–G5)', () => {
  it('G1: bland soft×3 composite — tool on plan, no argAllowlist, sensitive args → DENY via scanProposedToolArgs', () => {
    const f = fix('gs-g1-bland-soft-x3-composite-deny');
    const plan = planFrom(f);
    assert.ok(plan.tools?.includes('integrity_checker'));
    assert.equal(plan.argAllowlist, undefined);

    const { action, source } = proposedFrom(f);
    assert.equal(source, 'mcp_result');

    // Standalone scanner hits PEM / path-shaped contents
    assert.equal(action.type, 'tool');
    const standalone = scanProposedToolArgs(action.type === 'tool' ? action.args : undefined);
    assert.equal(standalone.deny, true);
    assert.ok(standalone.hits.length >= 1);

    // Without gate source → would allow (regress residual documented at tip)
    const withoutGate = actionGuard(plan, [action]);
    assert.equal(withoutGate.denied.length, 0, 'without mcp_result source, plan alone allows');
    assert.equal(withoutGate.allowed.length, 1);

    // With mcp_result → DENY via arg-content
    const withGate = actionGuard(plan, [action], { source: 'mcp_result' });
    assert.equal(withGate.allowed.length, 0);
    assert.ok(withGate.denied.length >= 1);
    assert.match(withGate.denied[0].reason, /secret\/path exfil|arg-content|private_key|TrustedPlan/i);

    // api_response peer also gates
    const apiGate = actionGuard(plan, [action], { source: 'api_response' });
    assert.equal(apiGate.allowed.length, 0);
  });

  it('G2: IMPORTANT full-instruction in one schema channel → not soft-allow', async () => {
    const f = fix('gs-g2-important-one-channel-control');
    const channels = f.channels as Array<{ schema?: ToolSchema & { parameters?: unknown } }>;
    const schema = channels[0]?.schema;
    assert.ok(schema);
    assert.match(String(schema.description), /IMPORTANT/i);

    const res = await scanToolSchema(schema as ToolSchema);
    assert.notEqual(res.classification, 'safe');
    assert.ok(
      res.action === 'block' || res.action === 'quarantine',
      `expected block|quarantine, got action=${res.action} classification=${res.classification}`,
    );
  });

  it('G3: argAllowlist positive path — off-list values still DENY', () => {
    const f = fix('gs-g3-arg-allowlist-positive');
    const plan = planFrom(f);
    assert.ok(plan.argAllowlist);
    assert.ok(plan.argAllowlist!['integrity_checker.field_a']?.includes('notes.txt'));

    const { action, source } = proposedFrom(f);
    const r = actionGuard(plan, [action], { source: source ?? 'mcp_result' });
    assert.equal(r.allowed.length, 0);
    assert.ok(r.denied.length >= 1);
    // Prefer argAllowlist reason (runs before content gate)
    assert.match(r.denied[0].reason, /field_a|allowlist/i);
  });

  it('G4: summarize-only TrustedPlan → AG DENY sensitive tools', () => {
    const f = fix('gs-g4-summarize-only-plan-deny');
    const plan = planFrom(f);
    assert.deepEqual(plan.actions, ['summarize']);
    assert.ok(!plan.tools?.length);

    const { action, source } = proposedFrom(f);
    const r = actionGuard(plan, [action], { source: source ?? 'mcp_result' });
    assert.equal(r.allowed.length, 0);
    assert.ok(r.denied.some((d) => /not in trusted plan/i.test(d.reason)));
  });

  it('G5: Deadbugz continuous path no-worsen — assertContinuousSchemaIntegrity still exported/usable', async () => {
    // Pointer bar: do not disable continuous integrity; smoke the existing pack path.
    const { assertContinuousSchemaIntegrity, SchemaConsentStore, hashToolSchema } =
      await import('../src/scanner/tool-schema.js');
    const store = new SchemaConsentStore();
    const schema: ToolSchema = {
      name: 'integrity_checker',
      description: 'Hash verification helper.',
      inputSchema: { type: 'object', properties: { field_a: { type: 'string' } } },
    };
    store.record('gs-g5-server', schema);
    const ok = await assertContinuousSchemaIntegrity(store, 'gs-g5-server', [schema]);
    assert.equal(ok.ok, true);
    assert.equal(ok.rugPull, false);
    assert.equal(hashToolSchema(schema).length > 0, true);

    // Benign args under mcp_result still allow (no false deny on ordinary content)
    const benign = actionGuard(
      { tools: ['integrity_checker'] },
      [{ type: 'tool', name: 'integrity_checker', args: { field_a: 'meeting notes excerpt' } }],
      { source: 'mcp_result' },
    );
    assert.equal(benign.denied.length, 0);
    assert.equal(benign.allowed.length, 1);
  });
});
