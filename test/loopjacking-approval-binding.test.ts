/**
 * Loopjacking ApprovalBinding thin land — G1–G8.
 * Fixture: prefer threat-scout pack; fallback pentest/payloads.
 * KPI = approval-binding integrity at act gate; not deepset 80%.
 * Keep argAllowlist + scanProposedToolArgs + SchemaConsent no-worsen.
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
import {
  ApprovalBindingStore,
  approveAction,
  assertRepresentationComplete,
  compareApprovalAtUse,
  digestApprovalVector,
  releaseWithApproval,
  type ApprovalVector,
  type UiApproveView,
} from '../src/delivery/approval-binding.js';
import {
  assertContinuousSchemaIntegrity,
  SchemaConsentStore,
  hashToolSchema,
  type ToolSchema,
} from '../src/scanner/tool-schema.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const TS_FIXTURE = '/workspace/threat-scout/pentest/payloads/loopjacking-approval-binding.json';
const LOCAL_FIXTURE = join(__dirname, '../pentest/payloads/loopjacking-approval-binding.json');
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

function vectorFrom(obj: Record<string, unknown>): ApprovalVector {
  return {
    tool: String(obj.tool),
    args: (obj.args as Record<string, unknown> | undefined) ?? {},
    destination: obj.destination !== undefined ? String(obj.destination) : '',
    scope: obj.scope !== undefined ? String(obj.scope) : '',
  };
}

describe('Loopjacking ApprovalBinding (G1–G8)', () => {
  it('G1/G2: approve args_A → mutate pending to args_B → use-time DENY (digest mismatch)', () => {
    const f = fix('lj-ab-mutate-A-to-B-DENY');
    const plan = planFrom(f);
    const approveVec = vectorFrom(f.hitlApprove as Record<string, unknown>);
    const mutateVec = vectorFrom(f.pendingMutation as Record<string, unknown>);

    assert.notEqual(
      digestApprovalVector(approveVec),
      digestApprovalVector(mutateVec),
      'A≠B digests required for bind gap close',
    );

    const store = new ApprovalBindingStore();
    const approved = approveAction(store, approveVec);
    assert.equal(approved.ok, true);
    assert.ok(approved.ticket);

    const cmp = compareApprovalAtUse(store, approved.ticket!.id, mutateVec);
    assert.equal(cmp.match, false);
    assert.match(String(cmp.reason), /use-time digest|re-approval/i);

    const ag = actionGuard(
      plan,
      [{ type: 'tool', name: mutateVec.tool, args: mutateVec.args }],
      {
        approvalBinding: {
          store,
          ticketId: approved.ticket!.id,
          destination: mutateVec.destination,
          scope: mutateVec.scope,
        },
      },
    );
    assert.equal(ag.allowed.length, 0);
    assert.ok(ag.denied.length >= 1);
    assert.match(ag.denied[0].reason, /digest|re-approval|consumed/i);
  });

  it('G3: unchanged args_A after approve → ALLOW (exact digest match + consume)', () => {
    const f = fix('lj-ab-unchanged-A-ALLOW');
    const plan = planFrom(f);
    const approveVec = vectorFrom(f.hitlApprove as Record<string, unknown>);

    const store = new ApprovalBindingStore();
    const approved = approveAction(store, approveVec);
    assert.equal(approved.ok, true);

    const release = releaseWithApproval(store, approved.ticket!.id, approveVec);
    assert.equal(release.allow, true);
    assert.equal(release.consumedNow, true);

    // Fresh ticket for AG compose path (prior release consumed)
    const store2 = new ApprovalBindingStore();
    const approved2 = approveAction(store2, approveVec);
    const ag = actionGuard(
      plan,
      [{ type: 'tool', name: approveVec.tool, args: approveVec.args }],
      {
        approvalBinding: {
          store: store2,
          ticketId: approved2.ticket!.id,
          destination: approveVec.destination,
          scope: approveVec.scope,
        },
      },
    );
    assert.equal(ag.denied.length, 0);
    assert.equal(ag.allowed.length, 1);
    assert.equal(store2.get(approved2.ticket!.id)?.consumed, true);
  });

  it('G4: incomplete/lossy UI approve vs full executable → refuse approve', () => {
    const f = fix('lj-ab-incomplete-UI-DENY');
    const ui = f.uiApproveView as Record<string, unknown>;
    const exec = vectorFrom(f.executableObject as Record<string, unknown>);
    const uiView: UiApproveView = {
      tool: String(ui.tool),
      shownArgs: (ui.shownArgs as Record<string, unknown>) ?? {},
      lossy: ui.lossy === true,
    };

    const completeness = assertRepresentationComplete(uiView, exec);
    assert.equal(completeness.ok, false);

    const store = new ApprovalBindingStore();
    const refused = approveAction(store, exec, { uiView });
    assert.equal(refused.ok, false);
    assert.equal(refused.refusedLossy, true);
    assert.equal(store.size(), 0);
    assert.match(String(refused.reason), /lossy|omit|refuse/i);
  });

  it('G5: consumed approval replay → DENY', () => {
    const f = fix('lj-ab-replay-consumed-DENY');
    const approveVec = vectorFrom(f.hitlApprove as Record<string, unknown>);
    const store = new ApprovalBindingStore();
    const approved = approveAction(store, approveVec);
    assert.equal(approved.ok, true);

    const first = releaseWithApproval(store, approved.ticket!.id, approveVec);
    assert.equal(first.allow, true);

    const replay = releaseWithApproval(store, approved.ticket!.id, approveVec);
    assert.equal(replay.allow, false);
    assert.match(String(replay.reason), /consumed|replay/i);

    const plan = { tools: [approveVec.tool] };
    const agReplay = actionGuard(
      plan,
      [{ type: 'tool', name: approveVec.tool, args: approveVec.args }],
      {
        approvalBinding: {
          store,
          ticketId: approved.ticket!.id,
          destination: approveVec.destination,
          scope: approveVec.scope,
        },
      },
    );
    assert.equal(agReplay.allowed.length, 0);
    assert.match(agReplay.denied[0].reason, /consumed|replay/i);
  });

  it('G6: wrong-scope / outsider tool not on TrustedPlan → DENY (no AG regress)', () => {
    const f = fix('lj-ab-outsider-wrong-scope-DENY');
    const plan = planFrom(f);
    const approveVec = vectorFrom(f.hitlApprove as Record<string, unknown>);
    assert.ok(!plan.tools?.includes(approveVec.tool));

    // Even with a valid ticket for outsider tool, AG plan gate DENYs first.
    const store = new ApprovalBindingStore();
    const approved = approveAction(store, approveVec);
    const ag = actionGuard(
      plan,
      [{ type: 'tool', name: approveVec.tool, args: approveVec.args }],
      {
        approvalBinding: {
          store,
          ticketId: approved.ticket!.id,
          destination: approveVec.destination,
          scope: approveVec.scope,
        },
      },
    );
    assert.equal(ag.allowed.length, 0);
    assert.ok(ag.denied.some((d) => /not in trusted plan/i.test(d.reason)));
  });

  it('G7a: argAllowlist off-list still DENY (complementary no-worsen)', () => {
    const f = fix('lj-ab-argAllowlist-no-worsen');
    const plan = planFrom(f);
    assert.ok(plan.argAllowlist?.['send_email.to']);
    const p = f.proposedAction as {
      type: string;
      name: string;
      args?: Record<string, unknown>;
    };
    const action: ProposedAction = {
      type: 'tool',
      name: p.name,
      args: p.args,
    };
    const r = actionGuard(plan, [action]);
    assert.equal(r.allowed.length, 0);
    assert.ok(r.denied.length >= 1);
    assert.match(r.denied[0].reason, /to|allowlist/i);
  });

  it('G7b: GhostSplice scanProposedToolArgs secret-args DENY (orthogonal no-regress)', () => {
    const f = fix('lj-ab-ghostsplice-secret-orthogonal');
    const plan = planFrom(f);
    const p = f.proposedAction as {
      type: string;
      name: string;
      args?: Record<string, unknown>;
      source?: string;
    };
    const standalone = scanProposedToolArgs(p.args);
    assert.equal(standalone.deny, true);

    const r = actionGuard(
      plan,
      [{ type: 'tool', name: p.name, args: p.args }],
      { source: p.source ?? 'mcp_result' },
    );
    assert.equal(r.allowed.length, 0);
    assert.match(r.denied[0].reason, /secret\/path exfil|arg-content|private_key|TrustedPlan/i);
  });

  it('G7c/G8 pointer: SchemaConsent orthogonal + CHANGELOG honesty smoke', async () => {
    const f = fix('lj-ab-schemaConsent-orthogonal');
    assert.equal((f.expect as Record<string, unknown>).SchemaConsent, 'schema_only');
    assert.equal(
      (f.expect as Record<string, unknown>).ApprovalBinding,
      'orthogonal_action_bind',
    );

    const store = new SchemaConsentStore();
    const schema: ToolSchema = {
      name: 'demo_tool',
      description: 'Benign schema-only control.',
      inputSchema: { type: 'object', properties: { x: { type: 'string' } } },
    };
    store.record('lj-ab-server', schema);
    const ok = await assertContinuousSchemaIntegrity(store, 'lj-ab-server', [schema]);
    assert.equal(ok.ok, true);
    assert.equal(ok.rugPull, false);
    assert.ok(hashToolSchema(schema).length > 0);

    // SchemaConsent digest ≠ ApprovalBinding digest (different payloads)
    const actionDigest = digestApprovalVector({
      tool: 'demo_tool',
      args: { x: '1' },
      destination: 'local',
      scope: 'user_initiated',
    });
    assert.notEqual(actionDigest, hashToolSchema(schema));

    const changelog = readFileSync(join(__dirname, '../CHANGELOG.md'), 'utf8');
    assert.match(changelog, /ApprovalBinding/);
    assert.match(changelog, /approval-binding integrity/i);
    assert.match(changelog, /not.*deepset/i);
  });
});
