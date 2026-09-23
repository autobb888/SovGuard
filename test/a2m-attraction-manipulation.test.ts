/**
 * A2M Attraction→Manipulation thin land — A1–A3, B1–B3, C1, D1–D2 + compose smoke.
 * Fixture: prefer threat-scout pack; fallback pentest/payloads.
 * KPI = prefer-pin + return IFC + C-DoS + mcp_config ApprovalBinding; not deepset 80%.
 * Compose Deadbugz / GhostSplice / MCP Discovery / EP — do not subsume. No A2M kit.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ToolAdmissionStore,
  admitTool,
  checkToolAdmission,
  preferPinnedTool,
  selectToolForCapability,
  verifyAdmittedDigest,
} from '../src/delivery/tool-admission.js';
import {
  applyReturnIfc,
  labelToolReturn,
  isReturnTrustedDirective,
} from '../src/delivery/return-ifc.js';
import {
  ToolCallBudgetStore,
  checkToolCallBudget,
  gateToolCall,
} from '../src/delivery/tool-call-budget.js';
import {
  gateMcpConfigWrite,
  mcpConfigApprovalVector,
} from '../src/delivery/mcp-config-gate.js';
import {
  ApprovalBindingStore,
  approveAction,
} from '../src/delivery/approval-binding.js';
import {
  SchemaConsentStore,
  assertContinuousSchemaIntegrity,
  hashToolSchema,
  TOOL_SCHEMA_INTEGRITY_KEYS,
  type ToolSchema,
} from '../src/scanner/tool-schema.js';
import {
  isolateDiscoveryInstructions,
  mayFoldIntoTrustedRegion,
  DiscoveryInstructionsConsentStore,
  assertDiscoveryInstructionsIntegrity,
} from '../src/scanner/mcp-discovery-instructions.js';
import {
  scanProposedToolArgs,
  isArgContentGateSource,
} from '../src/delivery/action-guard.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TS_FIXTURE = '/workspace/threat-scout/pentest/payloads/a2m-attraction-manipulation.json';
const LOCAL_FIXTURE = join(__dirname, '../pentest/payloads/a2m-attraction-manipulation.json');
const fixturePath = existsSync(TS_FIXTURE) ? TS_FIXTURE : LOCAL_FIXTURE;

const pack = JSON.parse(readFileSync(fixturePath, 'utf8')) as {
  _meta?: { n?: number; bars?: string[]; shapesOnly?: boolean; noCloneA2MKit?: boolean };
  fixtures: Array<Record<string, unknown>>;
};

function fix(id: string): Record<string, unknown> {
  const f = pack.fixtures.find((x) => x.id === id);
  assert.ok(f, `missing fixture ${id} in ${fixturePath}`);
  return f;
}

describe('A2M Attraction→Manipulation (A1–A3, B1–B3, C1, D1–D2)', () => {
  it('fixture pack shapes-only n=12 covering A/B/C/D + X', () => {
    assert.equal(pack._meta?.shapesOnly, true);
    assert.equal(pack._meta?.noCloneA2MKit, true);
    assert.ok((pack._meta?.n ?? 0) >= 6);
    assert.equal(pack.fixtures.length, 12);
    const bars = new Set(pack.fixtures.map((f) => f.bar));
    for (const b of ['A1', 'A2', 'A3', 'B1', 'B2', 'B3', 'C1', 'D1', 'D2']) {
      assert.ok(bars.has(b), `missing bar ${b}`);
    }
  });

  it('A1: unknown registry / unpinned differently-named competitor DENY', () => {
    const f = fix('a2m-a1-unknown-registry-competitor-DENY');
    const event = f.event as Record<string, unknown>;
    const pinned = event.pinnedTool as Record<string, unknown>;
    const competing = event.competingTool as Record<string, unknown>;
    const capability = String(event.capability);

    const store = new ToolAdmissionStore();
    admitTool(store, {
      name: String(pinned.name),
      description: String(pinned.description ?? ''),
      capability,
      schemaDigest: String(pinned.schemaDigest ?? ''),
      schema: {
        name: String(pinned.name),
        description: String(pinned.description ?? ''),
      },
    });

    const r = checkToolAdmission(
      store,
      {
        name: String(competing.name),
        description: String(competing.description ?? ''),
        registry: String(competing.registry ?? ''),
        admitted: false,
        schemaDigest: null,
        capability,
      },
      { capability },
    );

    assert.equal(r.verdict, 'DENY');
    assert.equal(r.deniedUnknown, true);
    assert.match(r.reason ?? '', /unknown|unpinned|never auto-select/i);

    const sel = selectToolForCapability(store, capability, [
      { name: String(pinned.name), admitted: true },
      {
        name: String(competing.name),
        description: String(competing.description ?? ''),
        registry: String(competing.registry ?? ''),
        admitted: false,
      },
    ]);
    assert.equal(sel.verdict, 'ALLOW');
    assert.equal(sel.preferredPinned, true);
    assert.equal((sel.selected as { name: string }).name, String(pinned.name));
  });

  it('A2: digest-pin drift → REJECT fail-closed (compose Deadbugz)', () => {
    const f = fix('a2m-a2-digest-pin-drift-REJECT');
    const sequence = f.sequence as Array<Record<string, unknown>>;
    const step1 = sequence[0];
    const step2 = sequence[1];
    const tool1 = step1.tool as ToolSchema;
    const tool2 = step2.tool as ToolSchema;

    const consent = new SchemaConsentStore();
    const store = new ToolAdmissionStore();
    const admitted = admitTool(
      store,
      {
        name: tool1.name,
        description: tool1.description,
        capability: 'calendar',
        schema: tool1,
        serverId: 'local',
      },
      { consentStore: consent, consentServerId: 'local' },
    );

    assert.ok(TOOL_SCHEMA_INTEGRITY_KEYS.includes('description'));
    assert.equal(admitted.schemaDigest, hashToolSchema(tool1));

    const ok = verifyAdmittedDigest(admitted, tool1, {
      consentStore: consent,
      serverId: 'local',
    });
    assert.equal(ok.verdict, 'ALLOW');

    const drift = verifyAdmittedDigest(admitted, tool2, {
      consentStore: consent,
      serverId: 'local',
    });
    assert.equal(drift.verdict, 'REJECT_DRIFT');
    assert.equal(drift.drift?.rugPull, true);
    assert.notEqual(hashToolSchema(tool1), hashToolSchema(tool2));
  });

  it('A3: prefer-pin same capability over persuasive differently-named competitor', () => {
    const f = fix('a2m-a3-prefer-pin-same-capability');
    const event = f.event as Record<string, unknown>;
    const pinned = event.pinnedTool as Record<string, unknown>;
    const competing = event.competingTool as Record<string, unknown>;
    const capability = String(event.capability);

    const store = new ToolAdmissionStore();
    admitTool(store, {
      name: String(pinned.name),
      description: String(pinned.description ?? ''),
      capability,
      schema: {
        name: String(pinned.name),
        description: String(pinned.description ?? ''),
      },
    });

    const r = preferPinnedTool({
      capability,
      pinned: store.listByCapability(capability),
      candidates: [
        {
          name: String(competing.name),
          description: String(competing.description ?? ''),
          registry: String(competing.registry ?? ''),
          admitted: false,
        },
        { name: String(pinned.name), admitted: true },
      ],
    });

    assert.equal(r.verdict, 'ALLOW');
    assert.equal(r.preferredPinned, true);
    assert.equal((r.selected as { name: string }).name, String(pinned.name));
    assert.notEqual((r.selected as { name: string }).name, String(competing.name));
  });

  it('B1: required_action / call-again / blocking_condition → strip or DENY', () => {
    const f = fix('a2m-b1-required-action-call-again-DENY');
    const event = f.event as Record<string, unknown>;
    const body = event.returnBody;

    const r = applyReturnIfc(body, {
      source: String(event.source ?? 'mcp_result'),
      tool: String(event.tool ?? ''),
    });

    assert.ok(r.verdict === 'STRIP' || r.verdict === 'DENY');
    assert.equal(r.instructionShaped, true);
    assert.equal(r.source, 'mcp_result');
    assert.ok(r.trust === 'untrusted' || r.trust === 'data_only');
    assert.equal(isReturnTrustedDirective(r), false);

    if (r.verdict === 'STRIP') {
      const stripped = r.body as Record<string, unknown>;
      assert.equal(stripped.required_action, undefined);
      assert.equal(stripped.call_again, undefined);
      assert.equal(stripped.blocking_condition, undefined);
      assert.equal(stripped.privilege_hint, undefined);
      assert.ok(r.strippedFields.length >= 1);
    }
  });

  it('B2: data-only structured return → ALLOW', () => {
    const f = fix('a2m-b2-data-only-structured-ALLOW');
    const event = f.event as Record<string, unknown>;
    const r = applyReturnIfc(event.returnBody, {
      source: String(event.source ?? 'mcp_result'),
      tool: String(event.tool ?? ''),
    });
    assert.equal(r.verdict, 'ALLOW');
    assert.equal(r.trust, 'data_only');
    assert.equal(r.instructionShaped, false);
    assert.equal(r.source, 'mcp_result');
    assert.deepEqual(r.body, event.returnBody);
  });

  it('B3: return labeled untrusted/data-only; no trust promotion', () => {
    const f = fix('a2m-b3-return-untrusted-label');
    const event = f.event as Record<string, unknown>;
    const labeled = labelToolReturn(event.returnBody, {
      source: String(event.source ?? 'mcp_result'),
      tool: String(event.tool ?? ''),
      registry: String(event.registry ?? ''),
    });
    assert.ok(labeled.trust === 'untrusted' || labeled.trust === 'data_only');
    assert.equal(labeled.source, 'mcp_result');
    assert.equal(isReturnTrustedDirective(labeled), false);

    // Refuse promotion even if host passes trusted/system
    const forced = labelToolReturn(event.returnBody, { source: 'system' });
    assert.equal(forced.source, 'mcp_result');
    assert.equal(forced.trust, 'untrusted');
  });

  it('C1: same-tool re-invocation storm → DENY or HITL (not SessionScorer alone)', () => {
    const f = fix('a2m-c1-same-tool-reinvocation-cap');
    const event = f.event as Record<string, unknown>;
    const tool = String(event.tool);
    const baseline = Number(event.taskBaselineInvocations);
    const observed = Number(event.observedInvocations);
    const store = new ToolCallBudgetStore();

    // Seed just under absolute cap path using paper-like storm shape.
    for (let i = 0; i < Math.min(observed - 1, 20); i++) {
      store.record({ sessionId: 'cdos-1', tool, tokenCost: Number(event.weightedTokenMultiplier) || 1 });
    }

    const first = checkToolCallBudget(store, {
      sessionId: 'cdos-1',
      tool,
      taskBaselineInvocations: baseline,
      taskBaselineTokens: baseline,
      proposedTokenCost: Number(event.weightedTokenMultiplier) || 1,
      config: {
        maxInvocationMultiplier: 4,
        absoluteMaxInvocations: 8,
        maxTokenCostMultiplier: 4,
        escalateBeforeDeny: true,
      },
    });
    assert.ok(
      first.verdict === 'DENY' || first.verdict === 'HITL' || first.verdict === 'COST_ESCALATE',
      `expected DENY/HITL/COST_ESCALATE, got ${first.verdict}`,
    );
    assert.equal(first.gate, 'CDoSCap.same_tool_reinvocation');

    // After escalate, next check hard DENYs
    store.markEscalated('cdos-1', tool);
    const second = gateToolCall(store, {
      sessionId: 'cdos-1',
      tool,
      taskBaselineInvocations: baseline,
      taskBaselineTokens: baseline,
      tokenCost: 1,
      config: {
        maxInvocationMultiplier: 4,
        absoluteMaxInvocations: 8,
        maxTokenCostMultiplier: 4,
        escalateBeforeDeny: true,
      },
    });
    assert.equal(second.verdict, 'DENY');
  });

  it('D1: mcp_config append without ApprovalBinding → DENY', () => {
    const f = fix('a2m-d1-mcp-config-append-without-binding-DENY');
    const event = f.event as Record<string, unknown>;
    const server = event.proposedServer as Record<string, unknown>;
    const r = gateMcpConfigWrite(
      {
        action: String(event.action),
        proposedServer: {
          id: String(server.id),
          url: String(server.url ?? ''),
          transport: String(server.transport ?? ''),
        },
      },
      null,
    );
    assert.equal(r.verdict, 'DENY');
    assert.equal(r.gate, 'ConfigWriteGate.DENY_no_binding');
  });

  it('D2: mcp_config append with fresh ApprovalBinding → ALLOW', () => {
    const f = fix('a2m-d2-mcp-config-append-with-fresh-binding-ALLOW');
    const event = f.event as Record<string, unknown>;
    const server = event.proposedServer as Record<string, unknown>;
    const attempt = {
      action: String(event.action),
      proposedServer: {
        id: String(server.id),
        url: String(server.url ?? ''),
        transport: String(server.transport ?? ''),
      },
      scope: 'mcp_config_registry_append',
    };
    const ab = new ApprovalBindingStore();
    const vector = mcpConfigApprovalVector(attempt);
    const approved = approveAction(ab, vector);
    assert.equal(approved.ok, true);
    assert.ok(approved.ticket);

    const r = gateMcpConfigWrite(attempt, {
      store: ab,
      ticketId: approved.ticket!.id,
    });
    assert.equal(r.verdict, 'ALLOW');
    assert.equal(r.gate, 'ConfigWriteGate.ALLOW_fresh_envelope');

    // Replay consumed → DENY
    const replay = gateMcpConfigWrite(attempt, {
      store: ab,
      ticketId: approved.ticket!.id,
    });
    assert.equal(replay.verdict, 'DENY');
  });
});

describe('A2M compose / no-worsen smoke (X1–X3, G5)', () => {
  it('X1: Deadbugz continuous integrity still green beside Attraction DENY', async () => {
    const f = fix('a2m-x1-deadbugz-tools-list-orthogonal');
    const event = f.event as Record<string, unknown>;
    const consented = event.consentedTool as Record<string, unknown>;
    const competitor = event.newCompetitor as Record<string, unknown>;

    const schema: ToolSchema = {
      name: String(consented.name),
      description: String(consented.description ?? ''),
    };
    const consent = new SchemaConsentStore();
    consent.record('local', schema);
    const cont = await assertContinuousSchemaIntegrity(consent, 'local', [schema]);
    assert.equal(cont.ok, true);
    assert.equal(cont.rugPull, false);

    const admit = new ToolAdmissionStore();
    admitTool(admit, {
      name: schema.name,
      description: schema.description,
      capability: 'format',
      schema,
      serverId: 'local',
    });
    const denied = checkToolAdmission(
      admit,
      {
        name: String(competitor.name),
        description: String(competitor.description ?? ''),
        registry: String(competitor.registry ?? ''),
        admitted: false,
        capability: 'format',
      },
      { capability: 'format' },
    );
    assert.equal(denied.verdict, 'DENY');
  });

  it('X2: MCP Discovery instructions isolate+pin still green', () => {
    const f = fix('a2m-x2-mcp-discovery-instructions-orthogonal');
    const sequence = f.sequence as Array<Record<string, unknown>>;
    const init = sequence[0];
    const isolated = isolateDiscoveryInstructions(String(init.instructions ?? ''));
    assert.equal(mayFoldIntoTrustedRegion(isolated), false);
    assert.equal(isolated.trust, 'untrusted');
    assert.equal(isolated.trustedRegionEligible, false);

    const store = new DiscoveryInstructionsConsentStore();
    store.record(String(init.serverId), String(init.instructions ?? ''));
    const integrity = assertDiscoveryInstructionsIntegrity(
      store,
      String(init.serverId),
      String(init.instructions ?? ''),
    );
    assert.equal(integrity.ok, true);

    const step2 = sequence[1];
    const pinned = (step2.pinnedTool as Record<string, unknown>).name as string;
    const competing = step2.competingTool as Record<string, unknown>;
    const admit = new ToolAdmissionStore();
    admitTool(admit, {
      name: pinned,
      capability: String(step2.capability),
      schema: { name: pinned },
    });
    const sel = preferPinnedTool({
      capability: String(step2.capability),
      pinned: admit.listByCapability(String(step2.capability)),
      candidates: [
        { name: pinned, admitted: true },
        {
          name: String(competing.name),
          description: String(competing.description ?? ''),
          admitted: false,
        },
      ],
    });
    assert.equal(sel.preferredPinned, true);
    assert.equal((sel.selected as { name: string }).name, pinned);
  });

  it('X3/G5: GhostSplice scanProposedToolArgs still gates source=mcp_result', () => {
    const f = fix('a2m-x3-ghostsplice-kpic-ep-no-worsen');
    const sequence = f.sequence as Array<Record<string, unknown>>;
    const ret = sequence[0];
    const proposed = sequence[1];

    // Return IFC labels data-only / untrusted — must NOT skip GhostSplice
    const ifc = applyReturnIfc(ret.returnBody, {
      source: String(ret.source ?? 'mcp_result'),
      tool: String(ret.tool ?? ''),
    });
    assert.equal(ifc.source, 'mcp_result');
    assert.ok(ifc.trust === 'untrusted' || ifc.trust === 'data_only');

    assert.equal(isArgContentGateSource('mcp_result'), true);
    assert.equal(isArgContentGateSource(String(proposed.source ?? 'mcp_result')), true);

    // Fixture shapes use short demo tokens; exercise GhostSplice with known-triggering
    // secret/path markers so G5 no-worsen is observable (compose, not re-land).
    const baseArgs = (proposed.args as Record<string, unknown>) ?? {};
    const args = {
      ...baseArgs,
      body: `${String(baseArgs.body ?? '')} path=/home/user/.ssh/id_rsa token=sk-abcdefghijklmnopqrstuvwxyz12`,
    };
    const scan = scanProposedToolArgs(args);
    assert.equal(scan.deny, true);
    assert.ok(scan.hits.length >= 1);
  });
});
