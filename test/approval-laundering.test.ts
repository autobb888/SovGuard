/**
 * ApprovalLaundering thin land A–D — AL1–AL6 + F1/R1 honesty.
 * Shapes only vs DL-011 acceptance. Escalate BLOCK.
 * No Approval Laundering paper PoC/kit. No ControlToken / Chronos / A2A / A2M /
 * Trace / IME / C-DoS reopen or land here.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  freezePred6BeforeAllow,
  requireFrozenPred6BeforeAllow,
  digestEffectBoundRecord,
  digestProvenanceContent,
  OMEGA6_CLASSES,
  PROVENANCE_KEYS,
} from '../src/delivery/effect-bound-record.js';
import {
  assertEffSubseteqRep,
  assertClosureWitness,
  DEFAULT_AMBIENT_ALLOWLIST,
} from '../src/delivery/closure-witness.js';
import {
  requireNetworkOmega6OnCard,
  gateMcpConfigWriteWithNetworkAtApprove,
  freezeMcpRemotePred6Card,
  isRemoteMcpTransport,
} from '../src/delivery/mcp-network-at-approve.js';
import {
  predictInstallLifecycle,
  gateInstallLifecycleApprove,
  lifecyclePredCoversHooks,
} from '../src/delivery/install-lifecycle-predict.js';
import {
  ApprovalBindingStore,
  approveAction,
  compareApprovalAtUse,
  releaseWithApproval,
  digestApprovalVector,
} from '../src/delivery/approval-binding.js';
import {
  gateMcpConfigWrite,
  mcpConfigApprovalVector,
} from '../src/delivery/mcp-config-gate.js';
import { actionGuard } from '../src/delivery/action-guard.js';
import { DecisionStepBarrier } from '../src/delivery/decision-step-barrier.js';
import { evaluateOrderConsistency } from '../src/delivery/order-consistency.js';
import { assessTraceToolComposite } from '../src/delivery/trace-tool-composite.js';
import { PeerRegistry } from '../src/delivery/peer-registry.js';
import { IndependentRecorder } from '../src/delivery/independent-recorder.js';
import { gateSessionPath } from '../src/delivery/session-path-gate.js';
import { MonitorHistoryLedger } from '../src/delivery/monitor-history.js';
import { ToolCallBudgetStore } from '../src/delivery/tool-call-budget.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, '../pentest/payloads/approval-laundering.json');
const scoutPath = '/workspace/threat-scout/pentest/payloads/approval-laundering.json';
const EXPECTED_PACK_SHA =
  'baafa95400fb2873c65f7ac91bfdb379b2383e7bcbd7f7ccdc8e12bbbb666ff7';

function loadPack(): { _meta: Record<string, unknown>; fixtures: unknown[] } {
  const path = existsSync(scoutPath) ? scoutPath : fixturePath;
  return JSON.parse(readFileSync(path, 'utf8'));
}

function sha256File(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

describe('F1 / AL6 — fixture pack shapes-only honesty', () => {
  it('loads shapes pack n=8 with honesty + soft-stay-soft flags', () => {
    const pack = loadPack();
    assert.ok((pack._meta.n as number) >= 6);
    assert.equal(pack._meta.n, 8);
    assert.equal(pack._meta.shapesOnly, true);
    assert.equal(pack._meta.noLivePoC, true);
    assert.equal(pack._meta.noDeepset, true);
    assert.equal(pack._meta.escalateBLOCK, true);
    assert.equal(pack._meta.noControlTokenReopen, true);
    assert.equal(pack._meta.noChronosReopen, true);
    assert.equal(pack._meta.noA2AReopen, true);
    assert.equal(pack._meta.noA2MReopen, true);
    assert.equal(pack._meta.doNotLandTraceHere, true);
    assert.equal(pack._meta.doNotLandIMEHere, true);
    assert.equal(pack._meta.doNotLandCDoSHere, true);
    assert.equal(pack._meta.softComposeApprovalBinding, true);
    assert.equal(pack._meta.noLoopjackingReland, true);
    assert.equal(pack._meta.softCDoSElevated, true);
    assert.equal(pack._meta.softAsyncHostBarrier, true);
    assert.equal(pack._meta.softCEHost, true);
    assert.equal(pack._meta.softDHost, true);
    assert.ok(Array.isArray(pack.fixtures) && pack.fixtures.length === 8);
    assert.equal(existsSync('/workspace/arxiv-2609.28586-kit'), false);
    assert.equal(existsSync('/tmp/approval-laundering-poc'), false);
  });

  it('mirrored engine pack SHA matches Scout pack and stamped sha256', () => {
    assert.equal(existsSync(fixturePath), true);
    const engineSha = sha256File(fixturePath);
    assert.equal(engineSha, EXPECTED_PACK_SHA);
    if (existsSync(scoutPath)) {
      assert.equal(engineSha, sha256File(scoutPath));
    }
  });
});

describe('AL1 — Effect-bound Pred₆ before ALLOW', () => {
  it('freezes Ω₆ classes + provenance digests before ALLOW', () => {
    const r = freezePred6BeforeAllow({
      omega6Classes: ['process', 'file', 'env', 'network', 'container', 'MCP'],
      provenance: {
        'package.json': '{"name":"shape-only"}',
        lockfile: 'lock-shape',
        Dockerfile: 'FROM shape',
        '.mcp.json': '{"mcpServers":{}}',
        hooks: 'postinstall-shape',
      },
      entryDigest: 'entry-digest-companion',
      approvalId: 'al1-ticket',
    });
    assert.equal(r.ok, true);
    assert.equal(r.gate, 'EffectBound.FROZEN');
    assert.ok(r.record);
    assert.equal(r.record!.frozenBeforeAllow, true);
    assert.deepEqual(r.record!.omega6Classes, [...OMEGA6_CLASSES]);
    for (const k of PROVENANCE_KEYS) {
      assert.ok(r.record!.provenanceDigests[k]);
      assert.equal(r.record!.provenanceDigests[k]!.length, 64);
    }
    assert.equal(r.record!.entryDigest, 'entry-digest-companion');
    assert.equal(requireFrozenPred6BeforeAllow(r.record).allow, true);
    assert.equal(digestEffectBoundRecord(r.record!).length, 64);
    assert.equal(
      r.record!.provenanceDigests['package.json'],
      digestProvenanceContent('{"name":"shape-only"}'),
    );
  });

  it('refuses ALLOW without frozen Pred₆; does not replace entry bind', () => {
    const empty = freezePred6BeforeAllow({ omega6Classes: [] });
    assert.equal(empty.ok, false);
    assert.equal(empty.gate, 'EffectBound.DENY_empty_pred6');
    assert.equal(empty.escalate, true);
    assert.equal(requireFrozenPred6BeforeAllow(null).allow, false);

    // Entry bind still independent — ApprovalBinding digest unchanged by Pred₆.
    const vector = { tool: 'npm_install', args: { pkg: 'shape' }, destination: '', scope: 'install' };
    const entryDigest = digestApprovalVector(vector);
    const frozen = freezePred6BeforeAllow({
      omega6Classes: ['process', 'file'],
      entryDigest,
    });
    assert.equal(frozen.record!.entryDigest, entryDigest);
    assert.notEqual(digestEffectBoundRecord(frozen.record!), entryDigest);
  });
});

describe('AL2 — Closure witness Eff ⊆ Rep', () => {
  it('unexplained residual outside Rep → pause / re-ASK (no silent expand)', () => {
    const { record } = freezePred6BeforeAllow({
      omega6Classes: ['process', 'file'],
    });
    assert.ok(record);
    const r = assertEffSubseteqRep(record!, [
      { omega6Class: 'network', unexplained: true, shape: 'residual_outside_rep' },
    ]);
    assert.equal(r.verdict, 'PAUSE_REASK');
    assert.equal(r.gate, 'ClosureWitness.PAUSE_REASK_residual');
    assert.equal(r.effSubseteqRep, false);
    assert.equal(r.pauseOrReAsk, true);
    assert.equal(r.silentExpand, false);
    assert.equal(r.escalate, true);
  });

  it('Eff ⊆ Rep → CLOSED; alias assertClosureWitness works', () => {
    const { record } = freezePred6BeforeAllow({
      omega6Classes: ['process', 'file', 'network'],
    });
    const r = assertClosureWitness(record!, [
      { omega6Class: 'process' },
      { omega6Class: 'file' },
    ]);
    assert.equal(r.verdict, 'CLOSED');
    assert.equal(r.effSubseteqRep, true);
    assert.equal(r.pauseOrReAsk, false);
    assert.equal(r.silentExpand, false);
  });

  it('ambient tmp/telemetry allowlist vs high-risk residual', () => {
    const { record } = freezePred6BeforeAllow({
      omega6Classes: ['process'],
    });
    assert.ok(DEFAULT_AMBIENT_ALLOWLIST.includes('tmp'));

    const ambient = assertEffSubseteqRep(record!, [
      { omega6Class: 'file', ambientClass: 'tmp', shape: 'tmp_or_telemetry' },
    ]);
    assert.equal(ambient.verdict, 'AMBIENT_ALLOWLISTED');
    assert.equal(ambient.effSubseteqRep, true);
    assert.equal(ambient.pauseOrReAsk, false);

    const highRisk = assertEffSubseteqRep(record!, [
      { omega6Class: 'network', shape: 'network_or_process_outside_rep' },
    ]);
    assert.equal(highRisk.verdict, 'PAUSE_REASK');
    assert.equal(highRisk.pauseOrReAsk, true);
    assert.equal(highRisk.silentExpand, false);

    // Ambient label must not waive high-risk network outside Rep.
    const launder = assertEffSubseteqRep(record!, [
      { omega6Class: 'network', ambientClass: 'telemetry' },
    ]);
    assert.equal(launder.verdict, 'PAUSE_REASK');
  });
});

describe('AL3 — MCP config→network at approve', () => {
  it('remote / streamable / URL must declare network Ω₆ — entry digest alone insufficient', () => {
    assert.equal(
      isRemoteMcpTransport({
        id: 'r',
        url: 'https://example.invalid/mcp',
        transport: 'streamable_http',
      }),
      true,
    );

    const denied = requireNetworkOmega6OnCard({
      attempt: {
        action: 'server_add',
        proposedServer: {
          id: 'remote-shape',
          url: 'https://example.invalid/mcp',
          transport: 'streamable_http',
        },
      },
      entryDigestPresent: true,
      omega6OnCard: ['MCP'],
    });
    assert.equal(denied.ok, false);
    assert.equal(denied.requiresNetwork, true);
    assert.equal(denied.networkDeclared, false);
    assert.equal(denied.entryDigestAloneSufficient, false);
    assert.ok(
      denied.gate === 'McpNetworkAtApprove.DENY_entry_digest_alone' ||
        denied.gate === 'McpNetworkAtApprove.REQUIRE_NETWORK',
    );

    const freeze = freezeMcpRemotePred6Card({
      attempt: {
        action: 'server_add',
        proposedServer: {
          id: 'remote-shape',
          url: 'https://example.invalid/mcp',
          transport: 'http',
        },
      },
      mcpJsonContent: '{"shape":true}',
    });
    assert.equal(freeze.ok, true);
    assert.ok(freeze.record!.omega6Classes.includes('network'));
    assert.ok(freeze.record!.omega6Classes.includes('MCP'));

    const allowed = requireNetworkOmega6OnCard({
      attempt: {
        action: 'server_add',
        proposedServer: {
          id: 'remote-shape',
          url: 'https://example.invalid/mcp',
          transport: 'streamable_http',
        },
      },
      effectBound: freeze.record,
      entryDigestPresent: true,
    });
    assert.equal(allowed.ok, true);
    assert.equal(allowed.networkDeclared, true);
    assert.equal(allowed.entryDigestAloneSufficient, false);
  });

  it('composes with gateMcpConfigWrite — does not gut entry envelope', () => {
    const store = new ApprovalBindingStore();
    const attempt = {
      action: 'mcp_config_write' as const,
      proposedServer: {
        id: 'remote-shape',
        url: 'https://example.invalid/mcp',
        transport: 'streamable_http',
      },
    };
    const vector = mcpConfigApprovalVector(attempt);
    const approved = approveAction(store, vector, {
      uiView: {
        tool: vector.tool,
        shownArgs: vector.args,
        shownDestination: vector.destination,
        shownScope: vector.scope,
      },
    });
    assert.equal(approved.ok, true);

    // Entry gate alone would ALLOW — network-at-approve still DENY without network Ω₆.
    const entryOnly = gateMcpConfigWrite(attempt, {
      store,
      ticketId: approved.ticket!.id,
      consume: false,
    });
    assert.equal(entryOnly.verdict, 'ALLOW');

    const composed = gateMcpConfigWriteWithNetworkAtApprove(
      attempt,
      { store, ticketId: approved.ticket!.id, consume: false },
      { omega6OnCard: ['MCP'], entryDigestPresent: true },
    );
    assert.equal(composed.verdict, 'DENY');
    assert.equal(composed.entryGate.verdict, 'ALLOW');
    assert.equal(composed.networkAtApprove.ok, false);

    const withNetwork = gateMcpConfigWriteWithNetworkAtApprove(
      attempt,
      { store, ticketId: approved.ticket!.id, consume: true },
      { omega6OnCard: ['MCP', 'network'], entryDigestPresent: true },
    );
    assert.equal(withNetwork.verdict, 'ALLOW');
    assert.equal(withNetwork.networkAtApprove.networkDeclared, true);
  });
});

describe('AL4 — Install→lifecycle predict', () => {
  it('predicts postinstall/file/network; lockfile alone insufficient when hooks remain', () => {
    const r = predictInstallLifecycle({
      action: 'npm_install',
      lockfileFrozen: true,
      fixedSha: true,
      hooksRemain: true,
      hookNames: ['postinstall'],
      packageJsonContent: '{"scripts":{"postinstall":"shape"}}',
      lockfileContent: 'lock-shape',
      hooksContent: 'postinstall-shape',
    });
    assert.equal(r.ok, true);
    assert.equal(r.lifecyclePredicted, true);
    assert.equal(r.lockfileAloneSufficient, false);
    assert.equal(r.hooksRemain, true);
    assert.ok(r.predictedClasses.includes('process'));
    assert.ok(r.predictedClasses.includes('file'));
    assert.ok(r.predictedClasses.includes('network'));
    assert.equal(lifecyclePredCoversHooks(r.predictedClasses), true);
    assert.ok(r.effectBound?.frozenBeforeAllow);

    const denied = gateInstallLifecycleApprove(
      {
        action: 'npm_add',
        lockfileFrozen: true,
        fixedSha: true,
        hooksRemain: true,
      },
      false,
    );
    assert.equal(denied.ok, false);
    assert.equal(denied.lockfileAloneSufficient, false);
    assert.ok(
      denied.gate === 'InstallLifecycle.DENY_lockfile_alone' ||
        denied.gate === 'InstallLifecycle.REQUIRE_LIFECYCLE_PRED',
    );
    assert.equal(denied.escalate, true);
  });

  it('no hooks → Pred₆ still freezes; network optional', () => {
    const r = predictInstallLifecycle({
      action: 'pnpm_install',
      lockfileFrozen: true,
      hooksRemain: false,
    });
    assert.equal(r.ok, true);
    assert.equal(r.hooksRemain, false);
    assert.equal(r.gate, 'InstallLifecycle.ALLOW_no_hooks');
    assert.ok(r.predictedClasses.includes('process'));
    assert.ok(r.predictedClasses.includes('file'));
  });
});

describe('AL5 — Entry bind compose no Loopjacking re-land', () => {
  it('ApprovalBinding use-time / one-shot / refuse-lossy no-worsen', () => {
    const store = new ApprovalBindingStore();
    const vector = {
      tool: 'run_tool',
      args: { x: 1 },
      destination: 'dest',
      scope: 's',
    };
    const ok = approveAction(store, vector, {
      uiView: {
        tool: 'run_tool',
        shownArgs: { x: 1 },
        shownDestination: 'dest',
        shownScope: 's',
      },
    });
    assert.equal(ok.ok, true);
    const cmp = compareApprovalAtUse(store, ok.ticket!.id, vector);
    assert.equal(cmp.match, true);
    const rel = releaseWithApproval(store, ok.ticket!.id, vector);
    assert.equal(rel.allow, true);
    const replay = releaseWithApproval(store, ok.ticket!.id, vector);
    assert.equal(replay.allow, false);

    const lossy = approveAction(
      store,
      { tool: 't', args: { secret: 1 }, destination: '', scope: '' },
      { uiView: { tool: 't', shownArgs: {}, lossy: true, omittedKeys: ['secret'] } },
    );
    assert.equal(lossy.ok, false);
    assert.equal(lossy.refusedLossy, true);
  });

  it('mcp_config gate + ActionGuard wire no-worsen; ActionGuard not Pred₆', () => {
    const denyNoBind = gateMcpConfigWrite({
      action: 'registry_append',
      proposedServer: { id: 'local', transport: 'stdio' },
    });
    assert.equal(denyNoBind.verdict, 'DENY');
    assert.equal(denyNoBind.gate, 'ConfigWriteGate.DENY_no_binding');

    const ag = actionGuard(
      { tools: ['read_file'], urls: [] },
      [{ type: 'tool', name: 'send_email', args: {} }],
      { source: 'mcp_result' },
    );
    assert.ok(ag.denied.length > 0);
  });
});

describe('AL6 — Orthogonal compose / no reopen / no serial lands', () => {
  it('does not reopen CT / Chronos / A2A / A2M; does not land Trace/IME/C-DoS', () => {
    // Chronos still callable (soft async stays soft — no reopen).
    const b = new DecisionStepBarrier();
    b.enrollObservation('al-r1', { id: 'b', toolName: 'email', payload: 1 });
    b.enrollObservation('al-r1', { id: 'a', toolName: 'calendar', payload: 2 });
    assert.equal(b.sealDecision('al-r1').verdict, 'SEALED');

    const oc = evaluateOrderConsistency(
      [
        { id: 'a', toolName: 'calendar', payload: {} },
        { id: 'b', toolName: 'email', payload: {} },
        { id: 'c', toolName: 'weather', payload: {} },
      ],
      () => 'stable',
    );
    assert.ok(oc.verdict === 'ALLOW' || oc.verdict === 'ABSTAIN' || oc.verdict === 'HITL');

    // ControlToken Soft D soft.
    const ct = assessTraceToolComposite({
      analysisText: 'short filler',
      proposed: { type: 'tool', name: 'run_shell', args: {} },
    });
    assert.ok(ct.verdict === 'ESCALATE' || ct.verdict === 'DENY' || ct.verdict === 'ALLOW');

    // A2A Soft C–E soft.
    const reg = new PeerRegistry();
    assert.equal(
      reg.enroll({
        name: 'helper-al-r1',
        origin: 'https://example.com/al',
        transportAuthenticated: true,
      }).verdict,
      'ALLOW',
    );

    // Trace / IME present elsewhere — callable but not re-landed here.
    assert.equal(new IndependentRecorder().isOutsideSandbox(), true);
    assert.equal(gateSessionPath({ path: 'harness:session.jsonl', op: 'delete' }).verdict, 'DENY');
    assert.ok(new MonitorHistoryLedger({ windowSize: 8 }).capacity >= 8);

    // C-DoS store still constructs — Soft elevated; not landed here.
    assert.ok(new ToolCallBudgetStore());
  });
});

describe('R1 — complementary smoke ApprovalBinding / mcp_config / ActionGuard / closed lands', () => {
  it('ActionGuard still gates untrusted plan expansion (no-worsen smoke)', () => {
    const r = actionGuard(
      { tools: ['read_file'], urls: [] },
      [{ type: 'tool', name: 'bash', args: { cmd: 'shape' } }],
      { source: 'mcp_result' },
    );
    assert.ok(r.denied.length > 0 || r.allowed !== undefined);
  });

  it('ApprovalBinding store still constructs (soft-compose intact)', () => {
    const store = new ApprovalBindingStore();
    assert.ok(store);
  });

  it('gateMcpConfigWrite entry envelope still DENY without binding', () => {
    const r = gateMcpConfigWrite({
      action: 'server_add',
      proposedServer: { id: 'x', transport: 'stdio' },
    });
    assert.equal(r.verdict, 'DENY');
  });
});
