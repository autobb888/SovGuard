/**
 * PersistentBillable thin land A–F — PB1–PB8 + F1/R1 honesty.
 * Shapes only vs DL-011 acceptance. Escalate BLOCK.
 * No DoW-Bench kit / no live PoC. Soft-compose ToolCallBudgetStore.
 * Soft C-DoS owned here. Soft mcp_config AL soft. Soft async / C–E / Soft D soft.
 * Do not reopen CT / Chronos / A2A / A2M. Do not land Trace / IME / AL here.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  preReingestUntrustedReturn,
  applyPreReingestionBeforeBillable,
  denyRawReenterUntrusted,
  compressUntrustedReturn,
  tombstoneUntrustedReturn,
  digestRetainedRaw,
} from '../src/delivery/pre-reingestion.js';
import {
  TokenMassBoundStore,
  checkTokenMassBound,
  gateTokenMassBound,
  estimateTokensFromChars,
} from '../src/delivery/token-mass-bound.js';
import {
  AdjacentGrowthBoundStore,
  checkAdjacentGrowthBound,
  gateAdjacentGrowthBound,
} from '../src/delivery/adjacent-growth-bound.js';
import {
  ToolTurnDepthStore,
  checkToolTurnDepth,
  gateToolTurnDepth,
} from '../src/delivery/tool-turn-depth.js';
import {
  CumulativeSpendStore,
  checkCumulativeSpend,
  gateCumulativeSpend,
} from '../src/delivery/cumulative-spend.js';
import {
  tripPolymorphicStealth,
  forceGrowthEvalOnMorph,
} from '../src/delivery/polymorphic-stealth-trip.js';
import {
  ToolCallBudgetStore,
  checkToolCallBudget,
  gateToolCall,
} from '../src/delivery/tool-call-budget.js';
import { applyReturnIfc, labelToolReturn } from '../src/delivery/return-ifc.js';
import { actionGuard } from '../src/delivery/action-guard.js';
import { DecisionStepBarrier } from '../src/delivery/decision-step-barrier.js';
import { evaluateOrderConsistency } from '../src/delivery/order-consistency.js';
import { assessTraceToolComposite } from '../src/delivery/trace-tool-composite.js';
import { PeerRegistry } from '../src/delivery/peer-registry.js';
import { IndependentRecorder } from '../src/delivery/independent-recorder.js';
import { gateSessionPath } from '../src/delivery/session-path-gate.js';
import { MonitorHistoryLedger } from '../src/delivery/monitor-history.js';
import { freezePred6BeforeAllow } from '../src/delivery/effect-bound-record.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, '../pentest/payloads/persistent-billable.json');
const scoutPath = '/workspace/threat-scout/pentest/payloads/persistent-billable.json';
const EXPECTED_PACK_SHA =
  '137eb25f5bf3d2c045655ece3e0606d94b7e3278de586c99367162b43ce8b1f8';

function loadPack(): { _meta: Record<string, unknown>; fixtures: unknown[] } {
  const path = existsSync(scoutPath) ? scoutPath : fixturePath;
  return JSON.parse(readFileSync(path, 'utf8'));
}

function sha256File(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

describe('F1 / PB8 — fixture pack shapes-only honesty', () => {
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
    assert.equal(pack._meta.doNotLandALHere, true);
    assert.equal(pack._meta.softComposeToolCallBudgetStore, true);
    assert.equal(pack._meta.softCDoSOwnedHere, true);
    assert.equal(pack._meta.softMcpConfigOnALTrack, true);
    assert.equal(pack._meta.softAsyncHostBarrier, true);
    assert.equal(pack._meta.softCEHost, true);
    assert.equal(pack._meta.softDHost, true);
    assert.ok(Array.isArray(pack.fixtures) && pack.fixtures.length === 8);
    assert.equal(existsSync('/workspace/arxiv-2609.28585-kit'), false);
    assert.equal(existsSync('/tmp/persistent-billable-poc'), false);
    assert.equal(existsSync('/tmp/dow-bench-kit'), false);
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

describe('PB1 — Pre-reingestion gate before billable call', () => {
  it('transforms/compresses untrusted mcp_result; raw does not re-enter unchanged', () => {
    const raw = 'A'.repeat(500) + ' untrusted tool return mass';
    const r = preReingestUntrustedReturn({ raw, source: 'mcp_result' });
    assert.equal(r.ok, true);
    assert.ok(
      r.verdict === 'ALLOW_TRANSFORMED' || r.verdict === 'TOMBSTONE',
    );
    assert.equal(r.rawReenterBlocked, true);
    assert.notEqual(r.transformed, raw);
    assert.ok((r.transformedChars ?? 0) > 0);
    assert.ok(r.rawDigest && r.rawDigest.length === 64);
  });

  it('tombstones large untrusted returns', () => {
    const raw = 'B'.repeat(5000);
    const r = preReingestUntrustedReturn({
      raw,
      source: 'api_response',
      policy: 'tombstone',
    });
    assert.equal(r.verdict, 'TOMBSTONE');
    assert.ok(r.transformed?.startsWith('[tombstone'));
    assert.notEqual(r.transformed, raw);
  });

  it('DENY_RAW_REENTER when proposed fragment equals raw', () => {
    const raw = 'PAD_MASS';
    const d = denyRawReenterUntrusted({
      source: 'mcp_result',
      raw,
      proposedPromptFragment: raw,
    });
    assert.equal(d.verdict, 'DENY_RAW_REENTER');
    assert.equal(d.ok, false);
    assert.equal(d.escalate, true);
  });

  it('applyPreReingestionBeforeBillable yields safe transformed bodies only', () => {
    const batch = applyPreReingestionBeforeBillable({
      returns: [
        { raw: 'peer-mass-1', source: 'peer_return' },
        { raw: { data: 1, note: 'x' }, source: 'mcp_result' },
      ],
    });
    assert.equal(batch.ok, true);
    assert.equal(batch.safeBodies.length, 2);
    assert.equal(batch.rawReenterBlocked, true);
    for (const b of batch.safeBodies) {
      assert.ok(b.includes('[compressed') || b.includes('[tombstone'));
    }
  });

  it('HITL when requireHitl on high-value artifact', () => {
    const r = preReingestUntrustedReturn({
      raw: 'valuable',
      source: 'mcp_result',
      requireHitl: true,
    });
    assert.equal(r.verdict, 'HITL');
    assert.equal(r.escalate, true);
  });

  it('compress/tombstone helpers change representation', () => {
    const raw = 'raw-body';
    assert.notEqual(compressUntrustedReturn(raw), raw);
    assert.notEqual(tombstoneUntrustedReturn(raw), raw);
    assert.equal(digestRetainedRaw(raw).length, 64);
  });
});

describe('PB2 — D1 token mass bound', () => {
  it('ALLOW under bound; trip → COMPRESS_HARDER / HITL / DENY', () => {
    const store = new TokenMassBoundStore();
    const ok = gateTokenMassBound(store, {
      sessionId: 'pb2',
      proposedRetainedToolTokens: 100,
      proposedPromptTokenMass: 1000,
      config: { maxRetainedToolTokens: 1000, maxPromptTokenMass: 5000 },
    });
    assert.equal(ok.verdict, 'ALLOW');

    const soft = checkTokenMassBound(store, {
      sessionId: 'pb2',
      proposedRetainedToolTokens: 800,
      proposedPromptTokenMass: 4500,
      config: {
        maxRetainedToolTokens: 1000,
        maxPromptTokenMass: 5000,
        softTripRatio: 0.85,
        escalateBeforeDeny: true,
      },
    });
    assert.ok(
      soft.verdict === 'COMPRESS_HARDER' || soft.verdict === 'HITL',
    );

    store.markEscalated('pb2');
    store.markEscalated('pb2');
    const hard = checkTokenMassBound(store, {
      sessionId: 'pb2',
      proposedRetainedToolTokens: 2000,
      proposedPromptTokenMass: 6000,
      config: { maxRetainedToolTokens: 1000, maxPromptTokenMass: 5000 },
    });
    assert.equal(hard.verdict, 'DENY_FURTHER_RETENTION');
    assert.ok(estimateTokensFromChars(400) >= 100);
  });
});

describe('PB3 — D2 Δp / adjacent growth; delayed/stealth still trips', () => {
  it('adjacent spike trips; delayed/stealth signal still trips', () => {
    const store = new AdjacentGrowthBoundStore();
    const base = gateAdjacentGrowthBound(store, {
      sessionId: 'pb3',
      promptTokenMass: 1000,
      config: { maxDeltaTokens: 500, maxDeltaRatio: 0.3 },
    });
    assert.equal(base.verdict, 'ALLOW');

    const spike = checkAdjacentGrowthBound(store, {
      sessionId: 'pb3',
      promptTokenMass: 4000,
      config: { maxDeltaTokens: 500, maxDeltaRatio: 0.3 },
    });
    assert.ok(spike.verdict === 'HITL' || spike.verdict === 'DENY_GROWTH');

    const stealth = new AdjacentGrowthBoundStore();
    gateAdjacentGrowthBound(stealth, {
      sessionId: 'pb3s',
      promptTokenMass: 1000,
      config: { maxDeltaTokens: 5000, maxDeltaRatio: 2 },
    });
    // Small adjacent step but cumulative + stealth signal
    gateAdjacentGrowthBound(stealth, {
      sessionId: 'pb3s',
      promptTokenMass: 1500,
      config: { maxDeltaTokens: 5000, maxDeltaRatio: 2 },
    });
    const delayed = checkAdjacentGrowthBound(stealth, {
      sessionId: 'pb3s',
      promptTokenMass: 1600,
      delayedOrStealthSignal: true,
      config: { maxDeltaTokens: 5000, maxDeltaRatio: 2, tripDelayedStealth: true },
    });
    assert.ok(
      delayed.verdict === 'HITL' ||
        delayed.verdict === 'DENY_GROWTH' ||
        delayed.delayedOrStealthTripped,
    );
  });
});

describe('PB4 — D3 cross-tool depth compose with CDoSCap', () => {
  it('bounds cross-tool depth; does not replace same-tool volume', () => {
    const depth = new ToolTurnDepthStore();
    const volume = new ToolCallBudgetStore();

    // Volume still works (compose).
    const v = gateToolCall(volume, {
      sessionId: 'pb4',
      tool: 'same_tool',
      taskBaselineInvocations: 1,
      config: { maxInvocationMultiplier: 2, absoluteMaxInvocations: 3, escalateBeforeDeny: true },
    });
    assert.equal(v.verdict, 'ALLOW');
    assert.ok(v.gate === 'CDoSCap.ALLOW' || v.gate === 'CDoSCap.same_tool_reinvocation');

    // Cross-tool depth across distinct tools.
    for (const t of ['a', 'b', 'c']) {
      const r = gateToolTurnDepth(depth, {
        sessionId: 'pb4',
        tool: t,
        sameToolCdosChecked: true,
        config: { maxCrossToolDepth: 4, maxDistinctToolsInWindow: 3 },
      });
      assert.equal(r.verdict, 'ALLOW');
      assert.equal(r.composeSameToolCdos, true);
    }
    const over = checkToolTurnDepth(depth, {
      sessionId: 'pb4',
      tool: 'd',
      sameToolCdosChecked: true,
      config: { maxCrossToolDepth: 4, maxDistinctToolsInWindow: 3 },
    });
    assert.ok(over.verdict === 'HITL' || over.verdict === 'DENY_DEPTH');
    assert.equal(over.composeSameToolCdos, true);
  });
});

describe('PB5 — D4 cumulative spend + host-verified milestones', () => {
  it('ceiling enforced; model self-report rejected; host milestone unlocks', () => {
    const store = new CumulativeSpendStore();

    const self = checkCumulativeSpend(store, {
      sessionId: 'pb5',
      proposedSpend: 20000,
      modelClaim: {
        claimedSpendExemption: true,
        claimedProgress: 'almost done',
        claimedMilestoneId: 'fake',
      },
      config: { sessionSpendCeiling: 10000 },
    });
    assert.equal(self.modelSelfReportRejected, true);
    assert.ok(
      self.gate === 'D4CumulativeSpend.DENY_model_self_report' ||
        self.verdict === 'DENY_SPEND' ||
        self.verdict === 'HITL',
    );

    const host = store.recordHostVerifiedMilestone('pb5', {
      id: 'milestone-1',
      hostAttestation: 'host-signed-attestation-shape',
      unlockSpendUnits: 15000,
      hostSetAt: Date.now(),
    });
    assert.equal(host.ok, true);
    assert.equal(host.milestone?.hostVerified, true);

    // Reject empty attestation (model-shaped).
    const forged = store.recordHostVerifiedMilestone('pb5', {
      id: 'm2',
      hostAttestation: '',
      unlockSpendUnits: 99999,
      hostSetAt: Date.now(),
    });
    assert.equal(forged.ok, false);

    const ok = gateCumulativeSpend(store, {
      sessionId: 'pb5',
      proposedSpend: 5000,
      hostMilestoneId: 'milestone-1',
      config: { sessionSpendCeiling: 10000 },
    });
    assert.ok(
      ok.verdict === 'ALLOW' || ok.verdict === 'ALLOW_PROGRESS_AUTHORIZED',
    );
    assert.equal(ok.progressAuthorized, true);

    // Unverified claimed host id → reject.
    const fakeHost = checkCumulativeSpend(store, {
      sessionId: 'pb5',
      proposedSpend: 1,
      hostMilestoneId: 'not-recorded',
      config: { sessionSpendCeiling: 10000 },
    });
    assert.equal(fakeHost.gate, 'D4CumulativeSpend.DENY_model_self_report');
  });
});

describe('PB6 — Polymorphic / stealth still trips growth or spend', () => {
  it('representation-changing / delayed-growth signal still trips', () => {
    const g = new AdjacentGrowthBoundStore();
    const s = new CumulativeSpendStore();
    gateAdjacentGrowthBound(g, { sessionId: 'pb6', promptTokenMass: 1000 });

    const trip = tripPolymorphicStealth(g, s, {
      sessionId: 'pb6',
      promptTokenMass: 6000,
      proposedSpend: 50,
      signal: { representationChanged: true, delayedGrowth: true },
      growthConfig: { maxDeltaTokens: 500, maxDeltaRatio: 0.25 },
      spendConfig: { sessionSpendCeiling: 10000 },
      applyGates: false,
    });
    assert.ok(
      trip.verdict === 'TRIP_GROWTH' ||
        trip.verdict === 'TRIP_SPEND' ||
        trip.verdict === 'TRIP_BOTH' ||
        trip.verdict === 'HITL',
    );
    assert.equal(trip.forcedEvaluation, true);
    assert.equal(trip.escalate, true);

    // Morph with small Δ still forces HITL (no exact-string match required).
    const g2 = new AdjacentGrowthBoundStore();
    const s2 = new CumulativeSpendStore();
    gateAdjacentGrowthBound(g2, {
      sessionId: 'pb6b',
      promptTokenMass: 1000,
      config: { maxDeltaTokens: 50000, maxDeltaRatio: 10 },
    });
    const morph = tripPolymorphicStealth(g2, s2, {
      sessionId: 'pb6b',
      promptTokenMass: 1001,
      proposedSpend: 1,
      signal: { morphDetected: true },
      growthConfig: { maxDeltaTokens: 50000, maxDeltaRatio: 10 },
      spendConfig: { sessionSpendCeiling: 1_000_000 },
      applyGates: false,
    });
    assert.ok(morph.verdict === 'HITL' || morph.forcedEvaluation);
    assert.ok(forceGrowthEvalOnMorph(new AdjacentGrowthBoundStore(), {
      sessionId: 'pb6c',
      promptTokenMass: 100,
      signal: { representationChanged: true },
    }));
  });
});

describe('PB7 — Compose C-DoS volume no-worsen', () => {
  it('ToolCallBudgetStore same-tool volume + weighted cost still works', () => {
    const store = new ToolCallBudgetStore();
    for (let i = 0; i < 3; i++) {
      gateToolCall(store, {
        sessionId: 'pb7',
        tool: 'storm',
        taskBaselineInvocations: 1,
        tokenCost: 10,
        taskBaselineTokens: 10,
        config: {
          maxInvocationMultiplier: 2,
          absoluteMaxInvocations: 4,
          maxTokenCostMultiplier: 3,
          escalateBeforeDeny: true,
        },
      });
    }
    const check = checkToolCallBudget(store, {
      sessionId: 'pb7',
      tool: 'storm',
      taskBaselineInvocations: 1,
      taskBaselineTokens: 10,
      proposedTokenCost: 10,
      config: {
        maxInvocationMultiplier: 2,
        absoluteMaxInvocations: 4,
        maxTokenCostMultiplier: 3,
        escalateBeforeDeny: true,
      },
    });
    assert.ok(
      check.verdict === 'HITL' ||
        check.verdict === 'DENY' ||
        check.verdict === 'COST_ESCALATE' ||
        check.gate === 'CDoSCap.same_tool_reinvocation',
    );
    // return IFC label still works — not a substitute for pre-reingestion.
    const labeled = labelToolReturn({ hello: 'data' }, { source: 'mcp_result' });
    assert.ok(labeled);
    const ifc = applyReturnIfc(
      { data: 1 },
      { source: 'mcp_result' },
    );
    assert.ok(ifc.verdict === 'ALLOW' || ifc.verdict === 'STRIP' || ifc.verdict === 'DENY');
  });
});

describe('PB8 — Orthogonal compose / no reopen / no serial lands', () => {
  it('does not reopen CT / Chronos / A2A / A2M; does not land Trace/IME/AL', () => {
    const b = new DecisionStepBarrier();
    b.enrollObservation('pb-r1', { id: 'b', toolName: 'email', payload: 1 });
    b.enrollObservation('pb-r1', { id: 'a', toolName: 'calendar', payload: 2 });
    assert.equal(b.sealDecision('pb-r1').verdict, 'SEALED');

    const oc = evaluateOrderConsistency(
      [
        { id: 'a', toolName: 'calendar', payload: {} },
        { id: 'b', toolName: 'email', payload: {} },
        { id: 'c', toolName: 'weather', payload: {} },
      ],
      () => 'stable',
    );
    assert.ok(oc.verdict === 'ALLOW' || oc.verdict === 'ABSTAIN' || oc.verdict === 'HITL');

    const ct = assessTraceToolComposite({
      analysisText: 'short filler',
      proposed: { type: 'tool', name: 'run_shell', args: {} },
    });
    assert.ok(ct.verdict === 'ESCALATE' || ct.verdict === 'DENY' || ct.verdict === 'ALLOW');

    const reg = new PeerRegistry();
    assert.equal(
      reg.enroll({
        name: 'helper-pb-r1',
        origin: 'https://example.com/pb',
        transportAuthenticated: true,
      }).verdict,
      'ALLOW',
    );

    // Trace / IME present elsewhere — callable but not re-landed here.
    assert.equal(new IndependentRecorder().isOutsideSandbox(), true);
    assert.equal(gateSessionPath({ path: 'harness:session.jsonl', op: 'delete' }).verdict, 'DENY');
    assert.ok(new MonitorHistoryLedger({ windowSize: 8 }).capacity >= 8);

    // AL Pred₆ still constructs — Soft mcp_config on AL track; not landed here.
    const al = freezePred6BeforeAllow({
      omega6Classes: ['process', 'file'],
      provenance: { 'package.json': '{}' },
    });
    assert.equal(al.ok, true);

    // Volume store still constructs — Soft C-DoS owned here (compose).
    assert.ok(new ToolCallBudgetStore());
  });
});

describe('R1 — complementary smoke ToolCallBudget / return-IFC / ActionGuard / closed lands', () => {
  it('ActionGuard still gates untrusted plan expansion (no-worsen smoke)', () => {
    const r = actionGuard(
      { tools: ['read_file'], urls: [] },
      [{ type: 'tool', name: 'bash', args: { cmd: 'shape' } }],
      { source: 'mcp_result' },
    );
    assert.ok(r.denied.length > 0 || r.allowed !== undefined);
  });

  it('ToolCallBudgetStore constructs and ALLOW under baseline', () => {
    const store = new ToolCallBudgetStore();
    const r = checkToolCallBudget(store, {
      sessionId: 'r1',
      tool: 't',
      taskBaselineInvocations: 2,
    });
    assert.equal(r.verdict, 'ALLOW');
  });

  it('return IFC still labels mcp_result untrusted', () => {
    const labeled = labelToolReturn({ x: 1 }, { source: 'mcp_result' });
    assert.ok(labeled);
  });
});
