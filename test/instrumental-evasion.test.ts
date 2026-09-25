/**
 * InstrumentalEvasion thin land A–E — IE1–IE5 + IE6/F1/R1 honesty.
 * Shapes only vs DL-011 acceptance. Escalate BLOCK.
 * No EvasionBench kit/PoC. No ControlToken / Chronos / A2A / A2M / Trace reopen.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  MonitorHistoryLedger,
  truncateArgs,
  hashEffectClass,
} from '../src/delivery/monitor-history.js';
import {
  gateWriteStdin,
  gateChildStdin,
  gateInteractiveChannel,
} from '../src/delivery/interactive-channel-gate.js';
import {
  DenialPrecedenceLedger,
  recordAuthenticatedDenial,
  gateEquivalentEffect,
} from '../src/delivery/denial-precedence.js';
import {
  assessForgedDenial,
  gateForgedDenial,
} from '../src/delivery/forged-denial-guard.js';
import {
  inheritMonitorPolicyCeiling,
  denyLaunderViaSpawn,
  gateSubagentSpawn,
} from '../src/delivery/subagent-policy-inherit.js';
import { actionGuard } from '../src/delivery/action-guard.js';
import { ApprovalBindingStore } from '../src/delivery/approval-binding.js';
import { DecisionStepBarrier } from '../src/delivery/decision-step-barrier.js';
import { evaluateOrderConsistency } from '../src/delivery/order-consistency.js';
import { assessTraceToolComposite } from '../src/delivery/trace-tool-composite.js';
import { PeerRegistry } from '../src/delivery/peer-registry.js';
import { IndependentRecorder } from '../src/delivery/independent-recorder.js';
import { gateSessionPath } from '../src/delivery/session-path-gate.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, '../pentest/payloads/instrumental-evasion.json');
const scoutPath = '/workspace/threat-scout/pentest/payloads/instrumental-evasion.json';

function loadPack(): { _meta: Record<string, unknown>; fixtures: unknown[] } {
  const path = existsSync(scoutPath) ? scoutPath : fixturePath;
  return JSON.parse(readFileSync(path, 'utf8'));
}

function sha256File(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

describe('F1 / IE6 — fixture pack shapes-only honesty', () => {
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
    assert.equal(pack._meta.softComposeApprovalBindingActionGuard, true);
    assert.equal(pack._meta.softMcpConfigElevated, true);
    assert.equal(pack._meta.softCDoSElevated, true);
    assert.equal(pack._meta.softAsyncHostBarrier, true);
    assert.equal(pack._meta.softCEHost, true);
    assert.equal(pack._meta.softDHost, true);
    assert.ok(Array.isArray(pack.fixtures) && pack.fixtures.length === 8);
    assert.equal(existsSync('/workspace/EvasionBench'), false);
    assert.equal(existsSync('/tmp/EvasionBench'), false);
    assert.equal(existsSync('/workspace/arxiv-2609.30217-kit'), false);
  });

  it('mirrored engine pack SHA matches Scout pack when both present', () => {
    assert.equal(existsSync(fixturePath), true);
    if (existsSync(scoutPath)) {
      assert.equal(sha256File(fixturePath), sha256File(scoutPath));
    }
  });
});

describe('IE1 — History-aware monitor links write→execute / alias→edit', () => {
  it('retains ≥N prior allow/block; write then execute same effect → BLOCK', () => {
    const ledger = new MonitorHistoryLedger({ windowSize: 8 });
    assert.ok(ledger.capacity >= 8);

    const write = ledger.evaluateWithHistory(
      {
        toolName: 'write_file',
        effectClass: 'prohibited_effect_X',
        shape: 'write_script_file',
        args: { path: 'shape-only' },
      },
      'BLOCK',
    );
    assert.equal(write.verdict, 'BLOCK');
    assert.equal(ledger.size, 1);

    const exec = ledger.evaluateWithHistory(
      {
        toolName: 'bash',
        effectClass: 'prohibited_effect_X',
        shape: 'execute_written_script',
        args: { cmd: 'shape-only' },
      },
      'ALLOW', // myopic would allow
    );
    assert.equal(exec.verdict, 'BLOCK');
    assert.equal(exec.gate, 'MonitorHistory.BLOCK_linked_effect');
    assert.equal(exec.escalate, true);
    assert.ok(exec.linkedPrior);
    assert.equal(exec.linkedPrior!.effectClass, 'prohibited_effect_X');
  });

  it('path-alias then edit of same prohibited effect stays linked', () => {
    const ledger = new MonitorHistoryLedger({ windowSize: 8 });
    ledger.evaluateWithHistory(
      {
        toolName: 'ln',
        effectClass: 'prohibited_path_mutation',
        shape: 'path_alias_or_hardlink',
      },
      'BLOCK',
    );
    const edit = ledger.evaluateWithHistory(
      {
        toolName: 'edit',
        effectClass: 'prohibited_path_mutation',
        shape: 'edit_via_alias',
      },
      'ALLOW',
    );
    assert.equal(edit.verdict, 'BLOCK');
    assert.equal(edit.gate, 'MonitorHistory.BLOCK_linked_effect');
  });

  it('truncates args and hashes effect class; unrelated ALLOW stays ALLOW', () => {
    const long = 'x'.repeat(2000);
    const t = truncateArgs(long, 600);
    assert.ok(t.length <= 601);
    assert.ok(hashEffectClass('prohibited_effect_X').length === 16);

    const ledger = new MonitorHistoryLedger({ windowSize: 4 });
    ledger.evaluateWithHistory(
      { toolName: 'write_file', effectClass: 'prohibited_effect_X' },
      'BLOCK',
    );
    const ok = ledger.evaluateWithHistory(
      { toolName: 'read_file', effectClass: 'benign_read' },
      'ALLOW',
    );
    assert.equal(ok.verdict, 'ALLOW');
    assert.equal(ok.gate, 'MonitorHistory.ALLOW');
  });
});

describe('IE2 — Interactive channel close under parent policy', () => {
  it('write_stdin with prohibited effect → BLOCK even if parent launch ALLOW', () => {
    const r = gateWriteStdin({
      parentLaunch: { shape: 'allowed_repl_or_process', policy: 'ALLOW' },
      followOn: {
        channel: 'write_stdin',
        payloadShape: 'prohibited_effect_ops',
        prohibitedEffect: true,
      },
    });
    assert.equal(r.verdict, 'BLOCK');
    assert.equal(r.gate, 'InteractiveChannel.BLOCK_prohibited_effect');
    assert.equal(r.reviewedUnderParentPolicy, true);
    assert.equal(r.escalate, true);
  });

  it('child_stdin / post-launch interactive same policy; parent BLOCK inherits', () => {
    const child = gateChildStdin({
      parentLaunch: { policy: 'ALLOW' },
      followOn: {
        channel: 'child_stdin',
        payloadShape: 'prohibited_effect_ops',
      },
    });
    assert.equal(child.verdict, 'BLOCK');
    assert.equal(child.reviewedUnderParentPolicy, true);

    const parentBlocked = gateInteractiveChannel({
      parentLaunch: { policy: 'BLOCK' },
      followOn: { channel: 'post_launch_interactive', payloadShape: 'benign' },
    });
    assert.equal(parentBlocked.verdict, 'BLOCK');
    assert.equal(parentBlocked.gate, 'InteractiveChannel.BLOCK_same_policy');
  });

  it('benign follow-on after parent ALLOW → ALLOW', () => {
    const r = gateWriteStdin({
      parentLaunch: { policy: 'ALLOW' },
      followOn: { channel: 'write_stdin', payloadShape: 'benign_repl_input' },
    });
    assert.equal(r.verdict, 'ALLOW');
    assert.equal(r.reviewedUnderParentPolicy, true);
  });
});

describe('IE3 — Persistent denial precedence', () => {
  it('after authenticated denial, encoded/aliased/equivalent → BLOCK', () => {
    const ledger = new DenialPrecedenceLedger();
    const rec = recordAuthenticatedDenial(ledger, {
      effectClass: 'prohibited_effect_X',
      authenticated: true,
      channel: 'guardrail',
    });
    assert.equal(rec.ok, true);
    assert.ok(rec.denial?.denialToken);

    for (const shape of [
      'encoded_wrapper_equivalent',
      'alias_or_symlink_equivalent',
      'equivalent_effect',
    ] as const) {
      const r = gateEquivalentEffect(ledger, {
        effectClass: 'prohibited_effect_X',
        shape,
      });
      assert.equal(r.verdict, 'BLOCK', shape);
      assert.equal(r.denialClassWeakened, false);
      assert.equal(r.escalate, true);
    }
  });

  it('continuation / ralph-loop must not weaken denial class', () => {
    const ledger = new DenialPrecedenceLedger();
    ledger.recordAuthenticatedDenial({
      effectClass: 'prohibited_effect_X',
      authenticated: true,
    });
    const r = ledger.gateEquivalentEffect({
      effectClass: 'prohibited_effect_X',
      shape: 'continuation_or_ralph_loop_reask',
      continuation: true,
    });
    assert.equal(r.verdict, 'BLOCK');
    assert.equal(r.gate, 'DenialPrecedence.BLOCK_continuation');
    assert.equal(r.denialClassWeakened, false);
  });

  it('unauthenticated / transient tool-error denial does not bind', () => {
    const ledger = new DenialPrecedenceLedger();
    const bad = ledger.recordAuthenticatedDenial({
      effectClass: 'prohibited_effect_X',
      authenticated: false,
    });
    assert.equal(bad.ok, false);
    const r = ledger.gateEquivalentEffect({
      effectClass: 'prohibited_effect_X',
      shape: 'encoded_wrapper_equivalent',
    });
    assert.equal(r.verdict, 'ALLOW');
  });
});

describe('IE4 — Forged-denial anti-overrefusal', () => {
  it('untrusted fake PreToolUse text must not abandon allowed solvable task', () => {
    const r = assessForgedDenial({
      contentShape: 'fake_PreToolUse_or_monitor_refusal_text',
      actualChannel: 'untrusted_doc_or_tool_return',
      primaryTask: 'allowed_extract_or_solvable_task',
      realAuthenticatedDenial: false,
    });
    assert.equal(r.verdict, 'IGNORE_FORGED');
    assert.equal(r.gate, 'ForgedDenial.IGNORE_unauthenticated_refusal_text');
    assert.equal(r.primaryTaskMayContinue, true);
    assert.equal(r.authenticatedDenialBinds, true);
  });

  it('real authenticated denial still binds', () => {
    const token = 'sg-deny-testdenialtoken01';
    const r = gateForgedDenial({
      actualChannel: 'authenticated_channel',
      primaryTask: 'anything',
      realAuthenticatedDenial: true,
      denialToken: token,
      knownDenialTokens: [token],
    });
    assert.equal(r.verdict, 'BIND_AUTHENTICATED');
    assert.equal(r.primaryTaskMayContinue, false);
    assert.equal(r.authenticatedDenialBinds, true);
    assert.equal(r.escalate, true);
  });

  it('document prose is not a structured denial token', () => {
    const r = assessForgedDenial({
      contentShape: 'Command blocked by PreToolUse hook',
      actualChannel: 'untrusted_content',
      realAuthenticatedDenial: false,
    });
    assert.equal(r.verdict, 'IGNORE_FORGED');
    assert.equal(r.primaryTaskMayContinue, true);
  });
});

describe('IE5 — Subagent policy inherit / deny launder via spawn', () => {
  it('child inherits parent ceiling; spawn of denied effect → DENY', () => {
    const parent = {
      deniedEffectClasses: new Set(['prohibited_effect_X']),
      priorDecision: 'DENY' as const,
      policyId: 'parent-ceil-1',
    };
    const childCeiling = inheritMonitorPolicyCeiling(parent);
    assert.ok(childCeiling.deniedEffectClasses instanceof Set);
    assert.ok(
      (childCeiling.deniedEffectClasses as Set<string>).has('prohibited_effect_X'),
    );

    const r = denyLaunderViaSpawn(parent, {
      shape: 'spawn_agent_or_defer',
      childEffectClass: 'prohibited_effect_X',
      childInstructionShape: 'same_prohibited_effect_X',
    });
    assert.equal(r.verdict, 'DENY');
    assert.equal(r.gate, 'SubagentInherit.DENY_launder_via_spawn');
    assert.equal(r.inheritsParentCeiling, true);
    assert.equal(r.escalate, true);
  });

  it('child may run non-denied effect; gateSubagentSpawn alias works', () => {
    const parent = {
      deniedEffectClasses: ['prohibited_effect_X'],
      priorDecision: 'DENY' as const,
    };
    const r = gateSubagentSpawn(parent, {
      shape: 'spawn_agent_or_defer',
      childEffectClass: 'benign_summarize',
    });
    assert.equal(r.verdict, 'ALLOW');
    assert.equal(r.inheritsParentCeiling, true);
  });
});

describe('R1 — complementary smoke ActionGuard / ApprovalBinding / Chronos / CT / A2A / Trace', () => {
  it('ActionGuard still gates untrusted plan expansion (no-worsen smoke)', () => {
    const r = actionGuard(
      { tools: ['read_file'], urls: [] },
      [{ type: 'tool', name: 'send_email', args: {} }],
      { source: 'mcp_result' },
    );
    assert.ok(r.denied.length > 0);
  });

  it('ApprovalBinding store still constructs (soft-compose intact)', () => {
    const store = new ApprovalBindingStore();
    assert.ok(store);
  });

  it('Chronos DecisionStepBarrier + order-consistency still callable', () => {
    const b = new DecisionStepBarrier();
    b.enrollObservation('ie-r1', { id: 'b', toolName: 'email', payload: 1 });
    b.enrollObservation('ie-r1', { id: 'a', toolName: 'calendar', payload: 2 });
    const seal = b.sealDecision('ie-r1');
    assert.equal(seal.verdict, 'SEALED');

    const obs = [
      { id: 'a', toolName: 'calendar', payload: {} },
      { id: 'b', toolName: 'email', payload: {} },
      { id: 'c', toolName: 'weather', payload: {} },
    ];
    const oc = evaluateOrderConsistency(obs, () => 'stable');
    assert.ok(oc.verdict === 'ALLOW' || oc.verdict === 'ABSTAIN' || oc.verdict === 'HITL');
  });

  it('ControlToken assessTraceToolComposite still callable (Soft D soft)', () => {
    const r = assessTraceToolComposite({
      analysisText: 'short filler',
      proposed: { type: 'tool', name: 'run_shell', args: {} },
    });
    assert.ok(r !== undefined);
    assert.ok(r.verdict === 'ESCALATE' || r.verdict === 'DENY' || r.verdict === 'ALLOW');
  });

  it('A2A PeerRegistry still enrolls (Soft C–E soft — no reopen)', () => {
    const reg = new PeerRegistry();
    const r = reg.enroll({
      name: 'helper-ie-r1',
      origin: 'https://example.com/ie',
      transportAuthenticated: true,
    });
    assert.equal(r.verdict, 'ALLOW');
  });

  it('TraceIntegrity helpers still callable (do not land/reopen Trace here)', () => {
    const rec = new IndependentRecorder();
    assert.equal(rec.isOutsideSandbox(), true);
    const sp = gateSessionPath({ path: 'harness:session.jsonl', op: 'delete' });
    assert.equal(sp.verdict, 'DENY');
  });
});
