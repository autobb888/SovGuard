/**
 * ChronosAttack / Tool Order thin land A–C — CH1–CH4 + honesty/CH6.
 * Shapes only vs DL-011 acceptance. Escalate BLOCK.
 * No ChronosAttack kit. No A2M / ControlToken reopen.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DecisionStepBarrier,
  canonicalToolOrder,
  serializeCanonical,
} from '../src/delivery/decision-step-barrier.js';
import type { ToolObservation } from '../src/delivery/decision-step-barrier.js';
import {
  evaluateOrderConsistency,
  permutations,
} from '../src/delivery/order-consistency.js';
import { SessionScorer } from '../src/scanner/session-scorer.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, '../pentest/payloads/chronos-tool-order.json');
const scoutPath = '/workspace/threat-scout/pentest/payloads/chronos-tool-order.json';

function loadPack(): { _meta: Record<string, unknown>; fixtures: unknown[] } {
  const path = existsSync(scoutPath) ? scoutPath : fixturePath;
  return JSON.parse(readFileSync(path, 'utf8'));
}

/** Order-sensitive oracle: first tool in presentation wins (simulates Chronos shift). */
function decideFirstWins(order: ToolObservation[]): string {
  return `prefer:${order[0]?.toolName ?? 'none'}`;
}

/** Order-stable oracle: always prefer calendar if present else first by canonical. */
function decideStable(order: ToolObservation[]): string {
  const names = order.map((o) => o.toolName);
  if (names.includes('calendar')) return 'prefer:calendar';
  return `prefer:${[...names].sort()[0]}`;
}

/** Privileged choice from auth_check + xfer — barrier canonical must preserve. */
function decidePrivileged(order: ToolObservation[]): string {
  const byName = Object.fromEntries(order.map((o) => [o.toolName, o]));
  if (byName['auth_check']?.payload && (byName['auth_check'].payload as { ok?: boolean }).ok) {
    return 'ALLOW_xfer';
  }
  return 'DENY_xfer';
}

describe('Chronos F1 — fixture pack shapes', () => {
  it('loads shapes pack with n≥6 and honesty flags', () => {
    const pack = loadPack();
    assert.ok((pack._meta.n as number) >= 6);
    assert.equal(pack._meta.shapesOnly, true);
    assert.ok(
      pack._meta.noChronosAttackKit === true || pack._meta.noChronosAttackKitClone === true,
      'honesty: no ChronosAttack kit flag',
    );
    assert.equal(pack._meta.escalateBLOCK, true);
    assert.equal(pack._meta.noDeepset, true);
    assert.ok(Array.isArray(pack.fixtures) && pack.fixtures.length >= 6);
    // Honesty: no kit path cloned into workspace
    assert.equal(existsSync('/workspace/ChronosAttack'), false);
    assert.equal(existsSync('/tmp/ChronosAttack'), false);
  });
});

describe('CH1 — Decision-step barrier / canonical tool order', () => {
  it('buffers peers; serialization is canonical not arrival', () => {
    const barrier = new DecisionStepBarrier();
    const decisionId = 'dec-ch1';
    // Inverted arrival: weather, calendar, email
    const arrivals: ToolObservation[] = [
      { id: 'obs-c', toolName: 'weather', payload: { temp: 72 }, arrivedAt: 300 },
      { id: 'obs-a', toolName: 'calendar', payload: { busy: false }, arrivedAt: 100 },
      { id: 'obs-b', toolName: 'email', payload: { unread: 0 }, arrivedAt: 200 },
    ];
    for (const obs of arrivals) {
      const r = barrier.enrollObservation(decisionId, obs);
      assert.equal(r.verdict, 'BUFFERED');
    }
    const arrivalIds = barrier.getArrivalOrder(decisionId).map((o) => o.toolName);
    assert.deepEqual(arrivalIds, ['weather', 'calendar', 'email']);

    const seal = barrier.sealDecision(decisionId);
    assert.equal(seal.verdict, 'SEALED');
    assert.deepEqual(
      seal.canonicalOrder.map((o) => o.toolName),
      ['calendar', 'email', 'weather'],
    );

    const ser = barrier.serializeForModel(decisionId);
    assert.equal(ser.sealed, true);
    assert.equal(ser.serialized, 'calendar::obs-a|email::obs-b|weather::obs-c');
    assert.notEqual(
      ser.serialized,
      serializeCanonical(
        // would-be arrival serialization
        arrivals,
      ).split('|').length === 3 && arrivals.map((o) => `${o.toolName}::${o.id}`).join('|')
        ? arrivals.map((o) => `${o.toolName}::${o.id}`).join('|')
        : '',
    );
    // Explicit: model serialization ≠ arrival order string
    const arrivalSer = arrivals.map((o) => `${o.toolName}::${o.id}`).join('|');
    assert.notEqual(ser.serialized, arrivalSer);
  });

  it('rejects enroll after seal (late obs → order-flip path, not barrier rewrite)', () => {
    const barrier = new DecisionStepBarrier();
    barrier.enrollObservation('dec-late', {
      id: 'a',
      toolName: 'alpha',
      payload: 1,
    });
    barrier.sealDecision('dec-late');
    const late = barrier.enrollObservation('dec-late', {
      id: 'b',
      toolName: 'beta',
      payload: 2,
    });
    assert.equal(late.verdict, 'DENY');
    assert.equal(late.gate, 'DecisionStepBarrier.DENY_sealed');
  });
});

describe('CH2 — Order-consistency abstain / HITL', () => {
  const three: ToolObservation[] = [
    { id: 'a', toolName: 'calendar', payload: {} },
    { id: 'b', toolName: 'email', payload: {} },
    { id: 'c', toolName: 'weather', payload: {} },
  ];

  it('m=3 yields 6 permutations', () => {
    assert.equal(permutations(three).length, 6);
  });

  it('order-sensitive decide → maxVotes <4 → HITL/ABSTAIN', () => {
    const r = evaluateOrderConsistency(three, decideFirstWins);
    assert.ok(r.permutationCount === 6);
    // first-wins across 6 perms: each tool appears first in 2 perms → max=2 <4
    assert.ok(r.maxVotes < 4);
    assert.ok(r.verdict === 'HITL' || r.verdict === 'ABSTAIN');
    assert.match(r.gate, /below_threshold/);
  });

  it('order-stable decide → ALLOW with ≥4/6', () => {
    const r = evaluateOrderConsistency(three, decideStable);
    assert.equal(r.verdict, 'ALLOW');
    assert.equal(r.gate, 'OrderConsistency.ALLOW_majority');
    assert.ok(r.maxVotes >= 4);
    assert.equal(r.choice, 'prefer:calendar');
  });
});

describe('CH3 — SessionScorer flip-after-late-obs escalate', () => {
  it('provisional flip after delayed authentic obs → escalate', () => {
    const scorer = new SessionScorer();
    scorer.recordProvisionalChoice('sess-ch3', 'dec-ch3', 'approve_transfer');
    const flip = scorer.observeLateAuthentic('sess-ch3', 'dec-ch3', 'deny_transfer');
    assert.equal(flip.flipped, true);
    assert.equal(flip.escalated, true);
    assert.equal(flip.signal, 'OrderFlip.ESCALATE_flip_after_late_obs');
    assert.equal(scorer.check('sess-ch3').escalated, true);
    scorer.stopPruneTimer();
  });

  it('no flip when late obs agrees with provisional → no escalate from flip', () => {
    const scorer = new SessionScorer();
    scorer.recordProvisionalChoice('sess-ch3b', 'dec-ch3b', 'approve_transfer');
    const same = scorer.observeLateAuthentic('sess-ch3b', 'dec-ch3b', 'approve_transfer');
    assert.equal(same.flipped, false);
    assert.equal(same.signal, 'OrderFlip.none');
    assert.equal(scorer.check('sess-ch3b').escalated, false);
    scorer.stopPruneTimer();
  });
});

describe('CH4 — Pairwise inversion with barrier on does not flip privileged choice', () => {
  it('natural vs inverted arrival → same ALLOW_xfer under canonical barrier', () => {
    const natural: ToolObservation[] = [
      { id: 'obs-pin', toolName: 'auth_check', payload: { ok: true } },
      { id: 'obs-act', toolName: 'xfer', payload: { amt: 1 } },
    ];
    const inverted: ToolObservation[] = [
      { id: 'obs-act', toolName: 'xfer', payload: { amt: 1 } },
      { id: 'obs-pin', toolName: 'auth_check', payload: { ok: true } },
    ];

    function viaBarrier(decisionId: string, arrivals: ToolObservation[]): string {
      const b = new DecisionStepBarrier();
      for (const o of arrivals) b.enrollObservation(decisionId, o);
      b.sealDecision(decisionId);
      return decidePrivileged(b.getCanonicalOrder(decisionId));
    }

    const cNat = viaBarrier('dec-ch4-n', natural);
    const cInv = viaBarrier('dec-ch4-i', inverted);
    assert.equal(cNat, 'ALLOW_xfer');
    assert.equal(cInv, 'ALLOW_xfer');
    assert.deepEqual(
      canonicalToolOrder(natural).map((o) => o.id),
      canonicalToolOrder(inverted).map((o) => o.id),
    );
  });
});

describe('CH6 — Honesty / no kit', () => {
  it('pack declares shapes-only + escalate BLOCK + no kit', () => {
    const pack = loadPack();
    assert.equal(pack._meta.shapesOnly, true);
    assert.ok(
      pack._meta.noChronosAttackKit === true || pack._meta.noChronosAttackKitClone === true,
    );
    assert.equal(pack._meta.escalateBLOCK, true);
    assert.equal(pack._meta.noA2MReopen, true);
    assert.equal(pack._meta.noControlTokenReopen, true);
  });
});
