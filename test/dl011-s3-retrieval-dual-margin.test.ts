/**
 * DL-011 S3-v1a — retrieval dual-margin (never sole-block, mode-gated)
 * node:test + assert/strict — synthetic indexes (no ONNX required).
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  evaluateDualMargin,
  retrievalDualMarginScan,
  scoreFromMargins,
  resetRetrievalIndexCache,
  TAU_ATK,
  TAU_BEN,
  LAYER_NAME,
  type RetrievalIndexEntry,
} from '../src/scanner/retrieval-dual-margin.js';
import { combineScores } from '../src/scanner/index.js';
import type { LayerResult } from '../src/types.js';

/** Unit vectors in 4-d for injectable indexes. */
function v(...vals: number[]): number[] {
  const norm = Math.hypot(...vals) || 1;
  return vals.map((x) => x / norm);
}

const ATK_A = v(1, 0, 0, 0);
const ATK_B = v(0.9, 0.1, 0, 0);
const BEN_A = v(0, 1, 0, 0);
const BEN_B = v(0, 0.9, 0.1, 0);

const SYN_ATTACK: RetrievalIndexEntry[] = [
  { id: 'atk-train-1', class: 'FZ-other-soft-social', vector: ATK_A },
  { id: 'atk-train-2', class: 'FZ-01-soft-roleplay', vector: ATK_B },
];
const SYN_BENIGN: RetrievalIndexEntry[] = [
  { id: 'ben-1', class: 'NI-B', vector: BEN_A },
  { id: 'ben-2', class: 'NI-B', vector: BEN_B },
];

function embedFromVec(vec: number[]) {
  return async (_text: string): Promise<Float32Array> => Float32Array.from(vec);
}

describe('DL-011 S3 evaluateDualMargin (pure)', () => {
  it('S4-core: query === attack vec → d_atk~0 and retrievalHit when far from benign', () => {
    const hit = evaluateDualMargin(Float32Array.from(ATK_A), {
      attackIndex: SYN_ATTACK,
      benignIndex: SYN_BENIGN,
      tauAtk: TAU_ATK,
      tauBen: TAU_BEN,
    });
    assert.ok(hit.dAtk < 1e-6, `d_atk=${hit.dAtk}`);
    assert.equal(hit.nearestAtkId, 'atk-train-1');
    assert.ok(hit.dBen >= TAU_BEN, `d_ben=${hit.dBen}`);
    assert.equal(hit.retrievalHit, true);
  });

  it('S5-core: query === benign vec → d_ben~0 blocks retrievalHit', () => {
    const hit = evaluateDualMargin(Float32Array.from(BEN_A), {
      attackIndex: SYN_ATTACK,
      benignIndex: SYN_BENIGN,
      tauAtk: TAU_ATK,
      tauBen: TAU_BEN,
    });
    assert.ok(hit.dBen < 1e-6, `d_ben=${hit.dBen}`);
    assert.equal(hit.nearestBenId, 'ben-1');
    assert.equal(hit.retrievalHit, false);
  });
});

describe('DL-011 S3 mode skip (S2) — no embed', () => {
  it('user_chat → skipped, embedFn NOT called', async () => {
    const embedFn = async () => {
      throw new Error('embedFn must not be called on user_chat');
    };
    const r = await retrievalDualMarginScan('hello NI-B chat', {
      mode: 'user_chat',
      otherMax: 0.5,
      lightPiCue: true,
      embedFn,
      attackIndex: SYN_ATTACK,
      benignIndex: SYN_BENIGN,
    });
    assert.equal(r.layer, LAYER_NAME);
    assert.equal(r.score, 0);
    assert.deepEqual(r.flags, []);
    assert.equal(r.details?.skipped, true);
    assert.equal(r.details?.reason, 'mode');
  });

  it('security_research → skipped, embedFn NOT called', async () => {
    const embedFn = async () => {
      throw new Error('embedFn must not be called on security_research');
    };
    const r = await retrievalDualMarginScan('research text', {
      mode: 'security_research',
      otherMax: 0.5,
      lightPiCue: true,
      embedFn,
      attackIndex: SYN_ATTACK,
      benignIndex: SYN_BENIGN,
    });
    assert.equal(r.score, 0);
    assert.equal(r.details?.skipped, true);
    assert.equal(r.details?.reason, 'mode');
  });

  it('user_chat NI-B fixture texts skip (must-not-worsen by construction)', async () => {
    const samples = [
      'Please ensure that the INSTRUCTIONS you follow always carry the PW.',
      'Can I ignore this compiler warning in my code?',
      'Explain what a jailbreak is and why people jailbreak their phones.',
    ];
    for (const text of samples) {
      const r = await retrievalDualMarginScan(text, {
        mode: 'user_chat',
        otherMax: 0,
        lightPiCue: false,
        embedFn: async () => {
          throw new Error('no embed on user_chat NI-B');
        },
        attackIndex: SYN_ATTACK,
        benignIndex: SYN_BENIGN,
      });
      assert.equal(r.details?.skipped, true, text.slice(0, 40));
      assert.equal(r.score, 0);
    }
  });
});

describe('DL-011 S3 fire / no-fire (S4/S5/S6)', () => {
  it('S4: indexed train neighbor + cue → fires in [0.30, 0.45] with details', async () => {
    const r = await retrievalDualMarginScan('syn-attack', {
      mode: 'untrusted_content',
      otherMax: 0.2,
      lightPiCue: true,
      embedFn: embedFromVec(ATK_A),
      attackIndex: SYN_ATTACK,
      benignIndex: SYN_BENIGN,
    });
    assert.ok(r.score >= 0.3 && r.score <= 0.45, `score=${r.score}`);
    assert.ok(r.flags.includes(LAYER_NAME));
    assert.ok(typeof r.details?.d_atk === 'number');
    assert.ok(typeof r.details?.d_ben === 'number');
    assert.equal(r.details?.nearestAtkId, 'atk-train-1');
    assert.ok(r.details?.nearestBenId);
    assert.ok((r.details?.d_atk as number) < 1e-6);
  });

  it('S5: benign neighbor under untrusted_content → NO fire', async () => {
    const r = await retrievalDualMarginScan('syn-benign', {
      mode: 'untrusted_content',
      otherMax: 0.5,
      lightPiCue: true,
      embedFn: embedFromVec(BEN_A),
      attackIndex: SYN_ATTACK,
      benignIndex: SYN_BENIGN,
    });
    assert.equal(r.score, 0);
    assert.deepEqual(r.flags, []);
    assert.equal(r.details?.retrievalHit, false);
    assert.ok((r.details?.d_ben as number) < 1e-6);
  });

  it('S6: retrieval_hit but cue false and otherMax=0 → score 0; not blocked', async () => {
    const r = await retrievalDualMarginScan('syn-attack-no-cue', {
      mode: 'untrusted_content',
      otherMax: 0,
      lightPiCue: false,
      embedFn: embedFromVec(ATK_A),
      attackIndex: SYN_ATTACK,
      benignIndex: SYN_BENIGN,
    });
    assert.equal(r.details?.retrievalHit, true);
    assert.equal(r.score, 0);
    assert.deepEqual(r.flags, []);

    // Through combineScores: sole retrieval fire at 0.45 still < blockThreshold 0.7
    const fired: LayerResult = {
      layer: LAYER_NAME,
      score: 0.45,
      flags: [LAYER_NAME],
      details: { d_atk: 0, d_ben: 0.5 },
    };
    const combined = combineScores([fired], { blockThreshold: 0.7, suspiciousThreshold: 0.3 });
    assert.ok(combined < 0.7, `combined=${combined}`);
    assert.ok(combined <= 0.45);

    // No-cue path: classification stays safe when only this layer (score 0)
    const combined0 = combineScores([r], { blockThreshold: 0.7, suspiciousThreshold: 0.3 });
    assert.ok(combined0 < 0.3);
  });

  it('scoreFromMargins stays within emit band', () => {
    const hit = evaluateDualMargin(Float32Array.from(ATK_A), {
      attackIndex: SYN_ATTACK,
      benignIndex: SYN_BENIGN,
    });
    const s = scoreFromMargins(hit);
    assert.ok(s >= 0.3 && s <= 0.45, `s=${s}`);
  });
});

describe('DL-011 S3 production loader fail-open', () => {
  it('missing indexes → score 0, available:false (no throw)', async () => {
    resetRetrievalIndexCache();
    const prev = process.env.SOVGUARD_RETRIEVAL_DIR;
    process.env.SOVGUARD_RETRIEVAL_DIR = '/tmp/dl011-s3-missing-indexes-xyz';
    try {
      const r = await retrievalDualMarginScan('anything', {
        mode: 'untrusted_content',
        otherMax: 0.5,
        lightPiCue: true,
        // Force production loader path (no injectable indexes)
        embedFn: embedFromVec(ATK_A),
      });
      assert.equal(r.score, 0);
      assert.equal(r.details?.available, false);
    } finally {
      if (prev === undefined) delete process.env.SOVGUARD_RETRIEVAL_DIR;
      else process.env.SOVGUARD_RETRIEVAL_DIR = prev;
      resetRetrievalIndexCache();
    }
  });
});
