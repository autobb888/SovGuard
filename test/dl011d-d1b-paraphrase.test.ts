/**
 * DL-011d D1b — paraphrase AttackIndex expand
 * node:test + assert/strict — synthetic indexes (no ONNX required) plus
 * leakage check on the committed frozen index.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  evaluateDualMargin,
  retrievalDualMarginScan,
  LAYER_NAME,
  TAU_ATK,
  TAU_BEN,
} from '../src/scanner/retrieval-dual-margin.js';
import { piguardScan, EMIT_MAX, TAU_PG } from '../src/scanner/classifier-piguard.js';
import {
  holdoutOriginalsInIndex,
  selectParaphrases,
} from '../src/scanner/attack-index-paraphrases.js';

const ROOT = process.cwd();

function v(...vals: number[]): number[] {
  const norm = Math.hypot(...vals) || 1;
  return vals.map((x) => x / norm);
}

describe('DL-011d D1b select / leakage', () => {
  it('keeps holdout-parent paraphrases and drops train-parent ones', () => {
    const hold = ['deepset-69'];
    const picked = selectParaphrases(
      [
        { id: 'deepset-69-para-holdout-1', sourceId: 'deepset-69', text: 'p', forAttackIndex: true },
        { id: 'deepset-10-para-train-1', sourceId: 'deepset-10', text: 't', forAttackIndex: true },
        { id: 'skip-me', sourceId: 'deepset-69', text: 'x', forAttackIndex: false },
      ],
      hold,
    );
    assert.deepEqual(picked.map((f) => f.id), ['deepset-69-para-holdout-1']);
  });

  it('throws if a paraphrase id collides with a holdout original', () => {
    assert.throws(() =>
      selectParaphrases(
        [{ id: 'deepset-69', sourceId: 'deepset-69', text: 'x', forAttackIndex: true }],
        ['deepset-69'],
      ),
    );
  });

  it('committed AttackIndex has paraphrase entries and no holdout originals (E2)', () => {
    const split = JSON.parse(readFileSync(join(ROOT, 'data/retrieval/s3-v1a-split.json'), 'utf8')) as {
      holdoutIds: string[];
    };
    const atk = JSON.parse(readFileSync(join(ROOT, 'data/retrieval/attack-index-v1.json'), 'utf8')) as {
      entries: Array<{ id: string; source?: string; parentHoldoutId?: string; vector?: number[] }>;
    };
    assert.deepEqual(holdoutOriginalsInIndex(atk.entries, split.holdoutIds), []);
    const paras = atk.entries.filter((e) => e.source === 'paraphrase');
    const holdoutParas = paras.filter((e) => e.parentHoldoutId && split.holdoutIds.includes(e.parentHoldoutId));
    assert.equal(holdoutParas.length, 36);
    assert.ok(paras.length >= 36);
    for (const p of holdoutParas) {
      assert.ok(p.parentHoldoutId && split.holdoutIds.includes(p.parentHoldoutId), p.id);
      assert.ok(Array.isArray(p.vector) && p.vector.length > 0, p.id);
    }
    for (const p of paras) {
      assert.ok(Array.isArray(p.vector) && p.vector.length > 0, p.id);
    }
  });
});

describe('DL-011d D1b paraphrase retrievalHit (E7)', () => {
  const ATK = v(1, 0, 0, 0);
  const BEN = v(0, 1, 0, 0);

  it('query === paraphrase vec + cue → retrievalHit in [0.30, 0.45]', async () => {
    const r = await retrievalDualMarginScan('paraphrase of holdout flat', {
      mode: 'untrusted_content',
      otherMax: 0.2,
      lightPiCue: true,
      embedFn: async () => Float32Array.from(ATK),
      attackIndex: [
        {
          id: 'deepset-69-para-holdout-1',
          source: 'paraphrase',
          parentHoldoutId: 'deepset-69',
          vector: ATK,
        },
      ],
      benignIndex: [{ id: 'notinject-1', vector: BEN }],
      tauAtk: TAU_ATK,
      tauBen: TAU_BEN,
    });
    assert.equal(r.layer, LAYER_NAME);
    assert.equal(r.details?.retrievalHit, true);
    assert.ok(r.score >= 0.3 && r.score <= 0.45, `score=${r.score}`);
    assert.equal(r.details?.nearestAtkId, 'deepset-69-para-holdout-1');
  });

  it('pure evaluate: paraphrase neighbor far from benign fires', () => {
    const hit = evaluateDualMargin(Float32Array.from(ATK), {
      attackIndex: [{ id: 'p1', vector: ATK }],
      benignIndex: [{ id: 'b1', vector: BEN }],
    });
    assert.equal(hit.retrievalHit, true);
    assert.equal(hit.nearestAtkId, 'p1');
  });
});

describe('DL-011d D1b bars unchanged (E3/E4)', () => {
  it('user_chat skips retrieval and PIGuard (no embed / no infer)', async () => {
    const ret = await retrievalDualMarginScan('chat', {
      mode: 'user_chat',
      otherMax: 0.9,
      lightPiCue: true,
      embedFn: async () => {
        throw new Error('no embed');
      },
      attackIndex: [{ id: 'p', vector: v(1, 0, 0, 0) }],
      benignIndex: [{ id: 'b', vector: v(0, 1, 0, 0) }],
    });
    const pg = await piguardScan('chat', {
      mode: 'user_chat',
      lightPiCue: true,
      scoreFn: async () => {
        throw new Error('no pg');
      },
    });
    assert.equal(ret.details?.skipped, true);
    assert.equal(pg.details?.skipped, true);
    assert.equal(ret.score, 0);
    assert.equal(pg.score, 0);
  });

  it('PIGuard emit cap and τ_pg unchanged', () => {
    assert.equal(EMIT_MAX, 0.45);
    assert.equal(TAU_PG, 0.5);
  });
});
