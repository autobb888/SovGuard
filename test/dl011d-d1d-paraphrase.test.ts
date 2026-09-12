/**
 * DL-011d D1d — unique-hit train paraphrases
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
  selectTrainParaphrases,
} from '../src/scanner/attack-index-paraphrases.js';

const ROOT = process.cwd();

function v(...vals: number[]): number[] {
  const norm = Math.hypot(...vals) || 1;
  return vals.map((x) => x / norm);
}

describe('DL-011d D1d select / ingest', () => {
  it('keeps train parents and throws on holdout parent', () => {
    const picked = selectTrainParaphrases(
      [
        { id: 'deepset-10-para-d1-1', sourceId: 'deepset-10', text: 'p', forAttackIndex: true },
        { id: 'skip-train-only', sourceId: 'deepset-999', text: 'x', forAttackIndex: true },
      ],
      ['deepset-10'],
      ['deepset-547'],
    );
    assert.deepEqual(picked.map((f) => f.id), ['deepset-10-para-d1-1']);
    assert.throws(() =>
      selectTrainParaphrases(
        [{ id: 'deepset-547-para-d1-1', sourceId: 'deepset-547', text: 'h', forAttackIndex: true }],
        ['deepset-10'],
        ['deepset-547'],
      ),
    );
  });

  it('committed AttackIndex n=131 with 29 train paras and no holdout originals (E2)', () => {
    const split = JSON.parse(readFileSync(join(ROOT, 'data/retrieval/s3-v1a-split.json'), 'utf8')) as {
      holdoutIds: string[];
      trainIds: string[];
    };
    const atk = JSON.parse(readFileSync(join(ROOT, 'data/retrieval/attack-index-v1.json'), 'utf8')) as {
      entries: Array<{ id: string; source?: string; parentHoldoutId?: string; parentTrainId?: string }>;
    };
    const pack = JSON.parse(
      readFileSync(join(ROOT, 'pentest/payloads/dl011d-d1-expand-paraphrases.json'), 'utf8'),
    ) as { fixtures: Array<{ id: string; sourceId: string }> };
    assert.equal(atk.entries.length, 131);
    assert.deepEqual(holdoutOriginalsInIndex(atk.entries, split.holdoutIds), []);
    const d1d = atk.entries.filter((e) => pack.fixtures.some((f) => f.id === e.id));
    assert.equal(d1d.length, 29);
    for (const e of d1d) {
      assert.equal(e.source, 'paraphrase');
    }
    const holdoutParas = atk.entries.filter(
      (e) => e.source === 'paraphrase' && e.parentHoldoutId && split.holdoutIds.includes(e.parentHoldoutId),
    );
    assert.equal(holdoutParas.length, 36);
  });
});

describe('DL-011d D1d paraphrase retrievalHit (E7)', () => {
  const ATK = v(1, 0, 0, 0);
  const BEN = v(0, 1, 0, 0);
  it('query === unique-hit para vec + cue → retrievalHit in [0.30, 0.45]', async () => {
    const r = await retrievalDualMarginScan('paraphrase of train unique-hit', {
      mode: 'untrusted_content',
      otherMax: 0.2,
      lightPiCue: true,
      embedFn: async () => Float32Array.from(ATK),
      attackIndex: [{ id: 'deepset-10-para-d1-1', source: 'paraphrase', vector: ATK }],
      benignIndex: [{ id: 'notinject-1', vector: BEN }],
      tauAtk: TAU_ATK,
      tauBen: TAU_BEN,
    });
    assert.equal(r.layer, LAYER_NAME);
    assert.equal(r.details?.retrievalHit, true);
    assert.ok(r.score >= 0.3 && r.score <= 0.45);
    assert.equal(r.details?.nearestAtkId, 'deepset-10-para-d1-1');
  });
});

describe('DL-011d D1d bars unchanged (E3/E4)', () => {
  it('user_chat skips retrieval and PIGuard', async () => {
    const ret = await retrievalDualMarginScan('chat', {
      mode: 'user_chat',
      otherMax: 0.9,
      embedFn: async () => {
        throw new Error('no embed');
      },
      attackIndex: [{ id: 'p', vector: v(1, 0, 0, 0) }],
      benignIndex: [{ id: 'b', vector: v(0, 1, 0, 0) }],
    });
    const pg = await piguardScan('chat', {
      mode: 'user_chat',
      scoreFn: async () => {
        throw new Error('no pg');
      },
    });
    assert.equal(ret.details?.skipped, true);
    assert.equal(pg.details?.skipped, true);
    assert.equal(EMIT_MAX, 0.45);
    assert.equal(TAU_PG, 0.5);
  });
});
