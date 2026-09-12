/**
 * DL-011d D1c — miss∩ expand: holdout refuse + coverage idempotent.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { retrievalDualMarginScan } from '../src/scanner/retrieval-dual-margin.js';
import { piguardScan, EMIT_MAX, TAU_PG } from '../src/scanner/classifier-piguard.js';
import { holdoutOriginalsInIndex } from '../src/scanner/attack-index-paraphrases.js';
import {
  selectTrainMissIntersect,
  holdoutMissIdsInIndex,
} from '../src/scanner/attack-index-miss.js';

const ROOT = process.cwd();

describe('DL-011d D1c miss∩ select / refuse', () => {
  it('keeps train parents and refuses holdout originals (E2/E7)', () => {
    const split = { trainIds: ['deepset-158'], holdoutIds: ['deepset-547'] };
    const { train, refusedHoldout } = selectTrainMissIntersect(
      [
        { id: 'deepset-158-miss', sourceId: 'deepset-158', text: 't', forAttackIndex: true },
        { id: 'deepset-547-miss', sourceId: 'deepset-547', text: 'h', forAttackIndex: true },
        { id: 'deepset-547', sourceId: 'deepset-547', text: 'orig', forAttackIndex: true },
      ],
      split.trainIds,
      split.holdoutIds,
    );
    assert.deepEqual(train.map((f) => f.sourceId), ['deepset-158']);
    assert.deepEqual(refusedHoldout.map((f) => f.id).sort(), ['deepset-547', 'deepset-547-miss']);
  });

  it('committed AttackIndex: train-11 present, holdout originals and *-miss holdout ids absent', () => {
    const split = JSON.parse(readFileSync(join(ROOT, 'data/retrieval/s3-v1a-split.json'), 'utf8')) as {
      trainIds: string[];
      holdoutIds: string[];
    };
    const atk = JSON.parse(readFileSync(join(ROOT, 'data/retrieval/attack-index-v1.json'), 'utf8')) as {
      entries: Array<{ id: string; source?: string }>;
    };
    const pack = JSON.parse(
      readFileSync(join(ROOT, 'pentest/payloads/dl011d-d1-expand-miss.json'), 'utf8'),
    ) as { fixtures: Array<{ id: string; sourceId: string; forAttackIndex?: boolean }> };
    const { train, refusedHoldout } = selectTrainMissIntersect(
      pack.fixtures,
      split.trainIds,
      split.holdoutIds,
    );
    assert.equal(train.length, 11);
    assert.equal(refusedHoldout.length, 14);
    const ids = new Set(atk.entries.map((e) => e.id));
    for (const f of train) assert.ok(ids.has(f.sourceId), `missing train ${f.sourceId}`);
    assert.deepEqual(holdoutOriginalsInIndex(atk.entries, split.holdoutIds), []);
    assert.deepEqual(holdoutMissIdsInIndex(atk.entries, split.holdoutIds), []);
    assert.ok(atk.entries.length >= 102, `n=${atk.entries.length}`);
  });
});

describe('DL-011d D1c bars unchanged (E3/E4)', () => {
  it('user_chat skips retrieval and PIGuard', async () => {
    const ret = await retrievalDualMarginScan('chat', {
      mode: 'user_chat',
      otherMax: 0.9,
      lightPiCue: true,
      embedFn: async () => {
        throw new Error('no embed');
      },
      attackIndex: [{ id: 'p', vector: [1, 0, 0, 0] }],
      benignIndex: [{ id: 'b', vector: [0, 1, 0, 0] }],
    });
    const pg = await piguardScan('chat', {
      mode: 'user_chat',
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
