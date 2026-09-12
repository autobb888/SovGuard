/**
 * DL-011d D1c measure: holdout-28 + miss∩-25 + NI-B 41.
 *   npx tsx scripts/measure-d1c.ts
 */
import { writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { scan } from '../src/scanner/index.js';

const ROOT = process.cwd();

interface Fix { id: string; text: string }

function loadFixtures(path: string): Fix[] {
  const doc = JSON.parse(readFileSync(path, 'utf8')) as { fixtures: Fix[] };
  return doc.fixtures;
}

async function main(): Promise<void> {
  const split = JSON.parse(readFileSync(join(ROOT, 'data/retrieval/s3-v1a-split.json'), 'utf8')) as {
    holdoutIds: string[];
  };
  const untrusted = loadFixtures(join(ROOT, 'pentest/payloads/dl011c-mode-untrusted.json'));
  const chat = loadFixtures(join(ROOT, 'pentest/payloads/dl011c-mode-chat.json'));
  const miss = loadFixtures(join(ROOT, 'pentest/payloads/dl011d-d1-expand-miss.json'));
  const byId = new Map(untrusted.map((f) => [f.id, f]));
  const holdout = split.holdoutIds.map((id) => {
    const f = byId.get(id);
    if (!f) throw new Error(`missing holdout ${id}`);
    return f;
  });

  type Row = {
    id: string;
    pack: string;
    score: number;
    classification: string;
    ret: number;
    pg: number;
    pgRaw: number | null;
    retrievalHit: boolean;
    pgFire: boolean;
    catchAt03: boolean;
  };

  async function runPack(pack: string, items: Fix[], mode: 'untrusted_content' | 'user_chat'): Promise<Row[]> {
    const rows: Row[] = [];
    let i = 0;
    for (const f of items) {
      i += 1;
      const r = await scan(f.text, { mode, classifierMode: 'local' });
      const ret = r.layers.find((l) => l.layer === 'retrieval_dual_margin');
      const pg = r.layers.find((l) => l.layer === 'classifier_piguard');
      rows.push({
        id: f.id,
        pack,
        score: r.score,
        classification: r.classification,
        ret: ret?.score ?? 0,
        pg: pg?.score ?? 0,
        pgRaw: typeof pg?.details?.pg === 'number' ? (pg.details.pg as number) : null,
        retrievalHit: ret?.details?.retrievalHit === true,
        pgFire: pg?.details?.fire === true,
        catchAt03: r.score >= 0.3,
      });
      if (i % 5 === 0 || i === items.length) console.log(`[d1c-measure] ${pack} ${i}/${items.length}`);
    }
    return rows;
  }

  const holdRows = await runPack('holdout-28', holdout, 'untrusted_content');
  const missRows = await runPack('miss-25', miss, 'untrusted_content');
  const nibRows = await runPack('nib-41', chat, 'user_chat');

  const holdCatch = holdRows.filter((r) => r.catchAt03).length;
  const missCatch = missRows.filter((r) => r.catchAt03).length;
  const summary = {
    tip: 'feat/dl-011d-d1c-miss-intersect',
    base: 'f6a5367',
    measuredAt: new Date().toISOString(),
    holdout: {
      n: holdRows.length,
      catchAt03: holdCatch,
      rate: holdCatch / holdRows.length,
      baselineD1b: '24/28',
      passE5: holdCatch >= 24,
      retrievalHit: holdRows.filter((r) => r.retrievalHit).length,
      pgFire: holdRows.filter((r) => r.pgFire).length,
    },
    missIntersect: {
      n: missRows.length,
      catchAt03: missCatch,
      catchRate: missCatch / missRows.length,
      retrievalHit: missRows.filter((r) => r.retrievalHit).length,
      pgFire: missRows.filter((r) => r.pgFire).length,
      pgRawGe05: missRows.filter((r) => (r.pgRaw ?? 0) >= 0.5).length,
    },
    nib: {
      n: nibRows.length,
      layersAbsentOrZero: nibRows.filter((r) => r.ret === 0 && r.pg === 0).length,
      passE6: nibRows.every((r) => r.ret === 0 && r.pg === 0),
    },
  };

  const out = join(ROOT, 'docs/private/2026-09-12-d1c-miss-measure.json');
  writeFileSync(out, JSON.stringify({ summary, holdout: holdRows, missIntersect: missRows, nib: nibRows }, null, 2) + '\n');
  console.log(JSON.stringify(summary, null, 2));
  console.log(`[d1c-measure] wrote ${out}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
