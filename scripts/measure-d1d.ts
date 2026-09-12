/**
 * DL-011d D1d measure: holdout-28 + unique-hit para-29 + NI-B 41.
 *   npx tsx scripts/measure-d1d.ts
 */
import { writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { scan } from '../src/scanner/index.js';

const ROOT = process.cwd();
interface Fix { id: string; text: string }
function loadFixtures(path: string): Fix[] {
  return (JSON.parse(readFileSync(path, 'utf8')) as { fixtures: Fix[] }).fixtures;
}

async function main(): Promise<void> {
  const split = JSON.parse(readFileSync(join(ROOT, 'data/retrieval/s3-v1a-split.json'), 'utf8')) as {
    holdoutIds: string[];
  };
  const untrusted = loadFixtures(join(ROOT, 'pentest/payloads/dl011c-mode-untrusted.json'));
  const chat = loadFixtures(join(ROOT, 'pentest/payloads/dl011c-mode-chat.json'));
  const para = loadFixtures(join(ROOT, 'pentest/payloads/dl011d-d1-expand-paraphrases.json'));
  const byId = new Map(untrusted.map((f) => [f.id, f]));
  const holdout = split.holdoutIds.map((id) => {
    const f = byId.get(id);
    if (!f) throw new Error(`missing holdout ${id}`);
    return f;
  });

  type Row = {
    id: string; pack: string; score: number; classification: string;
    ret: number; pg: number; pgRaw: number | null;
    retrievalHit: boolean; pgFire: boolean; catchAt03: boolean;
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
        id: f.id, pack, score: r.score, classification: r.classification,
        ret: ret?.score ?? 0, pg: pg?.score ?? 0,
        pgRaw: typeof pg?.details?.pg === 'number' ? (pg.details.pg as number) : null,
        retrievalHit: ret?.details?.retrievalHit === true,
        pgFire: pg?.details?.fire === true,
        catchAt03: r.score >= 0.3,
      });
      if (i % 5 === 0 || i === items.length) console.log(`[d1d-measure] ${pack} ${i}/${items.length}`);
    }
    return rows;
  }

  const holdRows = await runPack('holdout-28', holdout, 'untrusted_content');
  const paraRows = await runPack('para-29', para, 'untrusted_content');
  const nibRows = await runPack('nib-41', chat, 'user_chat');
  const holdCatch = holdRows.filter((r) => r.catchAt03).length;
  const paraCatch = paraRows.filter((r) => r.catchAt03).length;
  const summary = {
    tip: 'feat/dl-011d-d1d-unique-hit-para',
    base: 'ed87a8c',
    measuredAt: new Date().toISOString(),
    holdout: {
      n: holdRows.length, catchAt03: holdCatch, rate: holdCatch / holdRows.length,
      baselineD1c: '24/28', passE5: holdCatch >= 24,
      retrievalHit: holdRows.filter((r) => r.retrievalHit).length,
      pgFire: holdRows.filter((r) => r.pgFire).length,
    },
    uniqueHitParas: {
      n: paraRows.length, catchAt03: paraCatch, catchRate: paraCatch / paraRows.length,
      retrievalHit: paraRows.filter((r) => r.retrievalHit).length,
      pgFire: paraRows.filter((r) => r.pgFire).length,
      pgRawGe05: paraRows.filter((r) => (r.pgRaw ?? 0) >= 0.5).length,
    },
    nib: {
      n: nibRows.length,
      layersAbsentOrZero: nibRows.filter((r) => r.ret === 0 && r.pg === 0).length,
      passE6: nibRows.every((r) => r.ret === 0 && r.pg === 0),
    },
  };
  const out = join(ROOT, 'docs/private/2026-09-12-d1d-unique-hit-measure.json');
  writeFileSync(out, JSON.stringify({ summary, holdout: holdRows, uniqueHitParas: paraRows, nib: nibRows }, null, 2) + '\n');
  console.log(JSON.stringify(summary, null, 2));
  console.log(`[d1d-measure] wrote ${out}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
