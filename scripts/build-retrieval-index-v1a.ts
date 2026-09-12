/**
 * Build frozen AttackIndex / BenignIndex for DL-011 S3-v1a + D1b paraphrases + D1c miss∩.
 *
 * Usage (from sovguard repo root, MiniLM present):
 *   npx tsx scripts/build-retrieval-index-v1a.ts
 *
 * D1b: reuses train + paraphrase vectors (no re-embed jitter).
 * D1c: tags train miss∩ as source=miss_intersect; REFUSES holdout originals / *-miss holdout ids.
 * Unique-hit paraphrases (29) are out of scope.
 */

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { embedText, isEmbeddingModelAvailable } from '../src/scanner/semantic.js';
import { TAU_ATK, TAU_BEN } from '../src/scanner/retrieval-dual-margin.js';
import {
  selectParaphrases,
  holdoutOriginalsInIndex,
  type ParaFixture,
} from '../src/scanner/attack-index-paraphrases.js';
import {
  selectTrainMissIntersect,
  holdoutMissIdsInIndex,
  type MissFixture,
} from '../src/scanner/attack-index-miss.js';

const ROOT = process.cwd();
const OUT_DIR = process.env.SOVGUARD_RETRIEVAL_DIR || join(ROOT, 'data', 'retrieval');

interface FixtureFile {
  fixtures: Array<{ id: string; class?: string; text: string }>;
}

interface SplitFile {
  version: string;
  baseTip: string;
  trainIds: string[];
  holdoutIds: string[];
  benignIds: string[];
}

interface AttackEntry {
  id: string;
  class?: string;
  text?: string;
  source?: string;
  parentHoldoutId?: string;
  vector: number[];
}

function loadJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, 'utf8')) as T;
}

function checksumEntries(entries: Array<{ id: string; vector: number[] }>): string {
  const parts = [...entries]
    .sort((a, b) => a.id.localeCompare(b.id))
    .map((e) => `${e.id}:${e.vector.slice(0, 8).map((x) => x.toFixed(6)).join(',')}`);
  return createHash('sha256').update(parts.join('|')).digest('hex');
}

async function embedIds(
  ids: string[],
  byId: Map<string, { id: string; class?: string; text: string }>,
): Promise<AttackEntry[]> {
  const out: AttackEntry[] = [];
  for (const id of ids) {
    const f = byId.get(id);
    if (!f) {
      console.warn(`[build-index] missing fixture id=${id}`);
      continue;
    }
    const vec = await embedText(f.text);
    if (!vec) throw new Error(`embed failed for ${id}`);
    out.push({ id: f.id, class: f.class, text: f.text, vector: Array.from(vec) });
    if (out.length % 10 === 0) console.log(`[build-index] embedded ${out.length}/${ids.length}`);
  }
  return out;
}

function loadExistingAttack(): AttackEntry[] {
  const path = join(OUT_DIR, 'attack-index-v1.json');
  if (!existsSync(path)) return [];
  try {
    const doc = loadJson<{ entries: Array<Partial<AttackEntry>> }>(path);
    return (doc.entries ?? []).filter(
      (e): e is AttackEntry => !!e.id && Array.isArray(e.vector) && e.vector.length > 0,
    ) as AttackEntry[];
  } catch {
    return [];
  }
}

function reuseTrainVectors(trainIds: string[], existing: AttackEntry[]): AttackEntry[] | null {
  const byId = new Map<string, AttackEntry>();
  for (const e of existing) {
    if (!trainIds.includes(e.id)) continue;
    byId.set(e.id, {
      id: e.id,
      class: e.class,
      text: e.text,
      source: e.source,
      parentHoldoutId: e.parentHoldoutId,
      vector: e.vector,
    });
  }
  if (byId.size !== trainIds.length) {
    console.warn(`[build-index] reuse miss: have ${byId.size}/${trainIds.length} train vectors`);
    return null;
  }
  console.log(`[build-index] reusing ${byId.size} existing train vectors (no re-embed)`);
  return trainIds.map((id) => byId.get(id)!);
}

function reuseParaphrases(existing: AttackEntry[]): AttackEntry[] | null {
  const paras = existing.filter((e) => e.source === 'paraphrase');
  if (paras.length === 36) {
    console.log(`[build-index] reusing ${paras.length} existing paraphrase vectors (no re-embed)`);
    return paras;
  }
  return null;
}

function reuseBenign(benignIds: string[]): AttackEntry[] | null {
  const path = join(OUT_DIR, 'benign-index-v1.json');
  if (!existsSync(path)) return null;
  try {
    const doc = loadJson<{ entries: Array<Partial<AttackEntry>> }>(path);
    const keep = (doc.entries ?? []).filter(
      (e): e is AttackEntry =>
        !!e.id && benignIds.includes(e.id) && Array.isArray(e.vector) && e.vector.length > 0,
    ) as AttackEntry[];
    if (keep.length !== benignIds.length) return null;
    console.log(`[build-index] reusing ${keep.length} existing benign vectors`);
    return keep;
  } catch {
    return null;
  }
}

function suggestTaus(attack: AttackEntry[], benign: AttackEntry[]): void {
  function cos(a: number[], b: number[]): number {
    let d = 0;
    for (let i = 0; i < a.length; i++) d += a[i] * b[i];
    return d;
  }
  let minCross = Infinity;
  for (const a of attack) {
    for (const b of benign) {
      const dist = 1 - cos(a.vector, b.vector);
      if (dist < minCross) minCross = dist;
    }
  }
  console.log('[build-index] suggested τ (train-tuned defaults already frozen):');
  console.log(`  TAU_ATK=${TAU_ATK} (sim≥${(1 - TAU_ATK).toFixed(2)}); train self-distance=0`);
  console.log(`  TAU_BEN=${TAU_BEN}; min attack↔benign train distance=${minCross.toFixed(4)}`);
  console.log('  Keep τ_ben below min cross-distance to preserve the FP fence.');
}

async function embedParaphrases(split: SplitFile): Promise<AttackEntry[]> {
  const paraPath = join(ROOT, 'pentest/payloads/s3-attackindex-paraphrases.json');
  if (!existsSync(paraPath)) {
    console.warn('[build-index] no paraphrase pack; AttackIndex stays train-only');
    return [];
  }
  const pack = loadJson<{ fixtures: ParaFixture[] }>(paraPath);
  const paras = selectParaphrases(pack.fixtures, split.holdoutIds);
  const out: AttackEntry[] = [];
  for (const f of paras) {
    const vec = await embedText(f.text);
    if (!vec) throw new Error(`embed failed for paraphrase ${f.id}`);
    out.push({
      id: f.id,
      class: 'paraphrase-holdout',
      text: f.text,
      source: 'paraphrase',
      parentHoldoutId: f.sourceId,
      vector: Array.from(vec),
    });
    console.log(`[build-index] paraphrase ${f.id} parent=${f.sourceId}`);
  }
  return out;
}

async function applyMissIntersect(split: SplitFile, attackEntries: AttackEntry[]): Promise<{ tagged: number; added: number; refused: number }> {
  const missPath = join(ROOT, 'pentest/payloads/dl011d-d1-expand-miss.json');
  if (!existsSync(missPath)) {
    console.warn('[build-index] no miss∩ pack');
    return { tagged: 0, added: 0, refused: 0 };
  }
  const pack = loadJson<{ fixtures: MissFixture[] }>(missPath);
  const { train, refusedHoldout } = selectTrainMissIntersect(pack.fixtures, split.trainIds, split.holdoutIds);
  console.log(`[build-index] miss∩ train=${train.length} refusedHoldout=${refusedHoldout.length}`);
  let tagged = 0;
  let added = 0;
  for (const f of train) {
    const existing = attackEntries.find((e) => e.id === f.sourceId);
    if (existing) {
      if (existing.source !== 'paraphrase') existing.source = 'miss_intersect';
      tagged += 1;
      continue;
    }
    if (!f.text) throw new Error(`miss∩ ${f.sourceId} missing text and not in index`);
    const vec = await embedText(f.text);
    if (!vec) throw new Error(`embed failed for miss∩ ${f.sourceId}`);
    attackEntries.push({
      id: f.sourceId,
      class: 'miss-intersect',
      text: f.text,
      source: 'miss_intersect',
      vector: Array.from(vec),
    });
    added += 1;
    console.log(`[build-index] miss∩ added ${f.sourceId}`);
  }
  return { tagged, added, refused: refusedHoldout.length };
}

async function main(): Promise<void> {
  if (!isEmbeddingModelAvailable()) {
    console.error('[build-index] MiniLM model not found. Run scripts/download-embedding-model.sh first.');
    process.exit(1);
  }

  const splitPath = join(OUT_DIR, 's3-v1a-split.json');
  const atkFixPath = join(ROOT, 'pentest/payloads/dl011c-mode-untrusted.json');
  const benFixPath = join(ROOT, 'pentest/payloads/dl011c-mode-chat.json');
  for (const p of [splitPath, atkFixPath, benFixPath]) {
    if (!existsSync(p)) throw new Error(`missing ${p}`);
  }

  const split = loadJson<SplitFile>(splitPath);
  const atkFix = loadJson<FixtureFile>(atkFixPath);
  const benFix = loadJson<FixtureFile>(benFixPath);
  const atkById = new Map(atkFix.fixtures.map((f) => [f.id, f]));
  const benById = new Map(benFix.fixtures.map((f) => [f.id, f]));

  const holdoutSet = new Set(split.holdoutIds);
  for (const id of split.trainIds) {
    if (holdoutSet.has(id)) throw new Error(`train id also in holdout: ${id}`);
  }

  console.log(`[build-index] train=${split.trainIds.length} holdout=${split.holdoutIds.length} benign=${split.benignIds.length}`);

  const existing = loadExistingAttack();
  let attackEntries = reuseTrainVectors(split.trainIds, existing);
  if (!attackEntries) {
    attackEntries = await embedIds(split.trainIds, atkById);
  }

  let paraphrases = reuseParaphrases(existing);
  if (!paraphrases) paraphrases = await embedParaphrases(split);
  attackEntries = [...attackEntries, ...paraphrases];

  const miss = await applyMissIntersect(split, attackEntries);

  const leak = holdoutOriginalsInIndex(attackEntries, split.holdoutIds);
  if (leak.length) throw new Error(`holdout originals leaked into AttackIndex: ${leak.join(',')}`);
  const leakMiss = holdoutMissIdsInIndex(attackEntries, split.holdoutIds);
  if (leakMiss.length) throw new Error(`holdout *-miss leaked into AttackIndex: ${leakMiss.join(',')}`);

  let benignEntries = reuseBenign(split.benignIds);
  if (!benignEntries) {
    benignEntries = await embedIds(split.benignIds, benById);
  }

  const attackChecksum = checksumEntries(attackEntries);
  const benignChecksum = checksumEntries(benignEntries);

  mkdirSync(OUT_DIR, { recursive: true });

  const attackDoc = {
    version: 'v1a-d1c',
    baseTip: 'f6a5367',
    model: 'paraphrase-multilingual-MiniLM-L12-v2',
    dim: attackEntries[0]?.vector.length ?? 384,
    tauAtk: TAU_ATK,
    tauBen: TAU_BEN,
    checksum: attackChecksum,
    missIntersect: { tagged: miss.tagged, added: miss.added, refusedHoldout: miss.refused },
    entries: attackEntries,
  };
  const benignDoc = {
    version: 'v1a',
    baseTip: split.baseTip ?? '776aa4a',
    model: 'paraphrase-multilingual-MiniLM-L12-v2',
    dim: benignEntries[0]?.vector.length ?? 384,
    tauAtk: TAU_ATK,
    tauBen: TAU_BEN,
    checksum: benignChecksum,
    entries: benignEntries,
  };
  const holdoutDoc = {
    version: 'v1a-d1c',
    baseTip: 'f6a5367',
    holdoutIds: split.holdoutIds,
    note: 'ids-only; holdout originals never embedded. D1b paraphrases cover holdout parents. D1c refuses miss∩ holdout originals (14); tags train miss∩ (11) source=miss_intersect.',
    paraphraseCount: paraphrases.length,
    missIntersectTagged: miss.tagged,
    missIntersectAdded: miss.added,
  };

  writeFileSync(join(OUT_DIR, 'attack-index-v1.json'), JSON.stringify(attackDoc, null, 2) + '\n');
  writeFileSync(join(OUT_DIR, 'benign-index-v1.json'), JSON.stringify(benignDoc, null, 2) + '\n');
  writeFileSync(join(OUT_DIR, 'holdout-eval-v1.json'), JSON.stringify(holdoutDoc, null, 2) + '\n');

  console.log(`[build-index] wrote ${OUT_DIR}/attack-index-v1.json (n=${attackEntries.length} train=${split.trainIds.length} para=${paraphrases.length} missTag=${miss.tagged} missAdd=${miss.added}, sha256=${attackChecksum.slice(0, 12)}…)`);
  console.log(`[build-index] wrote ${OUT_DIR}/benign-index-v1.json (n=${benignEntries.length}, sha256=${benignChecksum.slice(0, 12)}…)`);
  suggestTaus(attackEntries, benignEntries);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
