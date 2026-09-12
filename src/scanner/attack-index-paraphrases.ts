/**
 * DL-011d D1b — AttackIndex paraphrase select / leakage helpers.
 * Used by the index builder and unit tests. No model I/O.
 */
export interface ParaFixture {
  id: string;
  sourceId: string;
  split?: string;
  text: string;
  forAttackIndex?: boolean;
}

export interface IndexIdEntry {
  id: string;
  source?: string;
  parentHoldoutId?: string;
}

/** Holdout original flat IDs that leaked into an index (must be empty). */
export function holdoutOriginalsInIndex(
  entries: IndexIdEntry[],
  holdoutIds: readonly string[],
): string[] {
  const hold = new Set(holdoutIds);
  return entries.filter((e) => hold.has(e.id)).map((e) => e.id);
}

/**
 * Keep paraphrases whose parent is a holdout original.
 * Skip train-parent paraphrases (would inflate train-only catch).
 * Throw if a fixture id collides with a holdout original id.
 */
export function selectParaphrases(
  fixtures: ParaFixture[],
  holdoutIds: readonly string[],
): ParaFixture[] {
  const hold = new Set(holdoutIds);
  const out: ParaFixture[] = [];
  for (const f of fixtures) {
    if (f.forAttackIndex === false) continue;
    if (!f.id || !f.text) continue;
    if (hold.has(f.id)) {
      throw new Error(`paraphrase id collides with holdout original: ${f.id}`);
    }
    if (!hold.has(f.sourceId)) continue;
    out.push(f);
  }
  return out;
}
