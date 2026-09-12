/**
 * DL-011d D1c — miss∩ AttackIndex select / refuse helpers.
 * No model I/O.
 */
export interface MissFixture {
  id: string;
  sourceId: string;
  text?: string;
  forAttackIndex?: boolean;
}

export interface MissSplit {
  train: MissFixture[];
  refusedHoldout: MissFixture[];
}

/** Train miss∩ may be indexed (idempotent). Holdout sourceIds are refused. */
export function selectTrainMissIntersect(
  fixtures: MissFixture[],
  trainIds: readonly string[],
  holdoutIds: readonly string[],
): MissSplit {
  const trainSet = new Set(trainIds);
  const hold = new Set(holdoutIds);
  const train: MissFixture[] = [];
  const refusedHoldout: MissFixture[] = [];
  for (const f of fixtures) {
    if (f.forAttackIndex === false) continue;
    if (!f.sourceId) continue;
    if (hold.has(f.sourceId) || hold.has(f.id)) {
      refusedHoldout.push(f);
      continue;
    }
    if (trainSet.has(f.sourceId)) train.push(f);
  }
  return { train, refusedHoldout };
}

export function holdoutMissIdsInIndex(
  entries: Array<{ id: string }>,
  holdoutIds: readonly string[],
): string[] {
  const hold = new Set(holdoutIds);
  const leaked: string[] = [];
  for (const e of entries) {
    if (hold.has(e.id)) leaked.push(e.id);
    for (const h of holdoutIds) {
      if (e.id === `${h}-miss`) leaked.push(e.id);
    }
  }
  return leaked;
}
