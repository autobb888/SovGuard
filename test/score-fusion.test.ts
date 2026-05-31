import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { combineScores } from '../src/scanner/index.js';
import type { LayerResult } from '../src/types.js';

const regex = (score: number): LayerResult => ({ layer: 'regex', score, flags: [] });
const perplexity = (score: number): LayerResult => ({ layer: 'perplexity', score, flags: [] });
const classifier = (score: number, provider: 'local' | 'lakera'): LayerResult => ({
  layer: 'classifier',
  score,
  flags: [],
  details: { available: true, provider },
});

describe('combineScores — provider-aware classifier fusion', () => {
  it('escalates a standalone LOCAL verdict to FLAG (suspicious) but not auto-BLOCK', () => {
    // Eval showed un-capped trust hard-blocks benign trigger-word text. So a
    // standalone model verdict flags for review but needs corroboration to block.
    const score = combineScores([regex(0.0), perplexity(0.05), classifier(0.95, 'local')]);
    assert.ok(score >= 0.3, `expected at least suspicious, got ${score}`);
    assert.ok(score < 0.7, `expected below block threshold (flag, not block), got ${score}`);
  });

  it('lets a corroborated LOCAL verdict block', () => {
    // Regex (or another layer) agreeing lifts the cap — a real attack blocks.
    const score = combineScores([regex(0.5), perplexity(0.05), classifier(0.95, 'local')]);
    assert.ok(score >= 0.7, `expected blockable when corroborated, got ${score}`);
  });

  it('still discounts a standalone LAKERA flag (flat boolean, FP-prone)', () => {
    const score = combineScores([regex(0.0), perplexity(0.05), classifier(0.95, 'lakera')]);
    assert.ok(score <= 0.3, `expected Lakera-alone to stay below suspicious, got ${score}`);
  });

  it('uses the max when another layer corroborates the classifier', () => {
    const score = combineScores([regex(0.8), perplexity(0.05), classifier(0.95, 'lakera')]);
    assert.equal(score, 0.95);
  });

  // ── Semantic arbitration of a lone classifier verdict (margin-based) ──
  const semantic = (attackSim: number, benignSim: number, available = true): LayerResult => ({
    layer: 'semantic', score: attackSim, flags: [], details: { available, benignSim },
  });

  it('BLOCKS a lone classifier verdict when near a known attack (high attackSim)', () => {
    const score = combineScores([regex(0.0), classifier(0.95, 'local'), semantic(0.8, 0.1)]);
    assert.ok(score >= 0.7, `expected block when semantic corroborates, got ${score}`);
  });

  it('SUPPRESSES a lone classifier verdict when closer to benign than attack', () => {
    const score = combineScores([regex(0.0), classifier(0.99, 'local'), semantic(0.3, 0.6)]);
    assert.ok(score < 0.3, `expected suppressed to safe, got ${score}`);
  });

  it('FLAGS (does not suppress) a typo/foreign attack: low attackSim but NOT benign-like', () => {
    // Foreign attack: both sims low (below the benign floor) → not corroborated,
    // not vetoed → flag, so the model's correct catch survives.
    const score = combineScores([regex(0.0), classifier(0.95, 'local'), semantic(0.19, 0.28)]);
    assert.ok(score >= 0.3 && score < 0.7, `expected flag band, got ${score}`);
  });

  it('falls back to flag-not-block when the semantic layer is unavailable', () => {
    const score = combineScores([regex(0.0), classifier(0.95, 'local'), semantic(0, 0, false)]);
    assert.ok(score >= 0.3 && score < 0.7, `expected flag band on semantic-unavailable, got ${score}`);
  });

  it('returns 0 when no layer flags anything', () => {
    const score = combineScores([regex(0.0), perplexity(0.0), classifier(0.04, 'local')]);
    assert.equal(score, 0.04);
  });

  it('does not discount a local verdict that is also corroborated', () => {
    const score = combineScores([regex(0.5), classifier(0.9, 'local')]);
    assert.equal(score, 0.9);
  });
});
