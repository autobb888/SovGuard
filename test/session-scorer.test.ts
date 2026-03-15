import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { SessionScorer } from '../src/scanner/session-scorer.js';

describe('Multi-Turn Session Scorer', () => {

  // ── Basic scoring ──────────────────────────────────────

  it('returns no escalation for safe messages', () => {
    const scorer = new SessionScorer();
    const result = scorer.record('session-1', 0.05);
    assert.equal(result.escalated, false);
    assert.equal(result.rollingSum, 0.05);
    assert.equal(result.windowSize, 1);
    assert.equal(result.flaggedCount, 0);
  });

  it('returns no escalation for a single high-score message', () => {
    // A single dangerous message shouldn't trigger multi-turn escalation
    // (that's handled by the per-message block threshold)
    const scorer = new SessionScorer();
    const result = scorer.record('session-1', 0.95);
    assert.equal(result.escalated, false);
    assert.equal(result.flaggedCount, 1);
    // minFlagged default is 3, so 1 isn't enough
  });

  it('tracks rolling sum across messages', () => {
    const scorer = new SessionScorer();
    scorer.record('session-1', 0.1);
    scorer.record('session-1', 0.2);
    const result = scorer.record('session-1', 0.15);
    assert.equal(result.rollingSum, 0.45);
    assert.equal(result.windowSize, 3);
  });

  // ── Crescendo detection ────────────────────────────────

  it('detects crescendo attack (gradual escalation)', () => {
    const scorer = new SessionScorer({ sumThreshold: 2.0, minFlaggedForEscalation: 3 });

    // Simulate crescendo: each message mildly suspicious (0.3-0.4)
    scorer.record('session-1', 0.1);   // normal question
    scorer.record('session-1', 0.15);  // slightly odd
    scorer.record('session-1', 0.35);  // flagged
    scorer.record('session-1', 0.32);  // flagged
    scorer.record('session-1', 0.35);  // flagged
    scorer.record('session-1', 0.4);   // escalating
    scorer.record('session-1', 0.38);  // escalating
    const result = scorer.record('session-1', 0.4); // sum now > 2.0

    assert.equal(result.escalated, true);
    assert.ok(result.rollingSum >= 2.0);
    assert.ok(result.flaggedCount >= 3);
  });

  it('does not escalate if sum < threshold', () => {
    const scorer = new SessionScorer({ sumThreshold: 2.0 });
    // 10 messages at 0.15 each = 1.5 < 2.0
    for (let i = 0; i < 10; i++) {
      scorer.record('session-1', 0.15);
    }
    const result = scorer.check('session-1');
    assert.equal(result.escalated, false);
    assert.ok(result.rollingSum < 2.0);
  });

  it('does not escalate without enough flagged messages', () => {
    const scorer = new SessionScorer({ sumThreshold: 2.0, minFlaggedForEscalation: 3, highSumOverride: 5.0 });
    // 2 high scores but only 2 flagged (need 3)
    scorer.record('session-1', 0.95);
    scorer.record('session-1', 0.95);
    scorer.record('session-1', 0.1);  // not flagged
    const result = scorer.record('session-1', 0.1);
    assert.equal(result.escalated, false);
    assert.ok(result.rollingSum >= 2.0);
    assert.equal(result.flaggedCount, 2);
  });

  // ── Window management ──────────────────────────────────

  it('respects window size (drops old scores)', () => {
    const scorer = new SessionScorer({ windowSize: 3 });
    scorer.record('session-1', 0.9);  // will be dropped
    scorer.record('session-1', 0.1);
    scorer.record('session-1', 0.1);
    const result = scorer.record('session-1', 0.1);
    assert.equal(result.windowSize, 3);
    assert.equal(result.rollingSum, 0.3);  // 0.9 dropped
  });

  it('expires old scores by age', async () => {
    const scorer = new SessionScorer({ maxAgeMs: 100 });
    scorer.record('session-1', 0.9);
    
    // Wait for expiry
    await new Promise(r => setTimeout(r, 150));
    
    const result = scorer.record('session-1', 0.1);
    assert.equal(result.windowSize, 1);  // old score expired
    assert.equal(result.rollingSum, 0.1);
  });

  // ── Session isolation ──────────────────────────────────

  it('isolates scores between sessions', () => {
    const scorer = new SessionScorer();
    scorer.record('session-1', 0.9);
    scorer.record('session-2', 0.1);

    const r1 = scorer.check('session-1');
    const r2 = scorer.check('session-2');

    assert.equal(r1.rollingSum, 0.9);
    assert.equal(r2.rollingSum, 0.1);
  });

  it('returns empty status for unknown session', () => {
    const scorer = new SessionScorer();
    const result = scorer.check('nonexistent');
    assert.equal(result.escalated, false);
    assert.equal(result.rollingSum, 0);
    assert.equal(result.windowSize, 0);
  });

  // ── Session lifecycle ──────────────────────────────────

  it('clears session scores', () => {
    const scorer = new SessionScorer();
    scorer.record('session-1', 0.9);
    scorer.clear('session-1');

    const result = scorer.check('session-1');
    assert.equal(result.rollingSum, 0);
    assert.equal(result.windowSize, 0);
    assert.equal(scorer.size, 0);
  });

  it('evicts LRU sessions when over capacity', () => {
    const scorer = new SessionScorer({ maxSessions: 3 });
    scorer.record('a', 0.1);
    scorer.record('b', 0.2);
    scorer.record('c', 0.3);
    scorer.record('d', 0.4); // should evict 'a'

    assert.equal(scorer.size, 3);
    const a = scorer.check('a');
    assert.equal(a.windowSize, 0); // evicted
    const d = scorer.check('d');
    assert.equal(d.rollingSum, 0.4); // still there
  });

  it('LRU eviction respects access order', () => {
    const scorer = new SessionScorer({ maxSessions: 3 });
    scorer.record('a', 0.1);
    scorer.record('b', 0.2);
    scorer.record('c', 0.3);
    // Touch 'a' again — now 'b' is oldest
    scorer.record('a', 0.1);
    scorer.record('d', 0.4); // should evict 'b', not 'a'

    assert.equal(scorer.size, 3);
    const b = scorer.check('b');
    assert.equal(b.windowSize, 0); // evicted
    const a = scorer.check('a');
    assert.ok(a.rollingSum > 0); // still there
  });

  // ── Config ─────────────────────────────────────────────

  it('uses custom thresholds', () => {
    const scorer = new SessionScorer({
      windowSize: 5,
      sumThreshold: 1.0,
      minFlaggedForEscalation: 2,
    });

    scorer.record('s1', 0.4);  // flagged
    scorer.record('s1', 0.4);  // flagged
    const result = scorer.record('s1', 0.3); // sum = 1.1 > 1.0, flagged >= 2

    assert.equal(result.escalated, true);
    assert.equal(result.threshold, 1.0);
  });

  // ── v0.2.0: Velocity Detection ───────────────────────────

  it('detects rapid message velocity', () => {
    const scorer = new SessionScorer({
      velocityCount: 5,
      velocityIntervalMs: 1000,
      minFlaggedForEscalation: 3,
    });

    // Send 5 flagged messages essentially instantly (same timestamp via Date.now())
    scorer.record('s1', 0.4, 'instruction_override');
    scorer.record('s1', 0.4, 'instruction_override');
    scorer.record('s1', 0.4, 'instruction_override');
    scorer.record('s1', 0.4, 'instruction_override');
    const result = scorer.record('s1', 0.4, 'instruction_override');

    assert.equal(result.velocityAlert, true, 'Should detect velocity');
    assert.equal(result.rapidMessageCount, 5);
    assert.equal(result.escalated, true, 'Should escalate on velocity + flagged');
  });

  // ── v0.2.0: Category Diversity Tracking ──────────────────

  it('tracks category diversity', () => {
    const scorer = new SessionScorer();

    scorer.record('s1', 0.4, 'instruction_override');
    scorer.record('s1', 0.4, 'instruction_override');
    const result = scorer.record('s1', 0.4, 'instruction_override');

    // All 3 are the same category → ratio = 1.0
    assert.equal(result.categoryDiversity, 1.0);
  });

  it('reports lower diversity for mixed categories', () => {
    const scorer = new SessionScorer();

    scorer.record('s1', 0.4, 'instruction_override');
    scorer.record('s1', 0.4, 'role_play');
    scorer.record('s1', 0.4, 'encoding_trick');
    const result = scorer.record('s1', 0.4, 'exfiltration');

    // 4 different categories → max ratio = 0.25
    assert.ok(result.categoryDiversity !== undefined);
    assert.ok(result.categoryDiversity! < 0.5, 'Mixed categories should have low diversity ratio');
  });

  it('ignores category diversity with too few categorized messages', () => {
    const scorer = new SessionScorer();

    scorer.record('s1', 0.4, 'instruction_override');
    const result = scorer.record('s1', 0.4);

    assert.equal(result.categoryDiversity, undefined, 'Not enough categorized messages');
  });
});
