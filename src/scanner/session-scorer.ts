/**
 * Multi-Turn Session Scorer
 *
 * Tracks rolling SovGuard scores per session to detect crescendo attacks.
 * Individual messages may score low (0.1-0.2) but a sequence of 10+ mildly
 * suspicious messages indicates gradual escalation.
 *
 * Convention: 0 = safe, 1 = dangerous (matches SovGuard scoring).
 */

import type { AttackCategory } from '../types.js';

export interface SessionScoreEntry {
  score: number;
  timestamp: number;
  category?: AttackCategory;
}

export interface SessionEscalation {
  escalated: boolean;
  /** Rolling sum of recent scores */
  rollingSum: number;
  /** Number of messages in window */
  windowSize: number;
  /** Current threshold */
  threshold: number;
  /** Number of flagged messages (score > 0.3) in window */
  flaggedCount: number;
  /** Whether rapid message velocity was detected */
  velocityAlert?: boolean;
  /** Number of rapid messages if velocity detected */
  rapidMessageCount?: number;
  /** Ratio of most common attack category in window (0-1) */
  categoryDiversity?: number;
}

export interface SessionScorerConfig {
  /** Number of recent messages to track. Default: 10 */
  windowSize?: number;
  /** Rolling sum threshold for escalation. Default: 1.5 */
  sumThreshold?: number;
  /** Max age of scores in ms. Default: 1 hour (3600000) */
  maxAgeMs?: number;
  /** Max sessions to track (LRU eviction). Default: 10000 */
  maxSessions?: number;
  /** Minimum flagged messages (score > 0.3) in window to consider escalation. Default: 2 */
  minFlaggedForEscalation?: number;
  /** Velocity detection: number of messages in rapid window. Default: 5 */
  velocityCount?: number;
  /** Velocity detection: max interval between messages in ms. Default: 1000 */
  velocityIntervalMs?: number;
  /** Category diversity: threshold for single-category probing (0-1). Default: 0.7 */
  categoryDiversityThreshold?: number;
  /** Rolling sum override: escalate even without individually flagged messages if sum reaches this. Default: 3.0 */
  highSumOverride?: number;
}

const DEFAULT_WINDOW_SIZE = 10;
const DEFAULT_SUM_THRESHOLD = 1.5;
const DEFAULT_MAX_AGE_MS = 3600000; // 1 hour
const DEFAULT_MAX_SESSIONS = 10000;
const DEFAULT_MIN_FLAGGED = 2;
const DEFAULT_VELOCITY_COUNT = 5;
const DEFAULT_VELOCITY_INTERVAL_MS = 1000;
const DEFAULT_CATEGORY_DIVERSITY_THRESHOLD = 0.7;
/** If rolling sum reaches this, escalate even without individually flagged messages.
 *  Catches "death by a thousand cuts" crescendo attacks where each turn scores < 0.3. */
const DEFAULT_HIGH_SUM_OVERRIDE = 1.5;

const DEFAULT_PRUNE_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

export class SessionScorer {
  private sessions = new Map<string, SessionScoreEntry[]>();
  private accessOrder = new Map<string, true>(); // O(1) LRU tracking via Map insertion order
  private readonly windowSize: number;
  private readonly sumThreshold: number;
  private readonly maxAgeMs: number;
  private readonly maxSessions: number;
  private readonly minFlagged: number;
  private readonly velocityCount: number;
  private readonly velocityIntervalMs: number;
  private readonly categoryDiversityThreshold: number;
  private readonly highSumOverride: number;
  private pruneTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config?: SessionScorerConfig) {
    this.windowSize = config?.windowSize ?? DEFAULT_WINDOW_SIZE;
    this.sumThreshold = config?.sumThreshold ?? DEFAULT_SUM_THRESHOLD;
    this.maxAgeMs = config?.maxAgeMs ?? DEFAULT_MAX_AGE_MS;
    this.maxSessions = config?.maxSessions ?? DEFAULT_MAX_SESSIONS;
    this.minFlagged = config?.minFlaggedForEscalation ?? DEFAULT_MIN_FLAGGED;
    this.velocityCount = config?.velocityCount ?? DEFAULT_VELOCITY_COUNT;
    this.velocityIntervalMs = config?.velocityIntervalMs ?? DEFAULT_VELOCITY_INTERVAL_MS;
    this.categoryDiversityThreshold = config?.categoryDiversityThreshold ?? DEFAULT_CATEGORY_DIVERSITY_THRESHOLD;
    this.highSumOverride = config?.highSumOverride ?? DEFAULT_HIGH_SUM_OVERRIDE;

    // Start periodic TTL-based session pruning
    this.startPruneTimer();
  }

  /**
   * Record a message score and check for escalation.
   * Returns escalation status after recording.
   */
  record(sessionId: string, score: number, category?: AttackCategory): SessionEscalation {
    const now = Date.now();

    // Get or create session scores
    let scores = this.sessions.get(sessionId);
    if (!scores) {
      scores = [];
      this.sessions.set(sessionId, scores);
    }

    // Add new score
    scores.push({ score, timestamp: now, category });

    // Prune old entries (by age and window size)
    const cutoff = now - this.maxAgeMs;
    const pruned = scores.filter(s => s.timestamp >= cutoff);
    const windowed = pruned.slice(-this.windowSize);
    this.sessions.set(sessionId, windowed);

    // Update LRU
    this.touchLRU(sessionId);

    // Evict if over capacity
    this.evictIfNeeded();

    // Calculate escalation
    const rollingSum = windowed.reduce((sum, s) => sum + s.score, 0);
    const flaggedCount = windowed.filter(s => s.score > 0.3).length;

    // Velocity detection: N messages arriving faster than interval
    const velocityResult = this.detectVelocity(windowed);

    // Category diversity: detect repeated single-category probing
    const categoryDiversity = this.calculateCategoryDiversity(windowed);

    // Escalate if: sum exceeds threshold AND enough individual messages were flagged
    // The minFlagged check prevents escalation from a single high-score message
    // Also escalate on velocity alert with flagged messages
    // Also escalate if rolling sum is very high (highSumOverride) even without
    // individually flagged messages — catches gradual crescendo attacks where
    // each message scores below the 0.3 flag threshold
    const escalated = (rollingSum >= this.sumThreshold && flaggedCount >= this.minFlagged)
      || (!!velocityResult.velocityAlert && flaggedCount >= this.minFlagged)
      || (rollingSum >= this.highSumOverride && windowed.length >= this.minFlagged);

    return {
      escalated,
      rollingSum: Math.round(rollingSum * 1000) / 1000,
      windowSize: windowed.length,
      threshold: this.sumThreshold,
      flaggedCount,
      ...velocityResult,
      categoryDiversity,
    };
  }

  /**
   * Get current escalation status for a session without recording.
   */
  check(sessionId: string): SessionEscalation {
    const scores = this.sessions.get(sessionId);
    if (!scores || scores.length === 0) {
      return {
        escalated: false,
        rollingSum: 0,
        windowSize: 0,
        threshold: this.sumThreshold,
        flaggedCount: 0,
      };
    }

    // Prune stale
    const now = Date.now();
    const cutoff = now - this.maxAgeMs;
    const windowed = scores.filter(s => s.timestamp >= cutoff).slice(-this.windowSize);

    const rollingSum = windowed.reduce((sum, s) => sum + s.score, 0);
    const flaggedCount = windowed.filter(s => s.score > 0.3).length;
    const escalated = (rollingSum >= this.sumThreshold && flaggedCount >= this.minFlagged)
      || (rollingSum >= this.highSumOverride && windowed.length >= this.minFlagged);

    return {
      escalated,
      rollingSum: Math.round(rollingSum * 1000) / 1000,
      windowSize: windowed.length,
      threshold: this.sumThreshold,
      flaggedCount,
    };
  }

  /**
   * Clear scores for a session (e.g., on job completion).
   */
  clear(sessionId: string): void {
    this.sessions.delete(sessionId);
    this.accessOrder.delete(sessionId);
  }

  /**
   * Number of tracked sessions.
   */
  get size(): number {
    return this.sessions.size;
  }

  /**
   * TTL-based session pruning: removes sessions where ALL entries are older
   * than maxAgeMs. Sessions with at least one recent entry are kept.
   * Returns the number of sessions pruned.
   */
  prune(): number {
    const cutoff = Date.now() - this.maxAgeMs;
    let pruned = 0;
    for (const [sessionId, entries] of this.sessions) {
      const hasRecent = entries.some(e => e.timestamp >= cutoff);
      if (!hasRecent) {
        this.sessions.delete(sessionId);
        this.accessOrder.delete(sessionId);
        pruned++;
      }
    }
    return pruned;
  }

  /**
   * Start periodic TTL-based pruning timer (similar to canary token cleanup).
   * Timer is unref'd so it doesn't keep the process alive.
   */
  startPruneTimer(): void {
    if (this.pruneTimer) return;
    this.pruneTimer = setInterval(() => this.prune(), DEFAULT_PRUNE_INTERVAL_MS);
    if (this.pruneTimer.unref) this.pruneTimer.unref();
  }

  /**
   * Stop the periodic pruning timer.
   */
  stopPruneTimer(): void {
    if (this.pruneTimer) {
      clearInterval(this.pruneTimer);
      this.pruneTimer = null;
    }
  }

  private detectVelocity(windowed: SessionScoreEntry[]): { velocityAlert?: boolean; rapidMessageCount?: number } {
    if (windowed.length < this.velocityCount) return {};

    // Check if the last N messages all arrived within the velocity interval
    const recent = windowed.slice(-this.velocityCount);
    let rapidCount = 0;
    for (let i = 1; i < recent.length; i++) {
      if (recent[i].timestamp - recent[i - 1].timestamp < this.velocityIntervalMs) {
        rapidCount++;
      }
    }

    // All gaps must be under the interval
    if (rapidCount >= this.velocityCount - 1) {
      return { velocityAlert: true, rapidMessageCount: this.velocityCount };
    }

    return {};
  }

  private calculateCategoryDiversity(windowed: SessionScoreEntry[]): number | undefined {
    const categorized = windowed.filter(s => s.category);
    if (categorized.length < 3) return undefined;

    const counts = new Map<string, number>();
    for (const entry of categorized) {
      counts.set(entry.category!, (counts.get(entry.category!) || 0) + 1);
    }

    if (counts.size === 0) return undefined;
    const maxCount = Math.max(...counts.values());
    const ratio = maxCount / categorized.length;

    return Math.round(ratio * 1000) / 1000;
  }

  private touchLRU(sessionId: string): void {
    this.accessOrder.delete(sessionId);
    this.accessOrder.set(sessionId, true);
  }

  private evictIfNeeded(): void {
    while (this.sessions.size > this.maxSessions && this.accessOrder.size > 0) {
      const oldest = this.accessOrder.keys().next().value!;
      this.accessOrder.delete(oldest);
      this.sessions.delete(oldest);
    }
  }
}
