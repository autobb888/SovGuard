/**
 * Safety Statistics Tracker
 */

import type { SafetyStats, ScanResult } from '../types.js';

let stats: SafetyStats = {
  totalScanned: 0,
  safe: 0,
  suspicious: 0,
  likelyInjection: 0,
  blocked: 0,
  canaryLeaks: 0,
  avgScore: 0,
  topCategories: {},
  since: Date.now(),
};

let scoreSum = 0;

export function recordScan(result: ScanResult): void {
  stats.totalScanned++;
  scoreSum += result.score;
  stats.avgScore = scoreSum / stats.totalScanned;

  switch (result.classification) {
    case 'safe': stats.safe++; break;
    case 'suspicious': stats.suspicious++; break;
    case 'likely_injection': stats.likelyInjection++; break;
  }

  for (const flag of result.flags) {
    const category = flag.split(':')[0];
    stats.topCategories[category] = (stats.topCategories[category] || 0) + 1;
  }
}

export function recordBlock(): void {
  stats.blocked++;
}

export function recordCanaryLeak(): void {
  stats.canaryLeaks++;
}

export function getStats(): SafetyStats {
  return { ...stats };
}

export function resetStats(): void {
  stats = {
    totalScanned: 0, safe: 0, suspicious: 0, likelyInjection: 0,
    blocked: 0, canaryLeaks: 0, avgScore: 0, topCategories: {}, since: Date.now(),
  };
  scoreSum = 0;
}
