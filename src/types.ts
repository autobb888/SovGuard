/**
 * SovGuard Engine — Type Definitions
 */

import type { TopicRailsConfig } from './scanner/topic-rails.js';

// ─── Scanner Types ───────────────────────────────────────────────

export type Severity = 'low' | 'medium' | 'high';
export type Classification = 'safe' | 'suspicious' | 'likely_injection';
export type AttackCategory =
  | 'instruction_override'
  | 'role_play'
  | 'encoding_trick'
  | 'context_manipulation'
  | 'exfiltration'
  | 'delimiter_attack'
  | 'adversarial_suffix'
  | 'financial_manipulation'
  | 'chatml_injection'
  | 'policy_puppetry'
  | 'tool_poisoning'
  | 'goal_hijacking'
  | 'memory_poisoning'
  | 'agent_impersonation';

export interface PatternMatch {
  pattern: string;
  category: AttackCategory;
  severity: Severity;
  matched: string;
}

export interface LayerResult {
  layer: string;
  score: number;
  flags: string[];
  details?: Record<string, unknown>;
}

export interface ScanResult {
  safe: boolean;
  score: number; // 0 (safe) to 1 (dangerous)
  classification: Classification;
  flags: string[];
  layers: LayerResult[];
  scannedAt: number;
}

// ─── Delivery Types ──────────────────────────────────────────────

export interface WrapOptions {
  role?: string;
  sessionId?: string;
  jobId?: string;
  canaryToken?: string;
}

export interface WrappedMessage {
  formatted: string;
  metadata: {
    role: string;
    safetyScore: number;
    classification: Classification;
    timestamp: string;
    jobId?: string;
  };
}

// ─── Canary Types ────────────────────────────────────────────────

export interface CanaryToken {
  token: string;
  sessionId: string;
  createdAt: number;
  injectionText: string;
}

export interface CanaryCheckResult {
  leaked: boolean;
  token?: string;
  sessionId?: string;
}

// ─── File Scanner Types ──────────────────────────────────────────

export interface FileMetadata {
  [key: string]: string | number | undefined;
}

export interface FileScanResult {
  safe: boolean;
  sanitizedFilename: string;
  flags: string[];
  details: {
    pathTraversal: boolean;
    nullBytes: boolean;
    unicodeRLO: boolean;
    injectionInName: boolean;
    suspiciousMetadata: boolean;
    dangerousExtension: boolean;
    doubleExtension: boolean;
  };
}

// ─── Monitor Types ───────────────────────────────────────────────

export interface SafetyStats {
  totalScanned: number;
  safe: number;
  suspicious: number;
  likelyInjection: number;
  blocked: number;
  canaryLeaks: number;
  avgScore: number;
  topCategories: Record<string, number>;
  since: number;
}

// ─── Outbound Scanner Types ──────────────────────────────────

export interface OutputScanContext {
  jobId: string;
  jobCategory?: string;
  jobFingerprints?: Map<string, Set<string>>;
  agentVerusId?: string;
  /** P2-OUT-3: Addresses to whitelist in financial scanner (e.g., job's payment address) */
  whitelistedAddresses?: Set<string>;
}

export interface OutputScanResult {
  safe: boolean;
  /** 0.0 = safe, 1.0 = dangerous. Higher = more risk. Matches inbound SovGuard convention. */
  score: number;
  classification: 'safe' | 'warning' | 'flagged' | 'blocked';
  flags: OutputFlag[];
  scannedAt: number;
}

export interface OutputFlag {
  type: 'pii_detected' | 'suspicious_url' | 'malicious_code' |
        'cross_contamination' | 'financial_manipulation' | 'agent_exfiltration' | 'data_uri' |
        'toxicity';
  severity: 'low' | 'medium' | 'high' | 'critical';
  detail: string;
  evidence: string;
  action: 'pass' | 'warn' | 'redact' | 'block' | 'flag';
}

// ─── Config ──────────────────────────────────────────────────────

export interface SovGuardConfig {
  /** Threshold above which messages are classified as likely_injection (0-1). Default: 0.7 */
  blockThreshold?: number;
  /** Threshold above which messages are suspicious (0-1). Default: 0.3 */
  suspiciousThreshold?: number;
  /** Enable perplexity scanner. Default: true */
  enablePerplexity?: boolean;
  /** Enable ML classifier (requires LAKERA_API_KEY or ONNX model). Default: true */
  enableClassifier?: boolean;
  /** Lakera API key for ML classification */
  lakeraApiKey?: string;
  /** Classifier mode: 'local' (self-hosted ONNX), 'lakera' (API), 'auto' (local if available, else lakera). Default: 'auto' */
  classifierMode?: 'local' | 'lakera' | 'auto';
  /** Custom regex patterns to add */
  extraPatterns?: Array<{ pattern: RegExp; category: AttackCategory; severity: Severity }>;
  /** Configurable topic/policy rails for denied topics */
  topicRails?: TopicRailsConfig;
}
