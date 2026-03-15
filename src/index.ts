/**
 * SovGuard Engine
 * Prompt injection detection and safe message delivery for AI agents.
 */

import { scan } from './scanner/index.js';
import { wrapMessage } from './delivery/wrap.js';
import { generateToken, checkLeak, getToken, revokeToken } from './canary/tokens.js';
import { scanFile } from './file/scanner.js';
import { scanFileContent, scanText } from './file/content-scanner.js';
import type { ContentScanResult, ContentScanOptions } from './file/content-scanner.js';
import { recordScan, recordCanaryLeak, getStats, resetStats } from './monitor/stats.js';
import { scanOutput } from './outbound/index.js';
import type {
  SovGuardConfig,
  ScanResult,
  WrappedMessage,
  WrapOptions,
  CanaryToken,
  CanaryCheckResult,
  FileScanResult,
  FileMetadata,
  SafetyStats,
  OutputScanContext,
  OutputScanResult,
} from './types.js';

export class SovGuardEngine {
  private config: SovGuardConfig;

  constructor(config: SovGuardConfig = {}) {
    this.config = config;
  }

  /**
   * Scan a message for prompt injection attacks.
   */
  async scan(message: string): Promise<ScanResult> {
    const result = await scan(message, this.config);
    recordScan(result);
    return result;
  }

  /**
   * Wrap a message with safety metadata for structured delivery to an agent.
   * Uses Microsoft Spotlighting pattern with data markers.
   */
  wrap(message: string, scanResult: ScanResult, options: WrapOptions = {}): WrappedMessage {
    return wrapMessage(message, scanResult, options);
  }

  /**
   * Create a canary token for a session.
   * Inject the token's injectionText into the agent's context.
   */
  createCanary(sessionId: string): CanaryToken {
    return generateToken(sessionId);
  }

  /**
   * Check an agent's response for canary token leaks.
   */
  checkCanary(agentResponse: string, sessionId?: string): CanaryCheckResult {
    const result = checkLeak(agentResponse, sessionId);
    if (result.leaked) {
      recordCanaryLeak();
    }
    return result;
  }

  /**
   * Revoke a session's canary token.
   */
  revokeCanary(sessionId: string): boolean {
    return revokeToken(sessionId);
  }

  /**
   * Scan a file's name and metadata for injection patterns.
   */
  scanFile(filename: string, metadata?: FileMetadata): FileScanResult {
    return scanFile(filename, metadata);
  }

  /**
   * Scan file content (body text) for injection patterns.
   * Extracts text from supported formats (TXT, MD, CSV, JSON, XML, PDF).
   */
  scanFileContent(buffer: Buffer, mimeType: string, options?: ContentScanOptions): ContentScanResult {
    return scanFileContent(buffer, mimeType, options);
  }

  /**
   * Scan raw text content for injection patterns.
   */
  scanText(text: string, options?: ContentScanOptions): ContentScanResult {
    return scanText(text, options);
  }

  /**
   * Get monitoring statistics.
   */
  getStats(): SafetyStats {
    return getStats();
  }

  /**
   * Reset monitoring statistics.
   */
  resetStats(): void {
    resetStats();
  }

  /**
   * Scan an outbound agent response before delivery to buyer.
   * Blocked messages should be held (not deleted) for appeals.
   */
  async scanOutput(message: string, context: OutputScanContext): Promise<OutputScanResult> {
    return scanOutput(message, context);
  }
}

// Re-export types
export type {
  SovGuardConfig,
  ScanResult,
  WrappedMessage,
  WrapOptions,
  CanaryToken,
  CanaryCheckResult,
  FileScanResult,
  FileMetadata,
  SafetyStats,
  Classification,
  Severity,
  AttackCategory,
  LayerResult,
  PatternMatch,
  OutputScanContext,
  OutputScanResult,
  OutputFlag,
} from './types.js';

// Re-export individual modules for advanced use
export { SessionScorer } from './scanner/session-scorer.js';
export type { SessionEscalation, SessionScorerConfig, SessionScoreEntry } from './scanner/session-scorer.js';
export { scan } from './scanner/index.js';
export { regexScan } from './scanner/regex.js';
export { perplexityScan } from './scanner/perplexity.js';
export { classifierScan } from './scanner/classifier.js';
export { wrapMessage } from './delivery/wrap.js';
export { generateToken, checkLeak, getToken, setCanaryStore, MAX_TOKENS, TOKEN_TTL_MS } from './canary/tokens.js';
export type { CanaryStore } from './canary/tokens.js';
export { createSqliteCanaryStore } from './canary/store-sqlite.js';
export { scanFile, sanitizeFilename } from './file/scanner.js';
export { scanFileContent, scanText } from './file/content-scanner.js';
export type { ContentScanResult, ContentScanOptions } from './file/content-scanner.js';
export { getStats, resetStats } from './monitor/stats.js';
export { scanOutput } from './outbound/index.js';
export { scanPII } from './outbound/pii.js';
export { scanURLs } from './outbound/urls.js';
export { scanCode } from './outbound/code.js';
export { scanFinancial } from './outbound/financial.js';
export { scanContamination } from './outbound/contamination.js';
