/**
 * SovGuard Engine
 * Prompt injection detection and safe message delivery for AI agents.
 */

import { scan } from './scanner/index.js';
import { scanContext } from './scanner/context.js';
import type { ScanMode } from './scanner/scan-mode.js';
import type { ContextScanOptions, ContextScanResult, SourceTrust, TaintPolicy, TaintAction, TaintNotification } from './scanner/context.js';
import { wrapMessage } from './delivery/wrap.js';
import { generateToken, checkLeak, getToken, revokeToken } from './canary/tokens.js';
import { scanFile } from './file/scanner.js';
import { scanFileContent, scanText } from './file/content-scanner.js';
import type { ContentScanResult, ContentScanOptions } from './file/content-scanner.js';
import { recordScan, recordCanaryLeak, getStats, resetStats } from './monitor/stats.js';
import { scanOutput } from './outbound/index.js';
import { scanTopics as scanTopicsImpl } from './scanner/topic-rails.js';
import type { TopicRailsConfig, TopicMatch, DeniedTopic } from './scanner/topic-rails.js';
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
  async scan(message: string, opts?: { jobCategory?: string; mode?: ScanMode }): Promise<ScanResult> {
    // Per-request jobCategory / mode merge over the engine config.
    const cfg = {
      ...this.config,
      ...(opts?.jobCategory ? { jobCategory: opts.jobCategory } : {}),
      ...(opts?.mode ? { mode: opts.mode } : {}),
    };
    const result = await scan(message, cfg);
    recordScan(result);
    return result;
  }

  /**
   * Scan a piece of text with awareness of WHERE it came from, and contain it
   * per policy. Untrusted sources (tool results, fetched files, job descriptions)
   * that trip the scanner are stripped/quarantined/blocked and always produce a
   * routable notification; trusted user input is never muzzled. This is the
   * primitive for gating data as it flows into an agent's context.
   */
  async scanContext(message: string, options: ContextScanOptions): Promise<ContextScanResult> {
    const result = await scanContext(message, { ...this.config, ...options });
    recordScan(result.scan);
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
  checkCanary(agentResponse: string, sessionId?: string, tenantId?: string): CanaryCheckResult {
    const result = checkLeak(agentResponse, sessionId, tenantId);
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

  /**
   * Scan text (inbound or outbound) against the configured topic/policy rails.
   * Returns an array of matched denied topics. Empty if no topicRails config set.
   */
  scanTopics(text: string): TopicMatch[] {
    if (!this.config.topicRails) return [];
    return scanTopicsImpl(text, this.config.topicRails);
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
export { scanContext } from './scanner/context.js';
export type { ScanMode } from './scanner/scan-mode.js';
export type { ContextScanOptions, ContextScanResult, SourceTrust, TaintPolicy, TaintAction, TaintNotification } from './scanner/context.js';
export { regexScan } from './scanner/regex.js';
export {
  retrievalDualMarginScan,
  evaluateDualMargin,
  TAU_ATK,
  TAU_BEN,
  LAYER_NAME as RETRIEVAL_DUAL_MARGIN_LAYER,
} from './scanner/retrieval-dual-margin.js';
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

export {
  shouldRecommendDataProtection,
  recommendDataProtection,
  sessionGateDataProtection,
} from './outbound/data-protection-hygiene.js';
export type {
  DataProtectionSessionContext,
  DataProtectionGateResult,
} from './outbound/data-protection-hygiene.js';
export { scanPII } from './outbound/pii.js';
export { scanURLs } from './outbound/urls.js';
export { scanCode } from './outbound/code.js';
export { scanFinancial } from './outbound/financial.js';
export { scanContamination } from './outbound/contamination.js';
export { scanToxicity } from './outbound/toxicity.js';
export { localClassifierScan, isLocalModelAvailable } from './scanner/classifier-local.js';
export { indirectInjectionScan } from './scanner/indirect.js';
export { scanTopics } from './scanner/topic-rails.js';
export type { TopicRailsConfig, DeniedTopic, TopicMatch } from './scanner/topic-rails.js';
export { getDb, setDb, closeDb } from './tenant/db.js';
export { ScanReportBody } from './schemas.js';

export { normalizeToFixedPoint, shouldEscalateUnicodeSignals, bidiCorroborated, stripBidiOverrides } from './scanner/regex.js';
export type { FixedPointNorm } from './scanner/regex.js';

export { detectPolicyRewrite, detectPolicyAck, detectCrescendoProbe } from './scanner/skeleton-key.js';

export { actionGuard, flagUntrustedUrlEcho, extractRemoteUrls, isUntrustedActionSource, scanProposedToolArgs, stringifyProposedToolArgs, isArgContentGateSource, denySideRecipientBind, denyEpGoalDestinationBind, flattenArgAllowlist, resolveArgAllowlist, denyArgAllowlist, denyShellClassPolicy, denyShellDestinationBind, isShellClassTool, isDestinationBindTool, isTrustedShellSource, collectDestinationUrls, DEFAULT_SHELL_CLASS_TOOLS, DEFAULT_DESTINATION_BIND_TOOLS } from './delivery/action-guard.js';
export type { TrustedPlan, ProposedAction, ActionGuardResult, DeniedAction, ProposedToolArgsScanResult, ProposedToolArgsHit, ActionGuardApprovalBindingOpts } from './delivery/action-guard.js';
export { urlOnTrustedAllowlist, normalizeUrlPathname } from './delivery/action-guard.js';

export {
  assessTraceToolComposite,
  classifyTraceWeakness,
  hasUnclosedToolCallSpan,
  DEFAULT_WEAK_TRACE_MAX_CHARS,
} from './delivery/trace-tool-composite.js';
export type {
  TraceToolCompositeInput,
  TraceToolCompositeResult,
  TraceToolVerdict,
  TraceWeakKind,
} from './delivery/trace-tool-composite.js';

export {
  memoryWriteGate,
  detectMemoryWriteIntent,
  preferenceRuleActTrust,
  PreferenceRuleStore,
  collectSideRecipients,
  isSideRecipientArg,
  SIDE_RECIPIENT_ARGS,
} from './delivery/memory-write-gate.js';
export type {
  PreferenceRule,
  PreferenceRuleProvenance,
  MemoryWriteAttempt,
  MemoryWriteGateResult,
  MemoryWriteGateVerdict,
} from './delivery/memory-write-gate.js';

export {
  ArtifactProvenanceStore,
  checkComposeProvenance,
  tagsConsistent,
  collectArtifactRefsFromArgs,
  denyInconsistentArtifactCompose,
  ARTIFACT_REF_ARG_KEYS,
} from './delivery/artifact-provenance.js';
export type {
  ArtifactProvenanceTag,
  ArtifactComposeGateResult,
  ArtifactComposeVerdict,
} from './delivery/artifact-provenance.js';

export {
  ApprovalBindingStore,
  approveAction,
  assertRepresentationComplete,
  compareApprovalAtUse,
  releaseWithApproval,
  digestApprovalVector,
  stableStringify,
  canonicalizeApprovalVector,
  approvalVectorFromToolAction,
} from './delivery/approval-binding.js';
export type {
  ApprovalVector,
  ApprovalTicket,
  UiApproveView,
  ApproveActionResult,
  UseTimeCompareResult,
  ReleaseApprovalResult,
} from './delivery/approval-binding.js';

// A2M Attraction→Manipulation thin land (prefer-pin / return IFC / C-DoS / mcp_config gate)
export {
  ToolAdmissionStore,
  admitTool,
  checkToolAdmission,
  preferPinnedTool,
  selectToolForCapability,
  verifyAdmittedDigest,
  normalizeSchemaDigest,
} from './delivery/tool-admission.js';
export type {
  AdmittedTool,
  ToolAdmissionCandidate,
  ToolAdmissionResult,
  ToolAdmissionVerdict,
  PreferPinSelectionInput,
} from './delivery/tool-admission.js';

export {
  applyReturnIfc,
  labelToolReturn,
  isInstructionShapedField,
  isReturnTrustedDirective,
  RETURN_INSTRUCTION_FIELDS,
} from './delivery/return-ifc.js';
export type {
  ReturnIfcResult,
  ReturnIfcOptions,
  ReturnIfcVerdict,
  ReturnTrustLabel,
} from './delivery/return-ifc.js';

export {
  ToolCallBudgetStore,
  checkToolCallBudget,
  gateToolCall,
} from './delivery/tool-call-budget.js';
export type {
  ToolCallBudgetConfig,
  ToolCallBudgetCheckInput,
  ToolCallBudgetResult,
  ToolCallBudgetVerdict,
  ToolCallRecordInput,
  SessionToolStats,
} from './delivery/tool-call-budget.js';

export {
  gateMcpConfigWrite,
  mcpConfigApprovalVector,
  digestMcpConfigWrite,
} from './delivery/mcp-config-gate.js';
export type {
  McpConfigWriteAttempt,
  McpConfigApprovalBinding,
  McpConfigGateResult,
  McpConfigGateVerdict,
  McpConfigWriteAction,
  McpServerProposal,
} from './delivery/mcp-config-gate.js';

export {
  scanToolSchema,
  TOOL_SCHEMA_INTEGRITY_KEYS,
  hashToolSchema,
  collectSchemaDocs,
  checkSchemaConsent,
  resolveToolShadowing,
  SchemaConsentStore,
  assertContinuousSchemaIntegrity,
} from './scanner/tool-schema.js';
export type {
  ToolSchema,
  ToolSchemaScanResult,
  ToolSchemaAction,
  ConsentedToolSchema,
  RugPullCheck,
  RegisteredTool,
  ShadowingResult,
  ContinuousSchemaIntegrityResult,
  ContinuousSchemaToolResult,
} from './scanner/tool-schema.js';

export {
  isolateDiscoveryInstructions,
  mayFoldIntoTrustedRegion,
  hashDiscoveryInstructions,
  normalizeDiscoveryInstructions,
  isEmptyDiscoveryInstructions,
  checkDiscoveryInstructionsConsent,
  DiscoveryInstructionsConsentStore,
  assertDiscoveryInstructionsIntegrity,
  evaluateDiscoveryCacheScope,
  bindDiscoveryCacheKey,
  DEFAULT_INSTRUCTIONS_MAX_LENGTH,
  DISCOVERY_INSTRUCTIONS_LABEL,
} from './scanner/mcp-discovery-instructions.js';
export type {
  IsolatedDiscoveryInstructions,
  ConsentedDiscoveryInstructions,
  InstructionsDriftCheck,
  DiscoveryInstructionsIntegrityResult,
  DiscoveryCachePolicy,
  DiscoveryCacheDecision,
  DiscoveryInstructionsTrust,
} from './scanner/mcp-discovery-instructions.js';

export { scrubBoundaries, scrubUntrustedIngress, neutralizeBoundaryToken, hasRawBoundaryToken, DEFAULT_BOUNDARY_PATTERNS } from './scanner/boundary-scrub.js';
export type { BoundaryScrubOptions, BoundaryScrubResult } from './scanner/boundary-scrub.js';

export { ingestPeerEnvelope, stripHtmlComments } from './delivery/peer-envelope.js';
export type { PeerEnvelope, PeerIngestOptions, PeerIngestResult } from './delivery/peer-envelope.js';

export {
  PeerRegistry,
  normalizePeerName,
  normalizePeerOrigin,
  mintStablePeerId,
  isNameDerivedBrokerTopic,
} from './delivery/peer-registry.js';
export type {
  AgentCard,
  EnrolledPeer,
  PeerEnrollVerdict,
  PeerEnrollGate,
  PeerEnrollResult,
  PeerResolveVerdict,
  PeerResolveGate,
  PeerResolveResult,
  PeerRenameResult,
  PeerRegistryOptions,
} from './delivery/peer-registry.js';


export {
  detectDelayedTrigger,
  DelayedTriggerWatch,
  delayedTriggerWatch,
  denyDelayedPlantBind,
  isTrustedPlantSource,
} from './scanner/delayed-trigger.js';
export type { DelayedTriggerHit, DelayedArm, DelayedArmType } from './scanner/delayed-trigger.js';

export { detectDecomposition, DecompositionWatch, decompositionWatch } from './scanner/decomposition.js';
export type { DecompositionHit, FragmentEntry } from './scanner/decomposition.js';

export { detectManyShot, bonFingerprint, BonParaphraseWatch, bonParaphraseWatch } from './scanner/many-shot.js';
export type { ManyShotHit, BonHit } from './scanner/many-shot.js';
