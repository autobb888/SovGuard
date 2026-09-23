/**
 * A2M Attraction→Manipulation thin land — ToolAdmission / prefer-pin (A).
 *
 * A1: Unknown registry / unpinned differently-named competitor → DENY
 *     (or HITL multi-admit); never auto-select over pin.
 * A2: Digest-pin approved (name,desc,schema) at admit/consent; drift →
 *     reject fail-closed (compose Deadbugz hashToolSchema / SchemaConsent).
 * A3: Prefer pinned tool over persuasive differently-named competitors for
 *     the same capability (extends beyond same-name resolveToolShadowing).
 *
 * KPI = Attraction MTIR surface close via admit+prefer-pin. Not deepset 80%.
 * Compose Deadbugz — do not reimplement. Soft residual: host wires prefer-pin
 * into MCP client tool-selection path.
 */
import {
  hashToolSchema,
  SchemaConsentStore,
  checkSchemaConsent,
  type ToolSchema,
  type ConsentedToolSchema,
  type RugPullCheck,
} from '../scanner/tool-schema.js';

export type ToolAdmissionVerdict =
  | 'ALLOW'
  | 'DENY'
  | 'HITL_MULTI_ADMIT'
  | 'REJECT_DRIFT';

/** Capability-scoped admitted (pinned) tool. */
export interface AdmittedTool {
  name: string;
  description?: string;
  /** sha256 from hashToolSchema (or host-supplied digest hex). */
  schemaDigest: string;
  /** Semantic capability bucket (e.g. fetch_document, send_message). */
  capability: string;
  registry?: string;
  serverId?: string;
  schema?: ToolSchema;
  admittedAt?: number;
}

/** Candidate proposed for selection / admission. */
export interface ToolAdmissionCandidate {
  name: string;
  description?: string;
  schemaDigest?: string | null;
  admitted?: boolean;
  registry?: string;
  serverId?: string;
  schema?: ToolSchema;
  capability?: string;
}

export interface ToolAdmissionResult {
  verdict: ToolAdmissionVerdict;
  /** Tool selected when ALLOW / prefer-pin. */
  selected?: AdmittedTool | ToolAdmissionCandidate;
  reason?: string;
  /** True when pinned beat a differently-named competitor (A3). */
  preferredPinned?: boolean;
  /** True when competitor was unknown/unpinned (A1). */
  deniedUnknown?: boolean;
  /** Drift check when composing Deadbugz (A2). */
  drift?: RugPullCheck & { consented?: boolean };
  /** Gate id for audit / fixtures. */
  gate?:
    | 'ToolAdmission.unknown_registry_DENY'
    | 'ToolAdmission.unpinned_competitor_DENY'
    | 'ToolAdmission.HITL_multi_admit'
    | 'ToolAdmission.digest_pin_drift_REJECT'
    | 'ToolAdmission.prefer_pin'
    | 'ToolAdmission.ALLOW_pinned'
    | 'ToolAdmission.ALLOW_admitted';
}

export interface PreferPinSelectionInput {
  capability: string;
  /** Pinned / admitted tools for this capability (host allowlist). */
  pinned: AdmittedTool[];
  /** Competing candidates (may include pinned + unpinned). */
  candidates: ToolAdmissionCandidate[];
  /**
   * When true and multiple unpinned candidates compete with no pin,
   * return HITL_MULTI_ADMIT instead of hard DENY (host multi-admit path).
   */
  allowHitlMultiAdmit?: boolean;
}

/** Normalize digest — strip optional sha256: prefix for compare. */
export function normalizeSchemaDigest(d: string | null | undefined): string {
  if (!d) return '';
  const s = String(d).trim().toLowerCase();
  return s.startsWith('sha256:') ? s.slice('sha256:'.length) : s;
}

/**
 * Digest-pin at admit/consent (A2).
 * Uses Deadbugz hashToolSchema over TOOL_SCHEMA_INTEGRITY_KEYS when schema given;
 * otherwise records host-supplied digest. Optionally mirrors into SchemaConsentStore.
 */
export function admitTool(
  store: ToolAdmissionStore,
  tool: {
    name: string;
    description?: string;
    capability: string;
    registry?: string;
    serverId?: string;
    schema?: ToolSchema;
    /** Host precomputed digest; ignored when schema provided (hashToolSchema wins). */
    schemaDigest?: string;
  },
  opts?: {
    consentStore?: SchemaConsentStore;
    /** Default serverId for SchemaConsentStore.record. */
    consentServerId?: string;
  },
): AdmittedTool {
  const schema: ToolSchema | undefined = tool.schema
    ? tool.schema
    : tool.description != null
      ? { name: tool.name, description: tool.description }
      : undefined;

  const digest =
    schema != null
      ? hashToolSchema(schema)
      : normalizeSchemaDigest(tool.schemaDigest) ||
        hashToolSchema({ name: tool.name, description: tool.description ?? '' });

  const admitted: AdmittedTool = {
    name: tool.name,
    description: tool.description ?? schema?.description,
    schemaDigest: digest,
    capability: tool.capability,
    registry: tool.registry,
    serverId: tool.serverId ?? opts?.consentServerId,
    schema,
    admittedAt: Date.now(),
  };

  store.record(admitted);

  if (opts?.consentStore && schema) {
    const sid = admitted.serverId ?? 'local';
    opts.consentStore.record(sid, schema);
  }

  return admitted;
}

/**
 * Verify current (name,desc,schema) against pin — drift → REJECT fail-closed (A2).
 * Composes Deadbugz checkSchemaConsent / SchemaConsentStore.verify when available.
 */
export function verifyAdmittedDigest(
  admitted: AdmittedTool,
  current: ToolAdmissionCandidate | ToolSchema,
  opts?: { consentStore?: SchemaConsentStore; serverId?: string },
): ToolAdmissionResult {
  let currentSchema: ToolSchema;
  const asCand = current as ToolAdmissionCandidate;
  if (asCand.schema && typeof asCand.schema === 'object' && typeof asCand.schema.name === 'string') {
    currentSchema = asCand.schema;
  } else if (
    current &&
    typeof current === 'object' &&
    typeof (current as ToolSchema).name === 'string' &&
    !('admitted' in (current as object))
  ) {
    currentSchema = current as ToolSchema;
  } else {
    currentSchema = {
      name: asCand.name,
      description: asCand.description,
      ...(asCand.schemaDigest ? {} : {}),
    };
  }

  // Prefer Deadbugz SchemaConsentStore when host wired it.
  if (opts?.consentStore) {
    const sid = opts.serverId ?? admitted.serverId ?? 'local';
    const v = opts.consentStore.verify(sid, currentSchema);
    if (v.consented && v.rugPull) {
      return {
        verdict: 'REJECT_DRIFT',
        reason: v.reason ?? 'schemaHash changed without re-consent (rug_pull)',
        drift: v,
        gate: 'ToolAdmission.digest_pin_drift_REJECT',
      };
    }
    if (v.consented && v.ok) {
      return {
        verdict: 'ALLOW',
        selected: admitted,
        drift: v,
        gate: 'ToolAdmission.ALLOW_pinned',
      };
    }
  }

  // Fallback: compare against AdmittedTool.schemaDigest via hashToolSchema /
  // checkSchemaConsent shape.
  if (admitted.schema) {
    const consented: ConsentedToolSchema = {
      serverId: admitted.serverId ?? 'local',
      toolName: admitted.name,
      schemaHash: admitted.schemaDigest,
    };
    const check = checkSchemaConsent(consented, currentSchema);
    if (!check.ok) {
      return {
        verdict: 'REJECT_DRIFT',
        reason: check.reason ?? 'digest pin drift — reject fail-closed',
        drift: { ...check, consented: true },
        gate: 'ToolAdmission.digest_pin_drift_REJECT',
      };
    }
    return {
      verdict: 'ALLOW',
      selected: admitted,
      drift: { ...check, consented: true },
      gate: 'ToolAdmission.ALLOW_pinned',
    };
  }

  const currentDigest =
    normalizeSchemaDigest((current as ToolAdmissionCandidate).schemaDigest) ||
    hashToolSchema(currentSchema);
  if (normalizeSchemaDigest(admitted.schemaDigest) !== normalizeSchemaDigest(currentDigest)) {
    return {
      verdict: 'REJECT_DRIFT',
      reason: 'schemaDigest drift vs admit pin — reject fail-closed',
      drift: {
        ok: false,
        rugPull: true,
        consented: true,
        reason: 'schemaDigest drift vs admit pin',
        consentedHash: admitted.schemaDigest,
        currentHash: currentDigest,
      },
      gate: 'ToolAdmission.digest_pin_drift_REJECT',
    };
  }
  return {
    verdict: 'ALLOW',
    selected: admitted,
    gate: 'ToolAdmission.ALLOW_pinned',
  };
}

/**
 * Admit check for a single candidate (A1).
 * Unknown / unpinned → DENY (or HITL when allowHitlMultiAdmit).
 */
export function checkToolAdmission(
  store: ToolAdmissionStore,
  candidate: ToolAdmissionCandidate,
  opts?: {
    capability?: string;
    allowHitlMultiAdmit?: boolean;
    /** When set, also verify digest against pin (A2). */
    verifyDigest?: boolean;
    consentStore?: SchemaConsentStore;
  },
): ToolAdmissionResult {
  const cap = opts?.capability ?? candidate.capability;
  const pinned = cap
    ? store.listByCapability(cap)
    : store.getByName(candidate.name)
      ? [store.getByName(candidate.name)!]
      : [];

  const match = pinned.find((p) => p.name === candidate.name);

  if (!match) {
    // Differently-named or unknown — never auto-admit.
    if (candidate.admitted === true && pinned.length === 0 && !cap) {
      // Host claimed admitted but store has no pin — still DENY unknown.
    }
    if (opts?.allowHitlMultiAdmit) {
      return {
        verdict: 'HITL_MULTI_ADMIT',
        reason:
          'Unknown/unpinned tool — require HITL multi-admit; never auto-select over pin',
        deniedUnknown: true,
        gate: 'ToolAdmission.HITL_multi_admit',
      };
    }
    const unknownRegistry =
      candidate.registry != null &&
      !pinned.some((p) => p.registry === candidate.registry);
    return {
      verdict: 'DENY',
      reason: unknownRegistry
        ? `Unknown registry tool "${candidate.name}" denied by default (Attraction admission)`
        : `Unpinned differently-named competitor "${candidate.name}" denied — never auto-select over pin`,
      deniedUnknown: true,
      gate: unknownRegistry
        ? 'ToolAdmission.unknown_registry_DENY'
        : 'ToolAdmission.unpinned_competitor_DENY',
    };
  }

  if (opts?.verifyDigest !== false) {
    const drift = verifyAdmittedDigest(match, candidate, {
      consentStore: opts?.consentStore,
      serverId: match.serverId,
    });
    if (drift.verdict === 'REJECT_DRIFT') return drift;
  }

  return {
    verdict: 'ALLOW',
    selected: match,
    gate: 'ToolAdmission.ALLOW_admitted',
  };
}

/**
 * Prefer pinned tool over persuasive differently-named competitors (A3).
 * Extends beyond same-name resolveToolShadowing.
 */
export function preferPinnedTool(input: PreferPinSelectionInput): ToolAdmissionResult {
  const { capability, pinned, candidates, allowHitlMultiAdmit } = input;
  const pins = pinned.filter((p) => p.capability === capability || !capability);
  const pinNames = new Set(pins.map((p) => p.name));

  // If any candidate is a pin, select the pin — never the persuasive competitor.
  const pinnedCandidates = candidates.filter((c) => pinNames.has(c.name));
  const unpinnedCompetitors = candidates.filter((c) => !pinNames.has(c.name));

  if (pins.length > 0) {
    // Prefer explicit pin from store even if not in candidates list.
    const preferred =
      pinnedCandidates.length > 0
        ? pins.find((p) => p.name === pinnedCandidates[0].name) ?? pins[0]
        : pins[0];

    if (unpinnedCompetitors.length > 0) {
      return {
        verdict: 'ALLOW',
        selected: preferred,
        preferredPinned: true,
        reason: `Prefer pinned "${preferred.name}" over differently-named competitor(s) for capability "${capability}"`,
        gate: 'ToolAdmission.prefer_pin',
      };
    }
    return {
      verdict: 'ALLOW',
      selected: preferred,
      preferredPinned: true,
      gate: 'ToolAdmission.prefer_pin',
    };
  }

  // No pin for capability — unpinned competitors must not auto-win.
  if (unpinnedCompetitors.length === 0) {
    return {
      verdict: 'DENY',
      reason: `No pinned tool and no candidates for capability "${capability}"`,
      deniedUnknown: true,
      gate: 'ToolAdmission.unpinned_competitor_DENY',
    };
  }

  if (allowHitlMultiAdmit) {
    return {
      verdict: 'HITL_MULTI_ADMIT',
      reason:
        'No capability pin — HITL multi-admit required before selecting unpinned competitor',
      deniedUnknown: true,
      gate: 'ToolAdmission.HITL_multi_admit',
    };
  }

  return {
    verdict: 'DENY',
    reason: `No pinned tool for capability "${capability}" — deny unpinned competitor auto-select`,
    deniedUnknown: true,
    gate: 'ToolAdmission.unknown_registry_DENY',
  };
}

/**
 * High-level selection: prefer-pin then admission check.
 */
export function selectToolForCapability(
  store: ToolAdmissionStore,
  capability: string,
  candidates: ToolAdmissionCandidate[],
  opts?: { allowHitlMultiAdmit?: boolean; consentStore?: SchemaConsentStore },
): ToolAdmissionResult {
  const pinned = store.listByCapability(capability);
  const prefer = preferPinnedTool({
    capability,
    pinned,
    candidates,
    allowHitlMultiAdmit: opts?.allowHitlMultiAdmit,
  });
  if (prefer.verdict !== 'ALLOW' || !prefer.selected) return prefer;

  // Re-verify digest only when candidate carries schema or digest (A2).
  // Sparse selection candidates (name-only prefer-pin) skip drift check.
  const sel = prefer.selected;
  const cand = candidates.find((c) => c.name === sel.name);
  if (cand && 'schemaDigest' in sel) {
    const admitted = sel as AdmittedTool;
    const hasSchemaMaterial =
      cand.schema != null ||
      (cand.schemaDigest != null && String(cand.schemaDigest).length > 0) ||
      (cand.description != null && cand.description !== admitted.description);
    if (admitted.schemaDigest && hasSchemaMaterial) {
      const v = verifyAdmittedDigest(admitted, cand, {
        consentStore: opts?.consentStore,
        serverId: admitted.serverId,
      });
      if (v.verdict === 'REJECT_DRIFT') return v;
    }
  }
  return prefer;
}

/** In-memory capability-scoped admission ledger. */
export class ToolAdmissionStore {
  private byKey = new Map<string, AdmittedTool>();

  private key(capability: string, name: string): string {
    return `${capability}::${name}`;
  }

  record(tool: AdmittedTool): void {
    this.byKey.set(this.key(tool.capability, tool.name), { ...tool });
  }

  get(capability: string, name: string): AdmittedTool | undefined {
    return this.byKey.get(this.key(capability, name));
  }

  getByName(name: string): AdmittedTool | undefined {
    for (const t of this.byKey.values()) {
      if (t.name === name) return t;
    }
    return undefined;
  }

  listByCapability(capability: string): AdmittedTool[] {
    const out: AdmittedTool[] = [];
    for (const t of this.byKey.values()) {
      if (t.capability === capability) out.push(t);
    }
    return out;
  }

  list(): AdmittedTool[] {
    return [...this.byKey.values()];
  }

  clear(): void {
    this.byKey.clear();
  }

  size(): number {
    return this.byKey.size;
  }
}
