/**
 * DL-005 — MCP / tool-schema integrity.
 * Treat tool descriptions and arg docs as untrusted; persist schemaHash at
 * consent; reject rug-pulls; quarantine cross-server name shadowing.
 *
 * Hash / doc collection cover MCP display+behavior fields: name, title,
 * description, inputSchema|parameters, annotations (allowlisted).
 */
import { createHash } from 'node:crypto';
import type { Classification, LayerResult } from '../types.js';
import { normalizeToFixedPoint } from './regex.js';
import { runJsLayersSync } from './js-layers.js';
import { combineScores } from './index.js';

/** Keys included in schemaHash + doc scan (MCP-relevant display/behavior). */
export const TOOL_SCHEMA_INTEGRITY_KEYS = [
  'name',
  'title',
  'description',
  'inputSchema',
  'parameters',
  'annotations',
] as const;

/** Minimal MCP-style tool schema surface. */
export interface ToolSchema {
  name: string;
  title?: string;
  description?: string;
  /** JSON Schema for args (MCP-style). */
  inputSchema?: {
    type?: string;
    properties?: Record<string, { description?: string; type?: string; [k: string]: unknown }>;
    required?: string[];
    [k: string]: unknown;
  };
  /** Alias used by some MCP hosts / Threat Scout fixtures. */
  parameters?: {
    type?: string;
    properties?: Record<string, { description?: string; type?: string; [k: string]: unknown }>;
    required?: string[];
    [k: string]: unknown;
  };
  /** MCP ToolAnnotations — titles / hints that hosts may surface to the model. */
  annotations?: Record<string, unknown>;
  [k: string]: unknown;
}

function argSchema(schema: ToolSchema) {
  return schema.inputSchema ?? schema.parameters;
}

export type ToolSchemaAction = 'allow' | 'quarantine' | 'block';

export interface ToolSchemaScanResult {
  schemaHash: string;
  textScanned: string;
  layers: LayerResult[];
  score: number;
  classification: Classification;
  flags: string[];
  action: ToolSchemaAction;
}

export interface ConsentedToolSchema {
  serverId: string;
  toolName: string;
  schemaHash: string;
}

export interface RugPullCheck {
  ok: boolean;
  rugPull: boolean;
  reason?: string;
  consentedHash: string;
  currentHash: string;
}

export interface RegisteredTool {
  serverId: string;
  /** Higher trust wins name collisions (user-approved / first-party). */
  trust: number;
  schema: ToolSchema;
}

export interface ShadowingResult {
  active: RegisteredTool[];
  quarantined: Array<{
    tool: RegisteredTool;
    reason: string;
    shadowedBy: { serverId: string; trust: number };
  }>;
}

/** Recursively collect string leaves from annotations / nested objects. */
function collectStrings(value: unknown, out: string[], depth = 0): void {
  if (depth > 8) return;
  if (typeof value === 'string') {
    const t = value.trim();
    if (t) out.push(t);
    return;
  }
  if (Array.isArray(value)) {
    for (const v of value) collectStrings(v, out, depth + 1);
    return;
  }
  if (value && typeof value === 'object') {
    for (const v of Object.values(value as Record<string, unknown>)) {
      collectStrings(v, out, depth + 1);
    }
  }
}

/** Collect description + property docs + title + annotations for untrusted scan. */
export function collectSchemaDocs(schema: ToolSchema): string {
  const parts: string[] = [];
  if (typeof schema.title === 'string' && schema.title.trim()) {
    parts.push(schema.title);
  }
  if (typeof schema.description === 'string' && schema.description.trim()) {
    parts.push(schema.description);
  }
  const props = argSchema(schema)?.properties;
  if (props && typeof props === 'object') {
    for (const [key, val] of Object.entries(props)) {
      if (val && typeof val === 'object' && typeof val.description === 'string' && val.description.trim()) {
        parts.push(`${key}: ${val.description}`);
      }
    }
  }
  if (schema.annotations != null) {
    collectStrings(schema.annotations, parts);
  }
  return parts.join('\n');
}

/** Canonical JSON for hashing (sorted keys). */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(',')}}`;
}

/**
 * Persistable integrity hash over allowlisted MCP fields.
 * Call at consent time; compare on later tool listing / call.
 */
export function hashToolSchema(schema: ToolSchema): string {
  const payload: Record<string, unknown> = {
    name: schema.name,
    title: schema.title ?? null,
    description: schema.description ?? '',
    // Prefer inputSchema; fall back to parameters (same as argSchema)
    inputSchema: argSchema(schema) ?? null,
    annotations: schema.annotations ?? null,
  };
  return createHash('sha256').update(stableStringify(payload)).digest('hex');
}

function classifyFromScore(score: number): Classification {
  if (score >= 0.7) return 'likely_injection';
  if (score >= 0.3) return 'suspicious';
  return 'safe';
}

/**
 * Scan a tool schema: description/arg docs/title/annotations are untrusted.
 * Runs Unicode fixed-point + JS layers (regex/indirect).
 */
export function scanToolSchema(
  schema: ToolSchema,
  opts?: { enablePerplexity?: boolean },
): ToolSchemaScanResult {
  const raw = collectSchemaDocs(schema);
  const fp = normalizeToFixedPoint(raw || schema.name);
  const textScanned = fp.text;
  const layers = runJsLayersSync(textScanned, opts?.enablePerplexity === true);
  const score = combineScores(layers);
  const classification = classifyFromScore(score);

  const flags: string[] = [];
  if (fp.signals.length > 0) flags.push(...fp.signals.map((s) => `unicode:${s}`));
  for (const layer of layers) {
    if (layer.score >= 0.3) {
      flags.push(`layer:${layer.layer}`);
      for (const f of layer.flags ?? []) flags.push(`flag:${f}`);
    }
  }
  if (classification !== 'safe') flags.push('poisoned_docstring');

  let action: ToolSchemaAction = 'allow';
  if (classification === 'likely_injection') action = 'block';
  else if (classification === 'suspicious') action = 'quarantine';

  return {
    schemaHash: hashToolSchema(schema),
    textScanned,
    layers,
    score,
    classification,
    flags: [...new Set(flags)],
    action,
  };
}

/** Reject schema mutation after consent without re-consent (MCPoison / rug-pull). */
export function checkSchemaConsent(
  consented: ConsentedToolSchema,
  current: ToolSchema,
): RugPullCheck {
  const currentHash = hashToolSchema(current);
  if (consented.toolName !== current.name) {
    return {
      ok: false,
      rugPull: true,
      reason: `tool name changed after consent (${consented.toolName} → ${current.name})`,
      consentedHash: consented.schemaHash,
      currentHash,
    };
  }
  if (consented.schemaHash !== currentHash) {
    return {
      ok: false,
      rugPull: true,
      reason: 'schemaHash changed without re-consent (rug_pull)',
      consentedHash: consented.schemaHash,
      currentHash,
    };
  }
  return {
    ok: true,
    rugPull: false,
    consentedHash: consented.schemaHash,
    currentHash,
  };
}

/**
 * Cross-server name collision: keep highest-trust registration; quarantine
 * lower-trust duplicates (shadowing).
 */
export function resolveToolShadowing(tools: RegisteredTool[]): ShadowingResult {
  const byName = new Map<string, RegisteredTool[]>();
  for (const t of tools) {
    const name = t.schema.name;
    const list = byName.get(name) ?? [];
    list.push(t);
    byName.set(name, list);
  }

  const active: RegisteredTool[] = [];
  const quarantined: ShadowingResult['quarantined'] = [];

  for (const [, group] of byName) {
    if (group.length === 1) {
      active.push(group[0]);
      continue;
    }
    const sorted = [...group].sort((a, b) => b.trust - a.trust || a.serverId.localeCompare(b.serverId));
    const winner = sorted[0];
    active.push(winner);
    for (const loser of sorted.slice(1)) {
      quarantined.push({
        tool: loser,
        reason: `schema_shadowing: tool "${loser.schema.name}" shadowed by higher-trust server`,
        shadowedBy: { serverId: winner.serverId, trust: winner.trust },
      });
    }
  }

  return { active, quarantined };
}

/** In-memory consent ledger for hosts that do not persist their own. */
export class SchemaConsentStore {
  private store = new Map<string, ConsentedToolSchema>();

  private key(serverId: string, toolName: string): string {
    return `${serverId}::${toolName}`;
  }

  record(serverId: string, schema: ToolSchema): ConsentedToolSchema {
    const entry: ConsentedToolSchema = {
      serverId,
      toolName: schema.name,
      schemaHash: hashToolSchema(schema),
    };
    this.store.set(this.key(serverId, schema.name), entry);
    return entry;
  }

  get(serverId: string, toolName: string): ConsentedToolSchema | undefined {
    return this.store.get(this.key(serverId, toolName));
  }

  /**
   * Verify current schema against stored consent.
   * Missing consent → ok:false rugPull:false (not yet consented).
   */
  verify(serverId: string, schema: ToolSchema): RugPullCheck & { consented: boolean } {
    const prior = this.get(serverId, schema.name);
    if (!prior) {
      return {
        ok: false,
        rugPull: false,
        consented: false,
        reason: 'no consent recorded',
        consentedHash: '',
        currentHash: hashToolSchema(schema),
      };
    }
    return { ...checkSchemaConsent(prior, schema), consented: true };
  }

  clear(): void {
    this.store.clear();
  }
}
