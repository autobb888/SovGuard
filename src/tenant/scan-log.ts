/**
 * DL-011c — thin scan_log writer (additive mode / mode_source columns).
 */
import { randomUUID } from 'crypto';
import { getDb } from './db.js';
import type { ScanMode, ModeSource } from '../scanner/scan-mode.js';

export interface ScanLogEntry {
  tenantId?: string;
  keyPrefix?: string | null;
  direction?: 'inbound' | 'outbound';
  inputText: string;
  score: number;
  classification: string;
  flags?: string[];
  layers?: unknown[];
  mode?: ScanMode;
  modeSource?: ModeSource;
}

export function recordScanLog(entry: ScanLogEntry): string {
  const id = randomUUID();
  const now = Date.now();
  getDb().prepare(`
    INSERT INTO scan_log (
      id, tenant_id, key_prefix, direction, input_text, score, classification,
      flags, layers, created_at, mode, mode_source
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    entry.tenantId ?? 'self-hosted',
    entry.keyPrefix ?? null,
    entry.direction ?? 'inbound',
    entry.inputText.slice(0, 50000),
    entry.score,
    entry.classification,
    JSON.stringify(entry.flags ?? []),
    JSON.stringify(entry.layers ?? []),
    now,
    entry.mode ?? null,
    entry.modeSource ?? null,
  );
  return id;
}
