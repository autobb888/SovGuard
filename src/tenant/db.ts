/**
 * SovGuard — SQLite Database Setup & Migrations
 */

import Database from 'better-sqlite3';

let db: Database.Database | null = null;

/**
 * Get or create the database singleton.
 * Retries up to 3 times with exponential backoff (100ms, 200ms, 400ms)
 * if the initial connection fails (e.g., locked file, disk I/O error).
 */
export function getDb(): Database.Database {
  if (db) return db;
  const dbPath = process.env.SOVGUARD_DB_PATH || './sovguard.db';
  const MAX_RETRIES = 3;
  const BASE_DELAY_MS = 100;

  let lastError: unknown;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    try {
      db = new Database(dbPath);
      db.pragma('journal_mode = WAL');
      db.pragma('foreign_keys = ON');
      db.pragma('busy_timeout = 5000');         // wait up to 5s for locks instead of failing
      db.pragma('wal_autocheckpoint = 1000');    // checkpoint every 1000 pages (~4MB)
      runMigrations(db);
      return db;
    } catch (err) {
      lastError = err;
      db = null;
      if (attempt < MAX_RETRIES) {
        // Exponential backoff: 100ms, 200ms, 400ms
        const delay = BASE_DELAY_MS * Math.pow(2, attempt);
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, delay);
      }
    }
  }
  throw lastError instanceof Error ? lastError : new Error(`Failed to open database after ${MAX_RETRIES + 1} attempts`);
}

/** Initialize with an existing Database instance (for testing). */
export function setDb(instance: Database.Database): void {
  runMigrations(instance);
  db = instance;
}

/** Close and reset the singleton (for testing). */
export function closeDb(): void {
  if (db) {
    db.close();
    db = null;
  }
}

function runMigrations(database: Database.Database): void {
  // Migration: canary_tokens table for persistence across restarts
  database.exec(`
    CREATE TABLE IF NOT EXISTS canary_tokens (
      session_id TEXT PRIMARY KEY,
      token TEXT NOT NULL,
      injection_text TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_canary_tokens_created ON canary_tokens(created_at);
  `);

  // Migration: audit_log table for API activity tracking
  database.exec(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      key_prefix TEXT,
      event_type TEXT NOT NULL,
      payload TEXT NOT NULL DEFAULT '{}',
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at);
    CREATE INDEX IF NOT EXISTS idx_audit_log_tenant ON audit_log(tenant_id, created_at);
  `);

  // Migration: scan_log table for ops monitor
  database.exec(`
    CREATE TABLE IF NOT EXISTS scan_log (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      key_prefix TEXT,
      direction TEXT NOT NULL DEFAULT 'inbound',
      input_text TEXT NOT NULL,
      score REAL NOT NULL,
      classification TEXT NOT NULL,
      flags TEXT NOT NULL DEFAULT '[]',
      layers TEXT NOT NULL DEFAULT '[]',
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_scan_log_created ON scan_log(created_at);
    CREATE INDEX IF NOT EXISTS idx_scan_log_tenant ON scan_log(tenant_id, created_at);
  `);

  // Migration: scan_reports table for false positive/negative feedback
  database.exec(`
    CREATE TABLE IF NOT EXISTS scan_reports (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      key_prefix TEXT,
      content_hash TEXT NOT NULL,
      file_path TEXT,
      score REAL NOT NULL,
      mime_type TEXT,
      workspace_uid TEXT,
      verdict TEXT NOT NULL,
      notes TEXT,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_scan_reports_tenant ON scan_reports(tenant_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_scan_reports_verdict ON scan_reports(verdict);
  `);
}
