/**
 * Tenant Database
 * Opens the SQLite database and runs all schema migrations idempotently.
 */

import Database from 'better-sqlite3';

let database: Database.Database | null = null;

export function getDatabase(): Database.Database {
  if (!database) {
    throw new Error('Database not initialized. Call initDatabase() first.');
  }
  return database;
}

export function initDatabase(path: string): Database.Database {
  database = new Database(path);
  database.pragma('journal_mode = WAL');
  database.pragma('foreign_keys = ON');
  runMigrations(database);
  return database;
}

export function closeDatabase(): void {
  if (database) {
    database.close();
    database = null;
  }
}

export function runMigrations(db: Database.Database): void {
  // Migration: canary_tokens table
  db.exec(`
    CREATE TABLE IF NOT EXISTS canary_tokens (
      session_id TEXT PRIMARY KEY,
      token TEXT NOT NULL,
      injection_text TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
  `);

  // Migration: audit_log table
  db.exec(`
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
  db.exec(`
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
}
