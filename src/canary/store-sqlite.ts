/**
 * SQLite-backed Canary Token Store
 * Drop-in replacement for the in-memory Map so tokens survive container restarts.
 */

import type Database from 'better-sqlite3';
import type { CanaryToken } from '../types.js';
import type { CanaryStore } from './tokens.js';

export function createSqliteCanaryStore(db: Database.Database): CanaryStore {
  const stmts = {
    get: db.prepare<[string], { session_id: string; token: string; injection_text: string; created_at: number }>(
      `SELECT session_id, token, injection_text, created_at FROM canary_tokens WHERE session_id = ?`,
    ),
    set: db.prepare<[string, string, string, number]>(
      `INSERT OR REPLACE INTO canary_tokens (session_id, token, injection_text, created_at) VALUES (?, ?, ?, ?)`,
    ),
    del: db.prepare<[string]>(`DELETE FROM canary_tokens WHERE session_id = ?`),
    all: db.prepare<[], { session_id: string; token: string; injection_text: string; created_at: number }>(
      `SELECT session_id, token, injection_text, created_at FROM canary_tokens`,
    ),
    count: db.prepare<[], { cnt: number }>(`SELECT COUNT(*) as cnt FROM canary_tokens`),
    clear: db.prepare(`DELETE FROM canary_tokens`),
    evictExpired: db.prepare<[number]>(`DELETE FROM canary_tokens WHERE created_at < ?`),
    evictOldest: db.prepare(`DELETE FROM canary_tokens WHERE rowid = (SELECT rowid FROM canary_tokens ORDER BY created_at ASC LIMIT 1)`),
  };

  function rowToToken(row: { session_id: string; token: string; injection_text: string; created_at: number }): CanaryToken {
    return {
      token: row.token,
      sessionId: row.session_id,
      createdAt: row.created_at,
      injectionText: row.injection_text,
    };
  }

  return {
    get(sessionId: string): CanaryToken | undefined {
      const row = stmts.get.get(sessionId);
      return row ? rowToToken(row) : undefined;
    },

    set(sessionId: string, token: CanaryToken): void {
      stmts.set.run(sessionId, token.token, token.injectionText, token.createdAt);
    },

    delete(sessionId: string): boolean {
      const result = stmts.del.run(sessionId);
      return result.changes > 0;
    },

    entries(): IterableIterator<[string, CanaryToken]> {
      const rows = stmts.all.all();
      let i = 0;
      return {
        [Symbol.iterator]() { return this; },
        next() {
          if (i >= rows.length) return { done: true as const, value: undefined };
          const row = rows[i++];
          return { done: false, value: [row.session_id, rowToToken(row)] as [string, CanaryToken] };
        },
      };
    },

    get size(): number {
      return stmts.count.get()!.cnt;
    },

    clear(): void {
      stmts.clear.run();
    },

    evictExpired(cutoff: number): void {
      stmts.evictExpired.run(cutoff);
    },

    evictOldest(): void {
      stmts.evictOldest.run();
    },
  };
}
