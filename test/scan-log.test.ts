import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import { randomUUID } from 'crypto';

describe('scan_log table', () => {
  let db: Database.Database;

  before(() => {
    db = new Database(':memory:');
    db.pragma('journal_mode = WAL');
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
  });

  after(() => { db.close(); });

  it('should insert and retrieve a scan log entry', () => {
    const id = randomUUID();
    const now = Date.now();
    db.prepare(`
      INSERT INTO scan_log (id, tenant_id, key_prefix, direction, input_text, score, classification, flags, layers, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, 'tenant-1', 'sg_abc1', 'inbound', 'test message', 0.85, 'likely_injection',
      JSON.stringify(['instruction_override:system_prompt']),
      JSON.stringify([{ layer: 'regex', score: 0.85, flags: ['instruction_override:system_prompt'] }]),
      now
    );

    const row = db.prepare('SELECT * FROM scan_log WHERE id = ?').get(id) as any;
    assert.equal(row.tenant_id, 'tenant-1');
    assert.equal(row.key_prefix, 'sg_abc1');
    assert.equal(row.direction, 'inbound');
    assert.equal(row.input_text, 'test message');
    assert.equal(row.score, 0.85);
    assert.equal(row.classification, 'likely_injection');
    assert.deepEqual(JSON.parse(row.flags), ['instruction_override:system_prompt']);
    assert.equal(JSON.parse(row.layers)[0].layer, 'regex');
  });

  it('should query by created_at for pruning', () => {
    const old = Date.now() - 31 * 24 * 60 * 60 * 1000;
    const recent = Date.now();
    db.prepare(`INSERT INTO scan_log (id, tenant_id, direction, input_text, score, classification, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run(randomUUID(), 't1', 'inbound', 'old', 0.1, 'safe', old);
    db.prepare(`INSERT INTO scan_log (id, tenant_id, direction, input_text, score, classification, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run(randomUUID(), 't1', 'inbound', 'new', 0.2, 'safe', recent);

    const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
    const deleted = db.prepare('DELETE FROM scan_log WHERE created_at < ?').run(cutoff);
    assert.equal(deleted.changes, 1);

    const remaining = db.prepare('SELECT COUNT(*) as c FROM scan_log WHERE tenant_id = ?').get('t1') as any;
    assert.equal(remaining.c, 1);
  });
});
