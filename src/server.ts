/**
 * SovGuard HTTP Server
 * Optional Fastify server exposing REST API for scanning, wrapping, and canary tokens.
 */

import Fastify from 'fastify';
import rateLimit from '@fastify/rate-limit';
import { z } from 'zod';
import { timingSafeEqual, createHash, randomUUID } from 'crypto';
import { SovGuardEngine } from './index.js';
import { getDb } from './tenant/db.js';
import { scanPool, ScanPoolSaturatedError } from './scanner/scan-pool.js';
import { ScanBody, ScanFileBody, ScanFileContentBody, ScanOutputBody, ScanReportBody, WrapBody, CanaryCreateBody, CanaryCheckBody } from './schemas.js';
import { version } from './version.js';

const API_KEY = process.env.SOVGUARD_API_KEY;
if (!API_KEY) {
  console.error('SOVGUARD_API_KEY environment variable is required');
  process.exit(1);
}

/** Constant-time string comparison to prevent timing attacks (P1-SC-003) */
function safeCompare(a: string, b: string): boolean {
  const aBuf = createHash('sha256').update(a).digest();
  const bBuf = createHash('sha256').update(b).digest();
  return timingSafeEqual(aBuf, bBuf);
}

import { isLocalModelAvailable } from './scanner/classifier-local.js';
import { checkDetectionHealth, type DetectionHealth } from './scanner/model-health.js';

let detectionHealth: DetectionHealth | null = null; // set at startup; surfaced on /health

const engine = new SovGuardEngine({
  enableClassifier: !!process.env.LAKERA_API_KEY || isLocalModelAvailable(),
  lakeraApiKey: process.env.LAKERA_API_KEY,
  classifierMode: (process.env.SOVGUARD_CLASSIFIER_MODE as 'local' | 'lakera' | 'auto') || 'auto',
});

const app = Fastify({
  logger: true,
  bodyLimit: 131072,            // 128KB max request body (matches ScanFileContentBody cap)
  connectionTimeout: 30_000,    // 30s to complete the TCP/HTTP handshake
  keepAliveTimeout: 72_000,     // 72s idle — above typical 60s proxy timeout
  requestTimeout: 30_000,       // 30s to receive a full request (slowloris guard); well above worst-case scan time
});

// ── Rate Limiting ────────────────────────────────────────────────

app.register(rateLimit, {
  max: 100,
  timeWindow: '1 minute',
});

// ── Authentication ───────────────────────────────────────────────

app.addHook('preHandler', async (req, reply) => {
  if (req.method === 'GET' && req.url.startsWith('/health')) return;
  const key = req.headers['x-api-key'] as string | undefined;
  if (!key || !safeCompare(key, API_KEY)) {
    reply.status(401).send({ error: 'Unauthorized. Provide a valid API key via the X-API-Key header.' });
    return;
  }
});

// ── Routes ───────────────────────────────────────────────────────

app.post('/v1/scan', async (req) => {
  const body = ScanBody.parse(req.body);
  const result = await engine.scan(body.text);
  return result;
});

app.post('/v1/scan/file', async (req) => {
  const body = ScanFileBody.parse(req.body);
  const result = engine.scanFile(body.filename, body.metadata);
  return result;
});

app.post('/v1/scan/file/content', async (req) => {
  const body = ScanFileContentBody.parse(req.body);
  const buffer = Buffer.from(body.content, 'base64');
  const result = engine.scanFileContent(buffer, body.mimeType, {
    maxExtractBytes: body.maxExtractBytes,
    chunkSize: body.chunkSize,
  });
  return result;
});

app.post('/v1/scan/output', async (req) => {
  const body = ScanOutputBody.parse(req.body);
  const context = {
    jobId: body.jobId,
    jobCategory: body.jobCategory,
    whitelistedAddresses: body.whitelistedAddresses
      ? new Set(body.whitelistedAddresses)
      : undefined,
  };
  const result = await engine.scanOutput(body.text, context);
  return result;
});

app.post('/v1/wrap', async (req) => {
  const body = WrapBody.parse(req.body);
  const scanResult = await engine.scan(body.text);
  const wrapped = engine.wrap(body.text, scanResult, {
    role: body.role,
    jobId: body.jobId,
    sessionId: body.sessionId,
  });
  return { scan: scanResult, wrapped };
});

app.post('/v1/canary/create', {
  config: { rateLimit: { max: 20, timeWindow: '1 minute' } },
}, async (req) => {
  const body = CanaryCreateBody.parse(req.body);
  const canary = engine.createCanary(body.sessionId);
  return canary;
});

app.post('/v1/canary/check', async (req) => {
  const body = CanaryCheckBody.parse(req.body);
  const result = engine.checkCanary(body.text, body.sessionId);
  return result;
});

app.post('/v1/report', async (req) => {
  const body = ScanReportBody.parse(req.body);
  const id = randomUUID();
  const now = Date.now();
  getDb().prepare(`
    INSERT INTO scan_reports (id, tenant_id, key_prefix, content_hash, file_path, score, mime_type, workspace_uid, verdict, notes, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, 'self-hosted', null, body.content_hash, body.file_path ?? null, body.score, body.mime_type ?? null, body.workspace_uid ?? null, body.verdict, body.notes ?? null, now);
  return { id, status: 'received' };
});

app.get('/v1/stats', async () => {
  return engine.getStats();
});

app.get('/health', async () => {
  return {
    status: 'ok',
    version,
    mode: 'standalone',
    detection: detectionHealth
      ? {
          healthy: detectionHealth.healthy,
          classifierActive: detectionHealth.classifierActive,
          degraded: detectionHealth.degraded,
          ...(detectionHealth.reason ? { reason: detectionHealth.reason } : {}),
        }
      : { healthy: null },
  };
});

// ── Error handler ────────────────────────────────────────────────

app.setErrorHandler((error, req, reply) => {
  if (error instanceof ScanPoolSaturatedError) {
    // H3: scan pool saturated under overload — refuse the request, never a fake verdict.
    reply.status(503).send({ error: 'Scanner busy, please retry shortly.' });
  } else if (error instanceof z.ZodError) {
    reply.status(400).send({ error: 'Validation error', details: error.errors.map(e => ({ field: e.path.join('.'), message: e.message })) });
  } else if ((error as any).statusCode && (error as any).statusCode < 500) {
    reply.status((error as any).statusCode).send({ error: 'Request error' });
  } else {
    req.log.error(error);
    reply.status(500).send({ error: 'Internal server error' });
  }
});

// ── Start ────────────────────────────────────────────────────────

const PORT = parseInt(process.env.SOVGUARD_PORT || '3100', 10);
if (isNaN(PORT) || PORT < 1 || PORT > 65535) {
  console.error(`Invalid SOVGUARD_PORT: ${process.env.SOVGUARD_PORT}`);
  process.exit(1);
}
const HOST = process.env.SOVGUARD_HOST || '127.0.0.1';

// Verify the detection stack catches a known injection before serving. Regex-only
// (no ML classifier) catches ~40% and silently misses paraphrase/typo/multilingual/
// indirect attacks. SOVGUARD_REQUIRE_MODELS=1 refuses to serve in that state.
async function start(): Promise<void> {
  detectionHealth = await checkDetectionHealth((t) => engine.scan(t));
  const requireModels = process.env.SOVGUARD_REQUIRE_MODELS === '1' || process.env.SOVGUARD_REQUIRE_MODELS === 'true';
  if (!detectionHealth.healthy) {
    if (requireModels) {
      console.error(`[FATAL] Detection DEGRADED — ${detectionHealth.reason}. SOVGUARD_REQUIRE_MODELS is set; refusing to serve in degraded mode.`);
      process.exit(1);
    }
    console.warn(`[security] Detection DEGRADED — ${detectionHealth.reason}. Serving anyway (set SOVGUARD_REQUIRE_MODELS=1 to fail-closed); /health reports degraded.`);
  } else {
    console.log('[security] Detection self-check passed — ML classifier active, known injection flagged.');
  }

  app.listen({ port: PORT, host: HOST }, (err) => {
    if (err) {
      console.error(err);
      process.exit(1);
    }
    console.log(`SovGuard Engine listening on ${HOST}:${PORT}`);
  });
}

start().catch((err) => {
  console.error('Startup failed:', err);
  process.exit(1);
});

// ── Graceful Shutdown ────────────────────────────────────────────

async function shutdown(signal: string): Promise<void> {
  console.log(`\n${signal} received — shutting down gracefully...`);
  try {
    await app.close();
  } catch (err) {
    console.error('Error closing Fastify:', err);
  }
  try {
    await scanPool.shutdown();   // H3: terminate scan workers
  } catch {
    // best effort
  }
  try {
    const { stopCleanup } = await import('./canary/tokens.js');
    stopCleanup();
  } catch {
    // best effort
  }
  try {
    const { closeDb } = await import('./tenant/db.js');
    closeDb();
  } catch {
    // best effort
  }
  console.log('Shutdown complete.');
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

export default app;
