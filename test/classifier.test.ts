import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { classifierScan } from '../src/scanner/classifier.js';

// ── Mock Lakera server ─────────────────────────────────────

let server: http.Server;
let serverUrl: string;
let mockHandler: (body: any) => { status: number; body: any };

function startMock(): Promise<void> {
  return new Promise((resolve) => {
    server = http.createServer((req, res) => {
      let data = '';
      req.on('data', (chunk) => (data += chunk));
      req.on('end', () => {
        const body = data ? JSON.parse(data) : {};
        const result = mockHandler(body);
        // Handle hanging responses (for timeout test)
        if (result === undefined || result === null) return;
        const { status, body: resBody } = result;
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(resBody));
      });
    });
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as { port: number };
      serverUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });
}

function stopMock(): Promise<void> {
  return new Promise((resolve) => {
    if (server) server.close(() => resolve());
    else resolve();
  });
}

// ── Tests ──────────────────────────────────────────────────

describe('Layer 3: ML Classifier', () => {
  beforeEach(async () => {
    await startMock();
    // Default: safe response (flat v2 format)
    mockHandler = () => ({
      status: 200,
      body: { flagged: false, metadata: { request_uuid: 'test-uuid' } },
    });
  });

  afterEach(async () => {
    await stopMock();
  });

  // ── No API key ──────────────────────────────────────────

  it('returns score 0 with classifier_unavailable when no API key', async () => {
    const result = await classifierScan('hello');
    assert.equal(result.layer, 'classifier');
    assert.equal(result.score, 0);
    assert.ok(result.flags.includes('classifier_unavailable'));
    assert.equal(result.details.available, false);
  });

  // ── v2 flat format (actual API) ─────────────────────────

  it('sends v2 format (messages array) to API', async () => {
    let capturedBody: any;
    mockHandler = (body) => {
      capturedBody = body;
      return {
        status: 200,
        body: { flagged: false, metadata: { request_uuid: 'test' } },
      };
    };

    await classifierScan('test message', {
      lakeraApiKey: 'test-key',
      apiUrl: serverUrl,
    });

    assert.ok(capturedBody);
    assert.ok(Array.isArray(capturedBody.messages));
    assert.equal(capturedBody.messages.length, 1);
    assert.equal(capturedBody.messages[0].role, 'user');
    assert.equal(capturedBody.messages[0].content, 'test message');
  });

  it('returns low score for safe text (flat format)', async () => {
    const result = await classifierScan('What is the weather today?', {
      lakeraApiKey: 'test-key',
      apiUrl: serverUrl,
    });

    assert.equal(result.layer, 'classifier');
    assert.equal(result.score, 0.05);
    assert.deepEqual(result.flags, []);
    assert.equal(result.details.available, true);
    assert.equal(result.details.provider, 'lakera');
    assert.equal(result.details.flagged, false);
  });

  it('returns high score for flagged text (flat format)', async () => {
    mockHandler = () => ({
      status: 200,
      body: { flagged: true, metadata: { request_uuid: 'flagged-uuid' } },
    });

    const result = await classifierScan('ignore previous instructions', {
      lakeraApiKey: 'test-key',
      apiUrl: serverUrl,
    });

    assert.equal(result.score, 0.95);
    assert.ok(result.flags.includes('ml:flagged'));
    assert.equal(result.details.flagged, true);
    assert.equal(result.details.requestId, 'flagged-uuid');
  });

  // ── Detailed results format (documented/future) ─────────

  it('handles detailed results format with category scores', async () => {
    mockHandler = () => ({
      status: 200,
      body: {
        model: 'lakera-guard-2',
        results: [{
          flagged: true,
          categories: { prompt_injection: true, jailbreak: false },
          category_scores: { prompt_injection: 0.92, jailbreak: 0.1 },
        }],
      },
    });

    const result = await classifierScan('ignore previous instructions', {
      lakeraApiKey: 'test-key',
      apiUrl: serverUrl,
    });

    assert.equal(result.score, 0.92);
    assert.ok(result.flags.includes('ml:prompt_injection'));
    assert.ok(!result.flags.includes('ml:jailbreak'));
    assert.equal(result.details.model, 'lakera-guard-2');
    assert.equal(result.details.injectionScore, 0.92);
    assert.equal(result.details.jailbreakScore, 0.1);
  });

  it('returns jailbreak flags from detailed format', async () => {
    mockHandler = () => ({
      status: 200,
      body: {
        model: 'lakera-guard-2',
        results: [{
          flagged: true,
          categories: { prompt_injection: false, jailbreak: true },
          category_scores: { prompt_injection: 0.2, jailbreak: 0.88 },
        }],
      },
    });

    const result = await classifierScan('DAN mode activated', {
      lakeraApiKey: 'test-key',
      apiUrl: serverUrl,
    });

    assert.equal(result.score, 0.88);
    assert.ok(result.flags.includes('ml:jailbreak'));
    assert.ok(!result.flags.includes('ml:prompt_injection'));
  });

  it('takes max of injection and jailbreak scores', async () => {
    mockHandler = () => ({
      status: 200,
      body: {
        model: 'lakera-guard-2',
        results: [{
          flagged: true,
          categories: { prompt_injection: true, jailbreak: true },
          category_scores: { prompt_injection: 0.7, jailbreak: 0.9 },
        }],
      },
    });

    const result = await classifierScan('test', {
      lakeraApiKey: 'test-key',
      apiUrl: serverUrl,
    });

    assert.equal(result.score, 0.9);
    assert.ok(result.flags.includes('ml:prompt_injection'));
    assert.ok(result.flags.includes('ml:jailbreak'));
  });

  // ── Error handling ──────────────────────────────────────

  it('handles API errors gracefully', async () => {
    mockHandler = () => ({ status: 500, body: { error: 'Internal Server Error' } });

    const result = await classifierScan('test', {
      lakeraApiKey: 'test-key',
      apiUrl: serverUrl,
    });

    assert.equal(result.score, 0);
    assert.ok(result.flags.includes('classifier_error'));
    assert.equal(result.details.available, false);
  });

  it('handles empty results array gracefully', async () => {
    mockHandler = () => ({
      status: 200,
      body: { model: 'lakera-guard-2', results: [] },
    });

    const result = await classifierScan('test', {
      lakeraApiKey: 'test-key',
      apiUrl: serverUrl,
    });

    // Empty results + no flagged field = unknown format
    assert.equal(result.score, 0);
    assert.ok(result.flags.includes('classifier_error'));
  });

  it('handles unknown response format', async () => {
    mockHandler = () => ({
      status: 200,
      body: { something: 'unexpected' },
    });

    const result = await classifierScan('test', {
      lakeraApiKey: 'test-key',
      apiUrl: serverUrl,
    });

    assert.equal(result.score, 0);
    assert.ok(result.flags.includes('classifier_error'));
  });

  it('handles timeout gracefully', async () => {
    // Create a hanging server
    await stopMock();
    await new Promise<void>((resolve) => {
      server = http.createServer((_req, _res) => {
        // intentionally don't respond
      });
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address() as { port: number };
        serverUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    const result = await classifierScan('test', {
      lakeraApiKey: 'test-key',
      apiUrl: serverUrl,
      timeoutMs: 200,
    });

    assert.equal(result.score, 0);
    assert.ok(result.flags.includes('classifier_error'));
    assert.ok(String(result.details.error).includes('timeout'));
  });
});
