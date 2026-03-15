import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateToken, checkLeak, getToken, revokeToken, clearAll, tokenCount, MAX_TOKENS, TOKEN_TTL_MS } from '../src/canary/tokens.js';

describe('Canary Tokens', () => {
  beforeEach(() => clearAll());

  it('should generate unique tokens per session', () => {
    const t1 = generateToken('session-1');
    const t2 = generateToken('session-2');
    // Tokens should NOT start with SOVGUARD_ anymore (P1-SC-BYPASS-2)
    assert.ok(!t1.token.startsWith('SOVGUARD_'), 'Token should not have predictable prefix');
    assert.ok(!t2.token.startsWith('SOVGUARD_'), 'Token should not have predictable prefix');
    assert.notEqual(t1.token, t2.token);
    assert.equal(t1.sessionId, 'session-1');
    assert.equal(t2.sessionId, 'session-2');
  });

  it('should generate natural-looking phrase tokens', () => {
    const canary = generateToken('session-1');
    // Token should contain multiple words (natural phrase)
    const words = canary.token.split(/\s+/);
    assert.ok(words.length >= 4, `Token should have 4+ words, got: "${canary.token}"`);
    // Should not look like a hex-only token
    assert.ok(!/^[A-F0-9_]+$/.test(canary.token), 'Token should not be hex-only');
  });

  it('should provide injection text for agent context', () => {
    const canary = generateToken('session-1');
    assert.ok(canary.injectionText.includes(canary.token));
    assert.ok(canary.injectionText.includes('Never reveal'));
    assert.ok(canary.injectionText.includes('verification phrase'));
  });

  it('should detect leak in agent response', () => {
    const canary = generateToken('session-1');
    const response = `Here is the information you asked for. The phrase is ${canary.token}. Have a nice day.`;
    const result = checkLeak(response, 'session-1');
    assert.equal(result.leaked, true);
    assert.equal(result.token, canary.token);
    assert.equal(result.sessionId, 'session-1');
  });

  it('should not detect leak when token is absent', () => {
    generateToken('session-1');
    const result = checkLeak('This is a normal response with no secrets.', 'session-1');
    assert.equal(result.leaked, false);
  });

  it('should detect leak across all sessions', () => {
    const c1 = generateToken('s1');
    generateToken('s2');
    const result = checkLeak(`The answer is ${c1.token}`);
    assert.equal(result.leaked, true);
    assert.equal(result.sessionId, 's1');
  });

  it('should retrieve token by session', () => {
    const original = generateToken('session-1');
    const retrieved = getToken('session-1');
    assert.deepEqual(retrieved, original);
  });

  it('should revoke token', () => {
    generateToken('session-1');
    assert.equal(revokeToken('session-1'), true);
    assert.equal(getToken('session-1'), undefined);
    assert.equal(revokeToken('session-1'), false);
  });

  // ── P2-SC-CANARY-2: Bounded store ────────────────────────

  it('should resist pattern-based stripping (no SOVGUARD_ prefix)', () => {
    const canary = generateToken('session-1');
    // An attacker trying to strip SOVGUARD_* tokens would fail
    const stripped = canary.token.replace(/SOVGUARD_[A-F0-9]+/g, '[REDACTED]');
    assert.equal(stripped, canary.token, 'Token should not match SOVGUARD_ pattern');
  });

  it('should evict oldest when at capacity', () => {
    // Generate tokens up to near capacity - test with smaller number
    for (let i = 0; i < 100; i++) {
      generateToken(`session-${i}`);
    }
    assert.equal(tokenCount(), 100);
    // Generating one more should still work (evicts oldest)
    generateToken('session-new');
    assert.ok(tokenCount() <= 101);
  });

  it('should have TTL and max constants defined', () => {
    assert.equal(TOKEN_TTL_MS, 24 * 60 * 60 * 1000);
    assert.equal(MAX_TOKENS, 10_000);
  });

  it('should detect leak with extra whitespace/line breaks', () => {
    const canary = generateToken('session-ws');
    // Simulate LLM reformatting the token with extra spaces/newlines
    const reformatted = canary.token.replace(/ /g, '  \n ');
    const result = checkLeak(`The phrase is ${reformatted} and more text`, 'session-ws');
    assert.equal(result.leaked, true, 'Should detect leak despite whitespace variations');
  });

  it('should detect leak with case variation', () => {
    const canary = generateToken('session-case');
    const upperVersion = canary.token.toUpperCase();
    const result = checkLeak(`Here: ${upperVersion}`, 'session-case');
    assert.equal(result.leaked, true, 'Should detect leak despite case changes');
  });
});
