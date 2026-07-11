#!/usr/bin/env node
/**
 * Claude Code PreToolUse hook — scans tool inputs through SovGuard before execution.
 * Install: add to .claude/settings.json hooks.PreToolUse with this script as command.
 * Env: SOVGUARD_API_BASE, SOVGUARD_API_KEY, SOVGUARD_BLOCK_THRESHOLD, SOVGUARD_FAIL_CLOSED.
 */
import { readFileSync } from 'node:fs';

const API_BASE = (process.env.SOVGUARD_API_BASE || 'https://api.sovguard.io').replace(/\/$/, '');
const API_KEY = process.env.SOVGUARD_API_KEY || '';
const BLOCK = Number(process.env.SOVGUARD_BLOCK_THRESHOLD || '0.7');

function textFromToolInput(input) {
  if (!input || typeof input !== 'object') return '';
  return [input.content, input.command, input.prompt, input.new_string, input.query]
    .filter((v) => typeof v === 'string').join('\n');
}

async function main() {
  const payload = JSON.parse(readFileSync(0, 'utf8'));
  const text = textFromToolInput(payload.tool_input);
  if (!text.trim()) { process.exit(0); }
  let result;
  try {
    const resp = await fetch(`${API_BASE}/v1/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': API_KEY },
      body: JSON.stringify({ text }),
      signal: AbortSignal.timeout(5000),
    });
    result = await resp.json();
  } catch (e) {
    console.error(`[sovguard] scan failed (${e.message}) — allowing; set SOVGUARD_FAIL_CLOSED=1 to block on error.`);
    process.exit(process.env.SOVGUARD_FAIL_CLOSED === '1' ? 2 : 0);
  }
  if (!result.safe && (result.score ?? 0) >= BLOCK) {
    console.log(JSON.stringify({
      decision: 'block',
      reason: `SovGuard blocked this tool call: ${result.classification} (score ${result.score}). `
            + `Flags: ${(result.flags || []).map((f) => f.type).slice(0, 5).join(', ')}`,
    }));
    process.exit(0);
  }
  process.exit(0);
}
main();
