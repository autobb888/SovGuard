/**
 * SovGuard guardrail middleware for the Vercel AI SDK.
 *
 * A `LanguageModelV1Middleware` for the `wrapLanguageModel({ model, middleware })`
 * pattern. In `transformParams` it extracts the user prompt from the call params,
 * scans it through SovGuard (`POST {apiBase}/v1/scan`), and throws before the model
 * is ever called if the verdict is unsafe at/above the block threshold.
 *
 * Usage:
 *   import { wrapLanguageModel } from 'ai';
 *   import { openai } from '@ai-sdk/openai';
 *   import { sovguardGuardrail } from './sovguard-middleware';
 *
 *   const model = wrapLanguageModel({
 *     model: openai('gpt-4o'),
 *     middleware: sovguardGuardrail(),
 *   });
 *
 * Docs: https://sdk.vercel.dev/docs/ai-sdk-core/middleware
 * Uses global `fetch` (Node >= 18 / edge runtimes). No dependencies beyond `ai`.
 */

// The `LanguageModelV1Middleware` and `LanguageModelV1CallOptions` types ship with
// the `ai` package. Import them as types so this file has no runtime dependency
// on `ai` itself (the middleware is consumed by the host app's `wrapLanguageModel`).
import type {
  LanguageModelV1Middleware,
  LanguageModelV1CallOptions,
} from 'ai';

/** Shape of the SovGuard `/v1/scan` response (see src/types.ts + verdict-annotation.ts). */
export interface SovGuardScanResult {
  safe: boolean;
  score: number;
  classification: 'safe' | 'suspicious' | 'likely_injection';
  flags: string[];
  degraded: boolean;
  mode: 'enforce' | 'monitor';
  wouldBlock: boolean;
}

export interface SovGuardGuardrailOptions {
  /** Base URL of the SovGuard API. Env: SOVGUARD_API_BASE. Default: https://api.sovguard.io */
  apiBase?: string;
  /** SovGuard tenant key sent as the `X-API-Key` header. Env: SOVGUARD_API_KEY. */
  apiKey?: string;
  /** Block when `!safe && score >= blockThreshold`. Default: 0.7 */
  blockThreshold?: number;
  /** Per-scan timeout in milliseconds. Default: 5000 */
  timeoutMs?: number;
  /**
   * When a scan cannot complete (network error, non-2xx) OR the verdict is
   * `degraded`, block the request instead of allowing it through.
   * Env: SOVGUARD_FAIL_CLOSED=1. Default: false (fail-open, warn-and-continue).
   */
  failClosed?: boolean;
}

/** Error thrown when SovGuard blocks a prompt. Lets callers `catch` and branch. */
export class SovGuardBlockedError extends Error {
  readonly result: SovGuardScanResult;
  constructor(result: SovGuardScanResult) {
    super(
      `Blocked by SovGuard: ${result.classification} ` +
        `(score=${result.score}, flags=${result.flags.slice(0, 5).join(', ')})`,
    );
    this.name = 'SovGuardBlockedError';
    this.result = result;
  }
}

/**
 * Pull the user-authored text out of the AI SDK call params.
 *
 * `params.prompt` is a `LanguageModelV1Prompt` (an array of messages). We scan
 * the text parts of `user` messages — those are the untrusted, attacker-reachable
 * turns. System/assistant/tool content is intentionally skipped.
 */
export function extractUserText(params: LanguageModelV1CallOptions): string {
  const prompt = params.prompt as unknown;
  if (!Array.isArray(prompt)) return '';
  const parts: string[] = [];
  for (const message of prompt) {
    if (!message || typeof message !== 'object') continue;
    const m = message as { role?: string; content?: unknown };
    if (m.role !== 'user') continue;
    if (typeof m.content === 'string') {
      parts.push(m.content);
    } else if (Array.isArray(m.content)) {
      for (const part of m.content) {
        if (part && typeof part === 'object' && (part as { type?: string }).type === 'text') {
          const t = (part as { text?: unknown }).text;
          if (typeof t === 'string') parts.push(t);
        }
      }
    }
  }
  return parts.join('\n');
}

/**
 * Build a SovGuard guardrail middleware.
 *
 * @example
 *   const model = wrapLanguageModel({
 *     model: openai('gpt-4o'),
 *     middleware: sovguardGuardrail({ blockThreshold: 0.7 }),
 *   });
 */
export function sovguardGuardrail(
  options: SovGuardGuardrailOptions = {},
): LanguageModelV1Middleware {
  const apiBase = (
    options.apiBase ??
    (typeof process !== 'undefined' ? process.env.SOVGUARD_API_BASE : undefined) ??
    'https://api.sovguard.io'
  ).replace(/\/$/, '');
  const apiKey =
    options.apiKey ??
    (typeof process !== 'undefined' ? process.env.SOVGUARD_API_KEY : undefined) ??
    '';
  const blockThreshold = options.blockThreshold ?? 0.7;
  const timeoutMs = options.timeoutMs ?? 5000;
  const failClosed =
    options.failClosed ??
    (typeof process !== 'undefined' && process.env.SOVGUARD_FAIL_CLOSED === '1');

  async function scan(text: string): Promise<SovGuardScanResult | null> {
    try {
      const resp = await fetch(`${apiBase}/v1/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
        body: JSON.stringify({ text }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!resp.ok) return null;
      return (await resp.json()) as SovGuardScanResult;
    } catch {
      return null;
    }
  }

  return {
    async transformParams({ params }) {
      const text = extractUserText(params);
      if (!text.trim()) return params;

      const result = await scan(text);

      // Scan failed to complete: fail-open by default, fail-closed if configured.
      if (result === null) {
        if (failClosed) {
          throw new Error('SovGuard scan unavailable — refusing (fail-closed).');
        }
        return params;
      }

      // Degraded verdict (a detection subsystem was unavailable): honor failClosed.
      if (result.degraded && failClosed) {
        throw new SovGuardBlockedError(result);
      }

      if (!result.safe && result.score >= blockThreshold) {
        throw new SovGuardBlockedError(result);
      }

      return params;
    },
  };
}

export default sovguardGuardrail;
