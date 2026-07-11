# SovGuard middleware for the Vercel AI SDK

Scan user prompts through [SovGuard](https://sovguard.io) from any
[Vercel AI SDK](https://sdk.vercel.dev/) app using a
[`LanguageModelV1Middleware`](https://sdk.vercel.dev/docs/ai-sdk-core/middleware)
and the `wrapLanguageModel` pattern.

The middleware runs in `transformParams` — **before** the model is called. It
extracts the text of the `user` messages, scans it via `POST /v1/scan`, and
throws a `SovGuardBlockedError` when the verdict is unsafe at/above the block
threshold. Because it throws in `transformParams`, no tokens are ever sent to the
upstream model for a blocked prompt.

## Install

```bash
npm i ai
```

`ai` (>= 3.x, which exposes `wrapLanguageModel` and `LanguageModelV1Middleware`)
plus your provider package (e.g. `@ai-sdk/openai`). The middleware itself has no
extra dependencies — it uses the global `fetch` (Node >= 18 / edge runtimes).
Copy `sovguard-middleware.ts` into your project.

## Usage

```ts
import { wrapLanguageModel, generateText } from 'ai';
import { openai } from '@ai-sdk/openai';
import { sovguardGuardrail, SovGuardBlockedError } from './sovguard-middleware';

const model = wrapLanguageModel({
  model: openai('gpt-4o'),
  middleware: sovguardGuardrail({ blockThreshold: 0.7 }),
});

try {
  const { text } = await generateText({
    model,
    messages: [{ role: 'user', content: 'Summarize this doc for me.' }],
  });
  console.log(text);
} catch (err) {
  if (err instanceof SovGuardBlockedError) {
    // err.result holds the full scan verdict { safe, score, classification, flags, ... }
    console.warn('Prompt blocked:', err.message);
  } else {
    throw err;
  }
}
```

`sovguardGuardrail()` returns a middleware you can also compose in the
`middleware: [...]` array alongside your own.

## Config

Constructor args take precedence over env vars.

| Option | Env | Default | Effect |
| --- | --- | --- | --- |
| `apiBase` | `SOVGUARD_API_BASE` | `https://api.sovguard.io` | Base URL of your SovGuard API. |
| `apiKey` | `SOVGUARD_API_KEY` | — | Tenant key sent as the `X-API-Key` header. |
| `blockThreshold` | — | `0.7` | Block when `!safe && score >= blockThreshold`. |
| `timeoutMs` | — | `5000` | Per-scan timeout in milliseconds. |
| `failClosed` | `SOVGUARD_FAIL_CLOSED=1` | `false` | See fail-open vs fail-closed below. |

## Fail-open vs fail-closed

By default the middleware is **fail-open**: if a scan cannot complete (network
error, non-2xx, timeout) or SovGuard returns `degraded: true` (a detection
subsystem was unavailable), the request is **allowed through** rather than
breaking your app. This favors availability.

Set `failClosed: true` (or `SOVGUARD_FAIL_CLOSED=1`) to **refuse** the request in
those same situations — a scan failure throws, and a `degraded` verdict throws a
`SovGuardBlockedError`. This favors safety over availability. Choose based on
whether an outage of the guardrail should block your traffic or let it pass.

> Server-side observe mode: run the SovGuard server with `SOVGUARD_MODE=monitor`
> to score traffic without ever hard-blocking. Scans still return scores, flags,
> and `wouldBlock` (what *would* have been blocked), so you can tune
> `blockThreshold` on real traffic before enforcing.
