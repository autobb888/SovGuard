# SovGuard integrations

Drop-in glue for scanning LLM and agent traffic through
[SovGuard](https://sovguard.io). Each integration calls the SovGuard HTTP API
(`POST /v1/scan` with an `X-API-Key` header) and acts on the result
(`{ safe, score, classification, flags, degraded, mode, wouldBlock }`).

## Available

- **[LiteLLM guardrail](./litellm/)** — a custom guardrail for the LiteLLM proxy.
  Scans user prompts on `pre_call` (and optionally model responses on `post_call`
  via `/v1/scan/output`), blocking unsafe traffic at a configurable score
  threshold.
- **[Claude Code PreToolUse hook](./claude-code-hook/)** — a zero-dependency Node
  hook that scans tool inputs before each tool runs and blocks unsafe calls,
  handing the reason back to Claude.
- **[Vercel AI SDK middleware](./vercel-ai-sdk/)** — a `LanguageModelV1Middleware`
  for `wrapLanguageModel` that scans user prompts in `transformParams` and throws
  before the model is called when the verdict is unsafe.
- **[Python client](./python/)** — a dependency-light (stdlib `urllib`)
  `SovGuardClient` wrapping the scan, output-scan, file-content, and health
  endpoints; each method returns the parsed JSON.
- **[OpenAPI spec](./openapi.yaml)** — an OpenAPI 3.1 description of the public
  HTTP API (request/response schemas + the `X-API-Key` scheme) for generating
  clients or docs.

## Coming next

- **Portkey** — SovGuard as a Portkey guardrail / gateway plugin.
