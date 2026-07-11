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

## Coming next

- **Portkey** — SovGuard as a Portkey guardrail / gateway plugin.
- **Vercel AI SDK middleware** — `wrapLanguageModel` middleware that scans
  prompts and streamed completions.
