# Code-Exec Detection — Phase 1b Design

**Date:** 2026-06-06
**Status:** Approved (brainstorming → spec)
**Repos affected:** `j41-jailbox` (Part A), `j41-sovagent-sdk` (Part B). Spec/plan docs live in `sovguard` for continuity with [Phase 1](2026-06-05-malicious-code-detection-design.md).
**Depends on:** Phase 1 (merged to `sovguard` + `sovguardwebsite` `main`; the API change must be **deployed** to `api.sovguard.io` for Part A to take effect).

---

## 1. Context (from scoping, 2026-06-06)

Phase 1 added code-exec detection to SovGuard's file-content scanner: weapon patterns hard-block (`safe:false`); contextual patterns warn unless an execution-context hint (`context.path` / `executes_on_host`, classified by a server-side `riskyPath` map) escalates them to block. The HTTP API `/v1/scan/file/content` now accepts an optional `context` and returns additive `action`/`warnings`.

Scoping the j41 stack found three consumers, only two relevant:
- **jailbox** scans the agent's file *writes* via the HTTP API (`sovguard.ts` → `POST /v1/scan/file/content`, called at `cli.ts:~770` and `pre-scan.ts:~62`). It blocks on `!safe`. Today it sends only `{content, mimeType}` and consumes `safe/score/category/flags/matches` — **not** `action`/`warnings`. It has the write path (`relPath`) at the call site but doesn't send it, and has **no** executes-on-host classifier of its own.
- **dispatcher** uses the vendored `scanContext` (`scanUntrusted()` in `sovguard-context.js`) on tool results + job descriptions — prompt-injection on text entering the LLM, not writes. Out of scope.
- **mcp-server** — no write-scan path. Out of scope.

The vendored SDK scanner (`j41-sovagent-sdk/src/safety/scanner/`) has `scan.ts` (injection) + `scanContext` (source-trust) but **no content-scan path**.

**Deploy-alone effect:** once the Phase-1 API is live, jailbox blocks weapons (reverse shell, `nc -e`, IEX-download → `safe:false`) with no jailbox change. The *contextual* payloads (postinstall `curl|bash`, `.envrc`) need Part A so jailbox sends `context.path`.

## 2. Goals / Non-goals

**Goals:** (A) jailbox sends `context.path` + consumes `action`/`warnings`, with warn-most handling. (B) a standalone `scanContent()` in the vendored SDK so a future daemon-less write-scanner has code-exec, published as `@junction41/sovagent-sdk@2.6.4`.

**Non-goals:** changing `scanContext` (stays injection-only); bumping dispatcher/mcp-server (they don't call `scanContent`); deploying the API (operator action); the v2 premium full-repo scan.

## 3. Part A — jailbox

### 3.1 `src/sovguard.ts`
- Extend the result interface (optional, so a pre-Phase-1 API that omits them is fine):
  ```ts
  export interface SovGuardScanResult {
    safe: boolean; score: number; reason?: string; category?: string;
    classification?: string; flags?: string[]; matches?: SovGuardScanMatch[];
    action?: 'allow' | 'warn' | 'block';   // NEW
    warnings?: string[];                     // NEW
  }
  export interface SovGuardScanContext {     // NEW
    path?: string; executes_on_host?: boolean; source?: string;
  }
  ```
- `scanContent(content: Buffer, mimeType: string, context?: SovGuardScanContext)`: when `context` is provided, include it in `jsonBody` (`JSON.stringify({ content, mimeType, context })`). It is inside the encrypted envelope, so AES-GCM encryption is unaffected. No other change to request/response handling.

### 3.2 Call sites — `src/cli.ts` (~770) and `src/pre-scan.ts` (~62)
- Pass `context: { path: relPath, source: 'other_agent' }`. (`pre-scan.ts` uses its own path variable — pass that file's path.)
- **Warn handling** (the new branch, alongside the existing `if (!scanResult.safe)` block which is unchanged):
  - `!scanResult.safe` → block (existing behavior; now also fires for escalated contextual writes).
  - else if `scanResult.action === 'warn'` (or `scanResult.warnings?.length`):
    - **supervised** (a `supervisor` is present): surface the warning in the approval/diff path — show the `warnings`/`reason` as a non-blocking notice (reuse the supervised approval seam used for blocks, but as a warn that defaults to allow).
    - **standard** (no supervisor): `feed.logStatus`/a warn log + append to `audit-log`, then allow the write.
  - else → allow silently (`action === 'allow'` or fields absent).

### 3.3 Backward compatibility
Sending `context` to a pre-Phase-1 API is harmless (zod `.parse` strips unknown keys). `action`/`warnings` absent → the warn branch is a no-op. So Part A is safe to ship before the API deploy; it simply has no new effect until the API is live.

### 3.4 Tests (jailbox: `node:test` + `tsx`, mock `fetch`)
- `scanContent` includes `context` in the request body when provided; omits it when not.
- Response `safe:false` → caller blocks (unchanged).
- Response `action:'warn'` + `warnings` → standard mode logs (feed + audit) and allows; supervised mode surfaces the warning.
- Encrypted path still round-trips with `context` present.
- Respect the known "stale sovguard mocks" caveat — update mocks to the new shape rather than fighting them.

## 4. Part B — vendored `scanContent()` in `j41-sovagent-sdk`

### 4.1 Files
- `src/safety/scanner/codeexec.ts` — **verbatim copy** of the main repos' `codeexec.ts`. (Becomes the 4th copy of this file; drift tracked.)
- `src/safety/scanner/content.ts` — new. `scanContent(text: string, opts?: { context?: ExecContext; mimeType?: string })` mirrors the main repos' `scanText` content-scan: vendored `regexScan` (injection regex layer) over the text + `detectCodeExec`/`decideCodeExec` + the doc-context `curl_exfil`/`wget_exfil` reconciliation + the warn-score floor, returning `{ safe, score, flags, action, warnings, category, reason }` (the main `ContentScanResult` minus the website-only `matches`). Keeps behavior identical to the deployed API.
- `src/safety/content.ts` — re-export `scanContent` (parallel to `src/safety/context.ts`).
- `src/index.ts` — export `scanContent` + its types.
- `package.json` — version `2.6.3 → 2.6.4`.
- `scanContext` and `scan` are **not** modified.

### 4.2 Result shape
```ts
interface ContentScanResult {
  safe: boolean; score: number; flags: string[];
  action: 'allow' | 'warn' | 'block'; warnings: string[];
  category: string | null; reason: string | null;
}
```

### 4.3 Tests
Port the codeexec unit tests verbatim. Add a model-less content/corpus test for `scanContent` (the Phase-1 10-must-flag / 5-must-pass corpus, run against the vendored `scanContent`; results match the main repos since the regex layer + codeexec are identical and model-less).

### 4.4 Publish
`npm publish` `2.6.4` via an env-ref `.npmrc` (`//registry.npmjs.org/:_authToken=${NPM_TOKEN}`) + a user-supplied token, removed after. Gate = `prepublishOnly: tsc --noEmit`. **No consumer bumps** (dispatcher/mcp-server stay on 2.6.3). See [[project_j41_sdk_publish_deps]].

## 5. Verification items (resolve during planning, do not guess)
- The vendored `src/safety/scanner/regex.ts` exports the decoders `codeexec.ts` imports (`decodeHexEscapes`, `decodeUnicodeEscapes`, `decodeUrlEncoding`). If any are missing, the port adds the export (it's a verbatim subset of the main `regex.ts`).
- The vendored `regexScan` signature/return matches what `content.ts` needs (`{ score, flags, details.matches }`).
- jailbox's exact feed/audit method names (`feed.logStatus`/`logOperation`/`audit-log` API) and the supervised approval seam (`supervisor.promptSovguardApproval`) for the warn notice.
- jailbox test harness layout + the "stale sovguard mocks" red-suite caveat ([[project_jailbox_reconcile_2026-06-03]]).

## 6. Drift / memory
`codeexec.ts` now lives in 4 places: `sovguard`, `sovguardwebsite`, and `j41-sovagent-sdk/src/safety/scanner/`. Update [[project_two_repo_layout]] (4-copy now) and note the vendored `scanContent` entrypoint. Long-term: a deps-free shared `@sovguard/scanner` slim-core would collapse the copies ([[project_integration_scancontext]] option C).

## 7. Sequencing
1. Part A (jailbox) — independent; ship behind the safe backward-compat.
2. Part B — port + publish 2.6.4 (needs user token).
3. **Operator actions (not in this plan):** deploy Phase-1 API to `api.sovguard.io` so Part A takes effect; rotate the npm token after publish.
