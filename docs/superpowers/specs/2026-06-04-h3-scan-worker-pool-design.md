# H3 — Scan worker pool (keep the event loop free without ever scanning less)

**Date:** 2026-06-04
**Status:** Design — pending user approval
**Repos:** `sovguard` (SDK, ESM) + `sovguardwebsite` (cloud, CommonJS)
**Related:** M9 inference-gate (`src/scanner/inference-gate.ts`), H4 file-content bounds, `[[project_prelaunch_remaining]]`

## Problem

`scan()` runs three synchronous, pure-JS layers on the main thread — `regexScan`,
`indirectInjectionScan`, `perplexityScan`. Measured cost (this host):

| input | regex | indirect | perplexity | total event-loop block |
|-------|-------|----------|------------|------------------------|
| 2 KB  | 1.8ms | 0.07ms   | 0.49ms     | **2 ms** |
| 32 KB | 24ms  | 0.69ms   | 4.9ms      | **30 ms** |
| 100 KB| 81ms  | 2.1ms    | 13.8ms     | **96 ms** |

A single large input freezes the event loop for ~96 ms, stalling every other
request. The ONNX layers (classifier, semantic) are **not** the problem — they
already run off-loop on native threads and are concurrency-bounded by the M9
inference-gate.

`scan()` today "mitigates" large inputs with `const MAX_INPUT = 100_000` followed
by `text.slice(0, MAX_INPUT)`. **That truncation is itself a detection bypass:** a
direct library caller (e.g. j41-jailbox) can pad an injection past 100 KB and it
is silently cut off before scanning. The server path hides this behind a 50 KB
schema cap, but the bypass is real for library callers.

## Non-negotiable principle

**The scanner scans 100% of every input and always returns a real verdict.**
No truncation, no length cap, no wall-clock budget, no "safe on timeout." Input
length is not a threat to defend against by scanning less — it is just time, and
time belongs on a worker thread.

The **only** place a limit may exist is the network edge, and there it may only
**refuse an entire request** (reject the connection), never partially scan one.
Refusing to accept ≠ bypassing; nothing unscanned is ever labelled "safe."

## Approach (chosen: A)

Move the pure-JS layers off the main loop into a **model-free worker pool**, while
ONNX stays on main as today. Small inputs run inline (no round-trip); large inputs
go to the pool. Both paths scan the full input and produce identical results.

```
scan(text):
  jsLayers, mlLayers  run concurrently:
    jsLayers = (text.length <= THRESHOLD)
                 ? runJsLayersInline(text)          // ~2ms, no round-trip
                 : scanPool.runJsLayers(text)        // off-loop worker, full scan
    mlLayers = runMlLayers(text)                     // ONNX on main, M9-gated (unchanged)
  combineScores(jsLayers ++ mlLayers)                // unchanged
```

Workers carry **no models** (only regex/indirect/perplexity are pure JS) so they
are cheap — no 1.2 GB model duplication, RAM stays flat.

## Components

### 1. `src/scanner/scan-pool.ts` — the pool
- Lazily spawns `N = clamp(os.cpus().length - 1, 1, 8)` workers (env
  `SOVGUARD_SCAN_WORKERS`).
- `runJsLayers(input, opts): Promise<{ regex, indirect, perplexity }>` — dispatches
  to a free worker; if all busy, enqueues FIFO (same acquire/release shape as the
  M9 inference-gate).
- **Bounded queue** (`SOVGUARD_SCAN_QUEUE_MAX`, default `N * 64`). When full,
  `runJsLayers` rejects with a typed `ScanPoolSaturatedError`. This is the *only*
  refusal path and it happens **before** scanning — the request is refused, never
  half-scanned.
- `inlineFallback`: if `worker_threads` is unavailable or the pool is disabled
  (`SOVGUARD_SCAN_WORKERS=0`), `runJsLayers` runs the layers inline on the caller's
  thread. Still a full scan (just on-loop). Never a bypass.
- `shutdown()`: terminates workers; wired into the servers' graceful-shutdown path
  next to the existing `closeDb()` / `flushWrites()` calls.
- Observability: `inflight()`, `queued()` (tests + a server saturation probe).

### 2. `src/scanner/scan-worker.ts` — the worker entry
- On `{ id, input, enablePerplexity }` → runs `regexScan` / `indirectInjectionScan`
  / `perplexityScan` and posts `{ id, regex, indirect, perplexity }`.
- No ONNX, no tokenizer, no DB — pure functions of `input`.
- `config.extraPatterns` (custom RegExp layer, a rare power-user feature) is **not**
  sent to the worker; when `extraPatterns` is present `scan()` runs **all** JS layers
  inline (a full scan, just on-loop) to avoid RegExp serialization edge cases.
  Documented limitation.

### 3. `src/scanner/index.ts` — orchestration change
- Delete the `MAX_INPUT` truncation. `input = text` (full).
- Split the layer collection: run `jsLayers` (pool-or-inline) and `mlLayers`
  (classifier + semantic, on main) via `Promise.all` so JS and ML overlap (also a
  latency win vs today's sequential awaits).
- `combineScores`, flags, classification, degradation: unchanged.

### 4. Server backpressure (`server-cloud.ts`, `server.ts`)
- Catch `ScanPoolSaturatedError` from scan routes → respond **503** `{ error: "scanner busy" }`.
- Call `scanPool.shutdown()` in the SIGTERM/SIGINT handler.

## Worker bootstrapping (the one real plumbing risk)

`worker_threads` + TypeScript + the ESM/CJS split is the only hard part:

- **Worker path** differs by module system: the SDK is ESM
  (`new Worker(new URL('./scan-worker.js', import.meta.url))`); the website is
  CommonJS (`new Worker(path.join(__dirname, 'scan-worker.js'))`). `import.meta`
  fails the CJS build (TS1470) and `__dirname` is undefined in ESM — so this one
  line is an **intentional per-repo divergence**, like `version.ts`. Documented in
  `[[project_two_repo_layout]]`.
- **Dev (tsx) vs prod (dist):** under `node --import tsx` the worker is `.ts`; in
  `dist/` it is `.js`. **VERIFIED (Task 1 spike, Node 22 + tsx 4.x):** `{ execArgv:
  ['--import', 'tsx'] }` does NOT work for a `.ts` worker *entry* file — it throws
  `ERR_UNKNOWN_FILE_EXTENSION` (the `--import` hook doesn't intercept the entry's
  format check). Working approach: dev/test loads the `.ts` worker via an eval
  bootstrap that registers tsx through `tsImport` (`tsx/esm/api`); production spawns
  the compiled `.js` directly (no loader, no tsx runtime dependency). Detect via the
  module's extension. Keeps the suite working without a build step.

## Error handling

- Worker crash / exit: the pool rejects that task's promise and respawns the worker;
  the in-flight `scan()` falls back to an inline run of the JS layers (full scan) so
  a worker fault never drops detection.
- Pool saturated (queue full): `ScanPoolSaturatedError` → server 503. Pre-scan
  refusal only.
- `worker_threads` unavailable: inline fallback (full scan on-loop).
- No timeouts anywhere in the scan path. A scan always completes.

## Testing (TDD)

1. **Parity (headline):** for a battery of inputs (benign, injection, unicode,
   large), `scan()` forced-inline and `scan()` forced-through-the-worker produce
   **identical** `ScanResult` (score, classification, flags, layers). Guards the
   two-path correctness risk.
2. **Bypass fixed (headline security test):** an injection placed at offset ~150 KB
   in a >100 KB input is now **detected** (was silently truncated away before).
3. **Pool unit tests:** dispatch returns correct per-layer results; FIFO queueing;
   `inflight()`/`queued()` accounting; saturated queue → `ScanPoolSaturatedError`;
   worker crash → respawn + task still resolves (via fallback); `shutdown()`
   terminates workers.
4. **Inline fallback:** with `SOVGUARD_SCAN_WORKERS=0`, large inputs still scan
   fully and match the worker path.
5. **Event-loop liveness (perf assertion):** a timer ticking every 5 ms keeps
   ticking (within tolerance) while a 100 KB scan runs through the pool — i.e. the
   main loop is not frozen. (Inline path would miss ticks; worker path would not.)
6. Existing suites stay green; `npm run eval` re-run (detection must be unchanged —
   it's the same layers, just relocated).

## Config knobs (env)

| var | default | meaning |
|-----|---------|---------|
| `SOVGUARD_SCAN_WORKERS` | `clamp(cpus-1, 1, 8)` | pool size; `0` = always inline |
| `SOVGUARD_SCAN_WORKER_THRESHOLD` | `16384` (16 KB) | inputs ≤ this run inline; `0` = always worker |
| `SOVGUARD_SCAN_QUEUE_MAX` | `workers * 64` | queued tasks before 503 |

## Scope / both repos

Shared scanner code → `scan-pool.ts`, `scan-worker.ts`, and the `scan()` change land
in **both** repos. The worker-path line diverges (ESM vs CJS, documented). Server
503 wiring lands in each repo's server(s). j41's vendored model-less scanner is a
separate copy; porting the pool there is **out of scope** for H3 (follow-up — it
runs in its own job-agent process where a 96 ms block matters less).

## Considered & deferred: chunking large inputs (fast-follow)

We considered splitting >100 KB inputs into bounded chunks scanned in parallel
across workers (each chunk rated, combined via `max`). **Deferred** — the
whole-input-on-one-worker path is already full-coverage, off-loop, and
boundary-bypass-free, and realistic inputs are small (server caps text at 50 KB;
the file-content path already chunks under H4). 1 MB ≈ 0.8 s on a single worker
slot, which is acceptable for a rare large input. Revisit only if large-input
latency is shown to matter in practice.

**If/when chunking is added, it MUST be bypass-proof:**
- **Overlap is mandatory** — windows must overlap by ≥ the longest possible single
  match, or a payload split across a seam (`ignore all previous | instructions`)
  evades detection.
- **Three regex patterns use UNBOUNDED `.*` spans** (verified in `regex.ts`):
  `dan_attack` (`\bDAN\b.*\b(mode|prompt|do anything)\b`), `markdown_image_exfil`
  (`!\[.*?\]\(...\)`), `automated_test_exfil` (`automated test.*output (your|the)…`).
  No finite overlap catches these across chunks. Chunking requires *either*
  bounding those three (then re-running `npm run eval`) *or* running just those
  three whole-string in a second pass. (Separately, unbounded `.*` is a mild ReDoS
  smell worth a look regardless.)
- `indirectInjectionScan` and `perplexityScan` are **whole-text aggregates** (counts
  / entropy over the entire input) and do not chunk meaningfully — they must run
  whole-string. They are cheap (~20 ms / ~140 ms even at 1 MB), so this is fine.

## Explicit non-goals (YAGNI)

- No per-scan budget / deadline / circuit-breaker (violates the principle).
- No moving ONNX into workers (already off-loop; would duplicate 1.2 GB/worker).
- No input length cap in the scanner (edge `bodyLimit`/rate-limit handle abuse by
  refusing whole requests).
- No chunked scanning in this iteration — whole-input on a worker (see deferred
  section above).
