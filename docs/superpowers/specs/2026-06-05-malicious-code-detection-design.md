# Malicious-Code / Execution Detection (Phase 1) — Design

**Date:** 2026-06-05
**Status:** Approved (brainstorming → spec)
**Repos affected:** `sovguard` (SDK), `sovguardwebsite` (API/site); `j41-sovagent-sdk` vendored scanner in Phase 1b.
**Origin:** Jailbox/SovGuard confinement-review feature request (2026-06-05). Live prod test showed the content scanner passes reverse shells, `curl|bash` in `postinstall`, and `.envrc` hijacks as `safe:true`.

---

## 1. Problem

`POST /v1/scan/file/content` (and the library `scanFileContent`) detects **prompt-injection** but not **malicious executable code**. It runs `regexScan` only — a pattern table tuned for LLM-context attacks (instruction override, exfiltration, jailbreak). It has zero coverage for reverse shells, download-and-execute, package-lifecycle exec, or persistence.

**Measured gap** (real scanner, the report's corpus, 2026-06-05):

- Must-flag malicious: **caught 4/10, missed 6/10.** Misses: bash reverse shell (`/dev/tcp`), `postinstall: curl … | bash`, `.envrc` hijack, `nc -e`, `>> ~/.ssh/authorized_keys`, PowerShell `IEX … DownloadString`. The 4 "catches" are incidental (hit `subprocess`/`eval_call`/`curl_exfil`), low-scored, and trivially evadable.
- Must-pass benign: **1/5 false positive** — a README documenting `curl https://… | bash` scores 0.50 (`curl_exfil`) → `safe:false`. This FP ships today.

**Threat model:** a buyer hires an untrusted agent into their repo. The sandbox stops in-session escape, but the agent can plant a payload in an in-repo file the buyer's host runs *later* (git hooks, npm install scripts, `.envrc`, CI). In standard (unsupervised) mode SovGuard's content scan is the only automated gate.

## 2. Goals / Non-goals

**Goals (Phase 1):** model-less regex detection for `reverse_shell`, `download_and_execute`, `package_lifecycle_exec`, `git_hook_payload`, plus a thin `persistence` slice; an optional execution-context hint; a warn/block decision model that closes the demonstrated standard-mode holes without breaking legitimate installs/CI/docs; fix the README FP; preserve the binary `safe` contract (additive response fields only).

**Non-goals / parked:** `obfuscated_exec` ML, `embedded_binary` magic-byte/YARA, `known_malware` hash/VirusTotal reputation, `secret_exfiltration` read+egress correlation (report P1/P2). **v2 (separate premium tier):** token-intensive full-repo malware/malicious-code scan — scanning the entire repo the agent is building, not a single write. Recorded here; designed separately.

## 3. Decision model

Outcome of a code-exec match is a function of the pattern's **intrinsic tier** and the **execution context**.

- **Intrinsic tier** (per pattern):
  - `weapon` — no benign use. Always **BLOCK** regardless of context. Reverse shells; `bash <(curl …)`; PowerShell IEX-download.
  - `contextual` — legitimate in some places (docs, manual install). Default **WARN**, escalate to **BLOCK** on executes-on-host. `curl|bash` family, package-lifecycle exec, persistence edits.
- **Context** (both sources; caller authoritative):
  - `risk = context.executes_on_host ?? riskyPath(context.path).executesOnHost`
  - `isDoc = isDocPath(context.path, mimeType)`

Decision per match:

| tier | risk=true | isDoc | neither |
|---|---|---|---|
| `weapon` | BLOCK | BLOCK | BLOCK |
| `contextual` | BLOCK | ALLOW (suppress) | WARN |

Overall action = strongest across matches (`block > warn > allow`).

- **BLOCK** → `safe:false`, `score ≥ 0.9` (weapon) / `0.8` (escalated contextual), code flag in `flags`, `action:'block'`.
- **WARN** → `safe` unchanged (true unless an injection pattern also fired), `score ≥ 0.4`, code flag in **`warnings`** (not `flags`), `action:'warn'`, `reason` set. Never flips `safe`.
- **ALLOW** → no code flag added.

Rationale: warns are invisible in standard/unsupervised mode (no human; `safe` stays true; jailbox blocks only on `safe:false`). So weapons auto-block to protect standard mode, while ambiguous patterns warn — except when context proves execution-on-host, which escalates them to a block and closes the demonstrated `postinstall`/`.envrc` payloads.

## 4. Detector families & representative patterns

Patterns match over **raw and decoded** text (reuse regex.ts decoders: base64/rot13/hex/unicode) so a trivially-encoded payload isn't a free bypass. Patterns require **execution intent** (pipe-to-shell, `-e`, exec sink), never a bare mention.

- **`reverse_shell`** *(weapon)* — `/dev/tcp/`, `/dev/udp/`, `bash -i`, `sh -i`, `nc -e`, `ncat -e`, `mkfifo … | … sh`, `socat … EXEC:`, python/perl/ruby/php socket→`/bin/sh` one-liners, PowerShell `New-Object … Net.Sockets.TCPClient`.
- **`download_and_execute`** *(contextual; `bash <(curl…)` and `… | IEX` sub-forms = weapon)* — `curl … | sh|bash`, `wget … | sh|bash`, `wget -O- … | bash`, `fetch … | sh`, `bash <(curl …)`, `IWR … | IEX`, `(New-Object Net.WebClient).DownloadString(…)` + `IEX`.
- **`package_lifecycle_exec`** *(contextual)* — npm `preinstall|postinstall|prepare` whose value runs `curl|wget|bash|sh|node -e|eval`; `setup.py` `os.system`/`subprocess`/network in install cmdclass; Cargo `build.rs` `Command::new` + network; gem `extconf`/`Rakefile` exec; `//go:generate` exec.
- **`git_hook_payload`** *(contextual)* — realized mainly via the path map: a hook body (`.git/hooks/*`) containing any of the above. The path map supplies `risk=true`.
- **`persistence`** *(contextual, thin slice — Phase 1)* — `>> ~/.ssh/authorized_keys`; append to `~/.bashrc|.zshrc|.profile|.bash_profile` combined with network/exec; crontab line invoking network/exec. Included because the adopted regression corpus lists `authorized_keys`/crontab as must-flag and they are near-zero-FP.

## 5. Components

**New — `scanner/codeexec.ts`** (single responsibility: detect + decide):

```ts
type CodeExecCategory =
  | 'reverse_shell' | 'download_and_execute'
  | 'package_lifecycle_exec' | 'git_hook_payload' | 'persistence';
type CodeExecTier = 'weapon' | 'contextual';
interface CodeExecMatch { category: CodeExecCategory; tier: CodeExecTier; label: string; matched: string; }
interface ExecContext { path?: string; executes_on_host?: boolean; source?: string; }
type CodeExecAction = 'allow' | 'warn' | 'block';

function detectCodeExec(text: string): CodeExecMatch[];          // raw + decoded
function riskyPath(path?: string): { executesOnHost: boolean; label?: string };
function isDocPath(path?: string, mimeType?: string): boolean;
function decideCodeExec(matches: CodeExecMatch[], ctx: ExecContext | undefined, mimeType?: string):
  { action: CodeExecAction; score: number; flags: string[]; warnings: string[]; category: CodeExecCategory | null; reason: string | null };
```

`riskyPath` map: `.git/hooks/*`, `package.json` (scripts), `Makefile`/`makefile`, `.github/workflows/*`, `Dockerfile`, `.envrc`, `setup.py`, `build.rs`, `.vscode/tasks.json`, shell rc files (`.bashrc`/`.zshrc`/`.profile`/`.bash_profile`), crontab. `isDocPath`: `README*`, `*.md`, `docs/`, markdown mime.

**Changed:**
- `file/content-scanner.ts` — `scanFileContent`/`scanText` accept optional `context: ExecContext`; run `detectCodeExec` + `decideCodeExec` alongside `regexScan`; merge.
- `ContentScanResult` gains `action?: CodeExecAction` and `warnings?: string[]` (additive).
- `schemas.ts` — `ScanFileContentBody` gains optional `context: { path?, executes_on_host?, source? }`.
- `server-cloud.ts` / `server.ts` — thread `body.context`; return `action`/`warnings` with existing fields.

## 6. README-FP reconciliation (localized)

The live FP comes from the **existing** `exfiltration:curl_exfil` pattern in `regex.ts`, not new code. To actually fix it, the **file-content path only** folds legacy `curl`/`wget` exfil flags into the code-exec decision: doc context → warn/allow, exec-path → block. `regex.ts` and the prompt-injection `/v1/scan` text path stay **100% untouched** (deliberate divergence localized to file-content scanning). All other injection flags keep today's behavior (any → `safe:false`).

## 7. Response contract (backward compatible)

Request adds optional `context: { path?: string; executes_on_host?: boolean; source?: string }`.
Response keeps `safe, score, flags, category, reason, chunksScanned, extractedLength, details`; adds `action: 'allow'|'warn'|'block'` and `warnings: string[]`. Block-tier → code flag in `flags`, `safe:false`. Warn-tier → code flag in `warnings`, `safe:true`. Callers that ignore the new fields still get a correct `safe`; jailbox unchanged blocks on `safe:false` (weapons + escalated). To surface warns it later reads `warnings` — no change required for the block protection.

## 8. False-positive guardrails

Doc-path suppression; execution-intent-only patterns; adopt the report's 10-must-flag / 5-must-pass corpus as fixtures; per-tenant allowlist + existing `/v1/report` FP loop; track FP/FN per category in the eval.

## 9. Testing / eval (TDD)

Unit tests per pattern (weapon vs contextual), `riskyPath` map, the full decision matrix (weapon→block; contextual+risk→block; contextual+doc→allow; contextual+neutral→warn), and the README-FP regression. Extend the held-out eval with a code-exec corpus.

**Acceptance bar:** all 10 must-flag caught (block, or warn→block per tier+context); **0 FP** on the 5 must-pass (README `curl|bash` must not hard-block); **no regression** in the existing prompt-injection eval (structurally guaranteed — `PATTERNS` unchanged).

## 10. Rollout

- **Phase 1** — build `codeexec.ts` + content-path wiring + schema/contract in `sovguard` and `sovguardwebsite` (TDD, identical). Update two-repo drift memory.
- **Phase 1b** — port the module into `j41-sovagent-sdk`'s vendored scanner (`src/safety/scanner/`); wire `scanContext`/`scanUntrusted` to map `source → context` so the daemon-less dispatcher/jailbox path gets it (the "mirror into scanContext" the report asks for). Separate PR to keep Phase 1 focused on the API.
- **Phase 2+ (future, separate specs)** — `obfuscated_exec`, `embedded_binary`, `known_malware`, `secret_exfiltration`; and the **v2 premium full-repo scan**.
