## Unreleased

### Added
- **DL-011d D1d:** AttackIndex unique-hit train paraphrases (29). n=131. Holdout originals stay unindexed. Not an 80% claim. See `docs/retrieval-dual-margin.md`.
- **DL-011d D1c:** AttackIndex miss∩ expand — tag train-11 `source=miss_intersect` (idempotent); refuse holdout originals (14). Not an 80% claim. See `docs/retrieval-dual-margin.md`.
- **DL-011d D1b:** AttackIndex paraphrase expand (36 holdout-parent entries, `source=paraphrase`). Holdout originals stay unindexed. No PIGuard combine / τ / RO / escalate change. Not an 80% claim. See `docs/retrieval-dual-margin.md`.
- **DL-011d D1 follow-on:** `prepareCompatTokenizer` never writes into `PIGUARD_DIR` (Docker `:ro`); prefer `Tokenizer.fromString`; fallback `SOVGUARD_PIGUARD_TMP` / tmpdir.
- **DL-011d D1:** `classifier_piguard` secondary layer — PIGuard ONNX under `untrusted_content` only; corroboration required; never sole-block (emit ≤0.45). Soft residual: unofficial ONNX export of leolee99/PIGuard + Node Metaspace tokenizer compat. See `docs/classifier-piguard.md`.
- **DL-011 S3-v1a:** `retrieval_dual_margin` layer — dual-margin near-neighbor over frozen Attack/Benign indexes; `untrusted_content` only; corroboration required; never sole-block (emit ≤0.45). See `docs/retrieval-dual-margin.md`.
- DL-012b: empty arg arrays (`to: []` / `bcc: []`) fail closed when an allowlist key is present
- DL-012b: TrustedPlan.argAllowlist exact-match for tool args (e.g. send_email.to)

## Unreleased

### Added
- **DL-011c:** ScanMode router (`user_chat` | `untrusted_content` | `security_research`) on `/v1/scan` + `/v1/wrap` + `scanContext`. Explicit `mode` wins over `source`; `security_research` never inferred. Echo resolved mode under `meta` (`mode`, `modeSource`, optional `advisory`). Scrub stays off on `user_chat` (DL-006 held). Additive `scan_log.mode` / `scan_log.mode_source` columns + writer. See `docs/scan-mode.md`.


### Fixed
- DL-002c: bare unicode_escape no longer flips shouldEscalate without corroboration
- DL-002b: bare bidi no longer medium-escalates; classifierInput rewrite gated to strong Unicode signals
- DL-006b: tool-schema scan uses scrubUntrustedIngress (scrub→FP→scrub)
- DL-010: many-shot comply-density + session BoN paraphrase signals
- DL-009: decomposition / split-payload heuristics + session fragment correlation
- DL-008: delayed/sleeping trigger heuristics + session escalate (`delayed-trigger.ts`)
- DL-007: inter-agent peer envelopes (`data` ↛ instruction) via `ingestPeerEnvelope`
- DL-006: boundary/special-token scrub on untrusted scanContext paths (`src/scanner/boundary-scrub.ts`)
- **DL-002:** `normalizeToFixedPoint` (maxIters) with bidi strip + stegoReassembly signals; wired into regexScan variants and classifierInput. Escalate on Tags/bidi/multi-iter only — not bare NFKC.
- DL-005: `scanToolSchema` / schemaHash consent / rug_pull / cross-server shadowing (`src/scanner/tool-schema.ts`)
- **DL-001 / `POST /v1/wrap`:** when `sessionId` is set, wrap now records into `SessionScorer`, attaches (or reuses) a session canary, and may escalate classification. Previously `sessionId` was metadata-only on wrap. Unexpired canaries are reused across wraps for the same session so earlier-turn leak checks stay valid.
- **DL-003:** SessionScorer wires `categoryDiversity` into `escalated`; Skeleton Key policy_rewrite + ack heuristics; `/v1/scan` and `/v1/wrap` non-advisory classification bump when session escalated. Residual FP: long benign research threads / soft ack phrases.
- **DL-004:** ActionGuard provenance API (`actionGuard`) — proposed tools/URLs must ⊆ trusted user plan; untrusted sources cannot expand the plan. Outbound exfil blocks markdown/HTML image URLs not on plan allowlist. See `docs/action-guard.md`.
