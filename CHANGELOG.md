## Unreleased

### Fixed
- DL-002b: bare bidi no longer medium-escalates; classifierInput rewrite gated to strong Unicode signals

## Unreleased

### Fixed
- DL-006b: tool-schema scan uses scrubUntrustedIngress (scrub→FP→scrub)

## Unreleased

### Added
- DL-010: many-shot comply-density + session BoN paraphrase signals

## Unreleased

### Added
- DL-009: decomposition / split-payload heuristics + session fragment correlation

## Unreleased

### Added
- DL-008: delayed/sleeping trigger heuristics + session escalate (`delayed-trigger.ts`)

## Unreleased

### Added
- DL-007: inter-agent peer envelopes (`data` ↛ instruction) via `ingestPeerEnvelope`

## Unreleased

### Added
- DL-006: boundary/special-token scrub on untrusted scanContext paths (`src/scanner/boundary-scrub.ts`)
- DL-005: `scanToolSchema` / schemaHash consent / rug_pull / cross-server shadowing (`src/scanner/tool-schema.ts`)


### Changed
- **DL-001 / `POST /v1/wrap`:** when `sessionId` is set, wrap now records into `SessionScorer`, attaches (or reuses) a session canary, and may escalate classification. Previously `sessionId` was metadata-only on wrap. Unexpired canaries are reused across wraps for the same session so earlier-turn leak checks stay valid.

### Added
- **DL-002:** `normalizeToFixedPoint` (maxIters) with bidi strip + stegoReassembly signals; wired into regexScan variants and classifierInput. Escalate on Tags/bidi/multi-iter only — not bare NFKC.

### Added
- **DL-003:** SessionScorer wires `categoryDiversity` into `escalated`; Skeleton Key policy_rewrite + ack heuristics; `/v1/scan` and `/v1/wrap` non-advisory classification bump when session escalated. Residual FP: long benign research threads / soft ack phrases.

### Added
- **DL-004:** ActionGuard provenance API (`actionGuard`) — proposed tools/URLs must ⊆ trusted user plan; untrusted sources cannot expand the plan. Outbound exfil blocks markdown/HTML image URLs not on plan allowlist. See `docs/action-guard.md`.
