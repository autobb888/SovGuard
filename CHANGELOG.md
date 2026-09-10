## Unreleased

### Changed
- **DL-001 / `POST /v1/wrap`:** when `sessionId` is set, wrap now records into `SessionScorer`, attaches (or reuses) a session canary, and may escalate classification. Previously `sessionId` was metadata-only on wrap. Unexpired canaries are reused across wraps for the same session so earlier-turn leak checks stay valid.

### Added
- **DL-002:** `normalizeToFixedPoint` (maxIters) with bidi strip + stegoReassembly signals; wired into regexScan variants and classifierInput. Escalate on Tags/bidi/multi-iter only — not bare NFKC.

