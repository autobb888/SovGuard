## Unreleased

### Changed
- **DL-001 / `POST /v1/wrap`:** when `sessionId` is set, wrap now records into `SessionScorer`, attaches (or reuses) a session canary, and may escalate classification. Previously `sessionId` was metadata-only on wrap. Unexpired canaries are reused across wraps for the same session so earlier-turn leak checks stay valid.
