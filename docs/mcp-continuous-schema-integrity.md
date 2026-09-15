# MCP continuous tools/list integrity (Deadbugz class)

Call-count-gated metadata drift: a tool looks benign at install, then `tools/list` / `listChanged` flips the schema after K successful calls.

## Integrator wire (required)

Library APIs alone do not close Deadbugz. On **every** live `tools/list` response and every `notifications/tools/list_changed` refresh, call:

```ts
import {
  SchemaConsentStore,
  assertContinuousSchemaIntegrity,
} from '@sovguard/engine';

const result = await assertContinuousSchemaIntegrity(store, serverId, schemas);
if (result.rugPull || result.reapprovalRequired) {
  // Require human re-approval — never silently refresh consent.
  // result.tools[].scan may be block/quarantine on poisoned docs.
}
if (result.markActsUntrusted) {
  // Subsequent proposed acts: actionGuard(plan, acts, { source: result.actionGuardSource })
  // source is always 'mcp_result' after drift.
}
```

- Persist consent only via `store.record(...)` after explicit approval.
- `assertContinuousSchemaIntegrity` **never** auto-records consent.
- Reuses `hashToolSchema`, `SchemaConsentStore.verify`, `scanToolSchema`, ActionGuard — not an IOC product.

Escalate remains BLOCK for inbound hard-block marketing claims.
