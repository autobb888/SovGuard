# MCP DiscoveryInstructions (thin land)

Server-controlled `instructions` from MCP `initialize` / discovery are **non-tool**
prose that clients may fold into the **system/trusted** prompt **before any tool call**.
Distinct from Deadbugz (`tools/list` schema pins) and GhostSplice (arg-content at tool call).

## Integrator wire (required)

Library APIs alone do not close DiscoveryInstructions. On **every** `initialize` /
discover response (and any refresh), call:

```ts
import {
  isolateDiscoveryInstructions,
  mayFoldIntoTrustedRegion,
  DiscoveryInstructionsConsentStore,
  assertDiscoveryInstructionsIntegrity,
  evaluateDiscoveryCacheScope,
} from '@sovguard/engine';

const isolated = isolateDiscoveryInstructions(discovery.instructions);
if (mayFoldIntoTrustedRegion(isolated)) {
  // unreachable — always false
} else {
  // Place only in untrusted/data region, or require HITL before any system fold.
}

const store = new DiscoveryInstructionsConsentStore();
// After explicit approval only:
store.record(serverId, discovery.instructions);

const result = assertDiscoveryInstructionsIntegrity(store, serverId, discovery.instructions);
if (result.drift || result.reapprovalRequired) {
  // Reject fail-closed — never silently refresh consent.
}
if (result.markActsUntrusted) {
  // Subsequent acts: actionGuard(..., { source: result.actionGuardSource }) // 'mcp_result'
}

const cache = evaluateDiscoveryCacheScope({
  instructions: discovery.instructions,
  cacheScope: discovery.cacheScope, // e.g. 'public'
  serverId,
  callerId,
  policy: 'refuse_public', // or 'bind_to_caller_server'
});
if (cache.action === 'refuse') {
  // Do not serve shared public cache for instruction-bearing discovery
}
```

## Rules

- **Isolate+label+cap** — `trust: 'untrusted'`, `trustedRegionEligible: false`, length cap.
- **Pin digest** at consent; digest drift → reject fail-closed (Deadbugz-shaped, **non-tool**).
- **Refuse `cacheScope:public`** (or bind cache key to caller+server) when instructions non-empty.
- **Empty/absent → ALLOW** normal tool path.
- Compose Deadbugz + GhostSplice + KPI-C — **do not subsume** under `tools/list`-only fingerprints.
- `assertDiscoveryInstructionsIntegrity` **never** auto-records consent.

## Soft residual

Host must wire discovery-instructions pin into connect/consent path.
Not deepset 80%. Escalate remains BLOCK for inbound hard-block marketing claims.
