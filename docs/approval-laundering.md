# ApprovalLaundering / Effect-bound Pred₆ (thin land A–D)

**Item:** DL-ApprovalLaundering-EffectBound (P1 closure-bound approval)  
**Source shapes:** [arxiv 2609.28586](https://arxiv.org/abs/2609.28586) · Zhang et al. (**shapes only — no PoC / no kit**)  
**Base tip:** `5825944` (InstrumentalEvasion tip-of-record)  
**Compose:** Soft-compose **ApprovalBinding** (use-time digests + one-shot + refuse-lossy stay — do **not** re-land Loopjacking). Extend **`gateMcpConfigWrite`** with network-at-approve Ω₆ (do not gut). Soft-compose **ActionGuard** (do not stretch as Pred₆ predictor). Soft mcp_config host Pred₆ UI Soft. Soft C-DoS → PersistentBillable (**do not land C-DoS**). Soft async Chronos / Soft C–E / Soft D stay soft. **Do not reopen** ControlToken / Chronos / A2A / A2M. **Do not land TraceIntegrity / InstrumentalEvasion / PersistentBillable here.**  
**Non-goals:** deepset 80% · paper attack PoC / kit · freelancing beyond A–D · merge/prod without RA APPROVE

## A — EffectBoundRecord / freezePred6BeforeAllow

Before ALLOW, freeze predicted Ω₆ classes (process / file / env / network / container / MCP) + provenance digests (package.json / lockfile / Dockerfile / `.mcp.json` / hooks) into a companion `EffectBoundRecord`. Compose with entry digest — do **not** replace ApprovalBinding entry bind.

```typescript
import { freezePred6BeforeAllow, requireFrozenPred6BeforeAllow } from '@sovguard/engine';

const { ok, record } = freezePred6BeforeAllow({
  omega6Classes: ['process', 'file', 'network'],
  provenance: {
    'package.json': '{"name":"demo"}',
    lockfile: 'lock-shape',
    hooks: 'postinstall-shape',
  },
  entryDigest: '…', // companion only
});
// ok === true; record.frozenBeforeAllow === true
requireFrozenPred6BeforeAllow(record); // allow: true
```

## B — Closure witness Eff ⊆ Rep

Post-run observed effects must ⊆ approved representation. Unexplained residual → pause / re-ASK (no silent expand). Ambient tmp/telemetry allowlistable; high-risk Ω₆ (network / process / container / MCP) residual outside Rep must pause/re-ASK.

```typescript
import { assertEffSubseteqRep } from '@sovguard/engine';

assertEffSubseteqRep(record, [
  { omega6Class: 'network', unexplained: true },
]);
// → PAUSE_REASK, pauseOrReAsk: true, silentExpand: false

assertEffSubseteqRep(record, [
  { omega6Class: 'file', ambientClass: 'tmp' },
]);
// → AMBIENT_ALLOWLISTED (when file not required to be high-risk cover)
```

## C — MCP config→network at approve

Streamable HTTP / remote / URL transport proposals must surface **network** (and related Ω₆) on the card at decision time. Entry `mcp_config` digest alone insufficient. Compose with `gateMcpConfigWrite`.

```typescript
import {
  requireNetworkOmega6OnCard,
  gateMcpConfigWriteWithNetworkAtApprove,
  freezeMcpRemotePred6Card,
} from '@sovguard/engine';

requireNetworkOmega6OnCard({
  attempt: {
    action: 'server_add',
    proposedServer: { id: 'remote', url: 'https://example.invalid/mcp', transport: 'streamable_http' },
  },
  entryDigestPresent: true,
  omega6OnCard: ['MCP'], // missing network
});
// → ok: false, entryDigestAloneSufficient: false, gate DENY_entry_digest_alone

const freeze = freezeMcpRemotePred6Card({
  attempt: { action: 'server_add', proposedServer: { id: 'r', url: 'https://example.invalid', transport: 'http' } },
});
// freeze.record.omega6Classes includes 'network'
```

## D — Install→lifecycle predict

Package install / add approvals must predict postinstall / file / network lifecycle. Frozen-lockfile / fixed-SHA does **not** erase residual when hooks remain.

```typescript
import { predictInstallLifecycle, gateInstallLifecycleApprove } from '@sovguard/engine';

predictInstallLifecycle({
  action: 'npm_install',
  lockfileFrozen: true,
  fixedSha: true,
  hooksRemain: true,
});
// → lifecyclePredicted: true, lockfileAloneSufficient: false,
//    predictedClasses: ['process','file','network']

gateInstallLifecycleApprove(
  { action: 'npm_add', lockfileFrozen: true, hooksRemain: true },
  false, // card missing lifecycle Pred₆
);
// → DENY_lockfile_alone / REQUIRE_LIFECYCLE_PRED
```

## Soft / follow-on (not this land)

| Soft | Note |
|------|------|
| Host PreToolUse ASK wire (Claude/Codex-class) | product surface |
| Richer Ω₆ predictors for Docker multi-stage | follow-on |
| Soft mcp_config host route UI for Pred₆ card | Soft until host bakes |
| Soft C-DoS / ToolCallBudget → PersistentBillable | **do not land C-DoS** |
| Soft async Chronos / Soft C–E / Soft D | stay soft |
| TraceIntegrity / InstrumentalEvasion | serial lands elsewhere — do not land here |

## Soft-compose notes (closed lands untouched)

- **ApprovalBinding** — entry use-time digest + one-shot + refuse-lossy **stay**; Soft-compose only (no Loopjacking re-land).
- **`gateMcpConfigWrite`** — entry envelope stays; this land adds network-at-approve Ω₆ declare.
- **ActionGuard** — act-gate compose stays; do **not** stretch as Pred₆ predictor.
- ControlToken / Chronos / A2A / A2M — GATE CLOSED; do not reopen.
- TraceIntegrity / InstrumentalEvasion / PersistentBillable — do not land in this pack.
- SchemaConsent / Deadbugz / CFD / PMPA — complementary; not effect-closure substitutes.

## Acceptance gates

AL1 Pred₆ before ALLOW · AL2 Eff ⊆ Rep · AL3 MCP→network at approve · AL4 install→lifecycle · AL5 entry-bind compose no-worsen · AL6 orthogonal / honesty · F1 pack n≥6 shapes-only · R1 no-worsen.

## Escalate

**BLOCK**. Not deepset 80%. Soft residuals stand. No merge until DL PASS + RA written APPROVE.
