# ActionGuard integrator hook (DL-004)

SovGuard cannot own every agent runtime. Integrators should:

1. Build a **trusted plan** from the *user* turn only (`tools` / `actions` / `urls`).
2. Never merge tools/URLs extracted from `email` / `file` / `web` / `mcp_result` / `other_agent` into that plan.
3. Before executing model tool calls, run:

```typescript
import { actionGuard, flagUntrustedUrlEcho, extractRemoteUrls } from '@sovguard/engine';

const decision = actionGuard(trustedPlan, proposedActions, { source: 'email' });
// execute only decision.allowed; log decision.denied

const untrustedUrls = extractRemoteUrls(emailBody);
const echoed = flagUntrustedUrlEcho(modelOutput, trustedPlan, untrustedUrls);
// if echoed.length, block/rewrite via egress
```

EchoLeak-shaped recipient-framed mail without AI keywords still cannot expand the plan.


## GhostSplice arg-content gate (KPI-C compose)

When `source` is `mcp_result` or `api_response`, ActionGuard runs `scanProposedToolArgs` **before allow**, even if the tool name/URL is on TrustedPlan and there is no `argAllowlist`:

```typescript
import { actionGuard, scanProposedToolArgs } from '@sovguard/engine';

const decision = actionGuard(trustedPlan, proposedActions, { source: 'mcp_result' });
// Sensitive arg contents (PEM / cloud keys / .ssh / id_rsa / .env) → denied
```

Reuses outbound `scanSecrets` + sensitive-path markers. No new PI lexicon. KPI = act/egress integrity — not deepset / not GhostSplice paper ASR.

### Deferred: CrossChannelMcpWatch (G6 follow-on)

Per-server/session correlator over schema-doc + recent `mcp_result` texts (≥2 soft-channel mapping cues → elevate re-approval) is **not** in this tip. Ship arg-content alone; document follow-on so Deadbugz continuous fingerprint stays orthogonal and DL-009 assemble_execute FP risk stays out of this land.

### MCP sampling (docs / soft residual)

Treat MCP `sampling/createMessage` fields `systemPrompt` and `includeContext` as **untrusted**. Prefer human gate / SourceTrust before they influence acts. No dedicated sampling API in this tip (docs-only soft residual OK).


## ApprovalBinding (Loopjacking compose)

When the host has a HITL-approved ticket, pass `opts.approvalBinding` so ActionGuard rechecks the use-time digest of `(tool, args, destination, scope)` **before allow** and **consumes** the ticket on successful release:

```typescript
import { actionGuard, ApprovalBindingStore, approveAction } from '@sovguard/engine';

const store = new ApprovalBindingStore();
const { ticket } = approveAction(store, {
  tool: 'send_email',
  args: approvedArgs,
  destination: 'smtp://…',
  scope: 'user_initiated',
});

const decision = actionGuard(trustedPlan, proposedActions, {
  approvalBinding: {
    store,
    ticketId: ticket!.id,
    destination: 'smtp://…',
    scope: 'user_initiated',
  },
});
```

Mutated args / consumed replay → DENY. See `docs/approval-binding.md`. Orthogonal to argAllowlist, `scanProposedToolArgs`, and SchemaConsent.

## Side-recipient bind (PMPA / KPI-C compose)

When a recalled PreferenceRule has untrusted provenance, pass `opts.preferenceProvenance` so ActionGuard forces side-recipient bind before allow:

```typescript
const decision = actionGuard(trustedPlan, proposedActions, {
  preferenceProvenance: recalledRule.provenance, // contentTrust: 'untrusted'
});
// invitees / cc / bcc / sync must ⊆ TrustedPlan argAllowlist
// Open plan (tool allowed, no allowlist key) → DENY
```

Compose MemoryWriteGate + PreferenceRule provenance. See `docs/memory-write-gate.md`. Orthogonal to GhostSplice arg-content, Deadbugz schema integrity, and Loopjacking ApprovalBinding.

## ExplosivePrompt / DL-008 plant-provenance bind

When untrusted ingest armed a delayed conditional (EP / sleeping rule), pass
`opts.delayedPlant` so ActionGuard DENYs proposed tools that match the armed
deferred action — even on an open TrustedPlan. Closing utterance alone is
insufficient. User / HITL (`SourceTrust=user` or `hitlConfirm`) → ALLOW.

```typescript
import { actionGuard, DelayedTriggerWatch, detectDelayedTrigger } from '@sovguard/engine';

const watch = new DelayedTriggerWatch();
watch.recordIngest(sessionId, detectDelayedTrigger(ingestText), { sourceTrust: 'untrusted' });

const decision = actionGuard(trustedPlan, proposedActions, {
  delayedPlant: { watch, sessionId },
});
```

KPI-C: when a plant is armed, goal destinations/recipients must ⊆ TrustedPlan
`argAllowlist` (`denyEpGoalDestinationBind`). See `docs/explosiveprompt-delayed-trigger.md`.

