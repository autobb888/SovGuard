# ApprovalBinding (Loopjacking thin land)

Exact use-time bind of a HITL-approved action *A* so a genuine approve cannot release materially different *B*.

**KPI = approval-binding integrity at the act gate.** Not deepset 80%. Not dialog PI ASR. No VSL / BragJack / AttackIndex / IOC this land.

## Layers

| Layer | API | Behavior |
|-------|-----|----------|
| **A — Digest @ approve** | `approveAction(store, vector)` / `ApprovalBindingStore.record` | Persist `ApprovalTicket` with sha256 of stable-stringified `(tool, args, destination, scope)`. |
| **B — Use-time compare** | `compareApprovalAtUse` · composed inside `actionGuard` via `opts.approvalBinding` | Recompute use-time digest; mismatch → **DENY / require re-approval**. |
| **C — One-shot consume** | `releaseWithApproval` · `store.consume` on AG allow | After first successful release, ticket consumed; replay → **DENY**. |
| **D — Representation completeness** | `assertRepresentationComplete` · `approveAction(..., { uiView })` | Refuse approve when UI view is lossy/incomplete vs executable vector. |

## Integrator hook

```typescript
import {
  ApprovalBindingStore,
  approveAction,
  actionGuard,
} from '@sovguard/engine';

const store = new ApprovalBindingStore();

// HITL gate — host presents full canonical vector (or refuse-lossy when UI incomplete)
const approved = approveAction(store, {
  tool: 'send_email',
  args: { to: 'alice@example.test', subject: 'Q3', body: '…' },
  destination: 'smtp://mail.example.test',
  scope: 'user_initiated',
}, {
  uiView: {
    tool: 'send_email',
    shownArgs: { to: 'alice@example.test', subject: 'Q3', body: '…' },
    shownDestination: 'smtp://mail.example.test',
    shownScope: 'user_initiated',
  },
});
if (!approved.ok) {
  // refusedLossy or other — do not issue ticket
}

// Act gate — compose ActionGuard
const decision = actionGuard(
  trustedPlan,
  [{ type: 'tool', name: 'send_email', args: pendingArgs }],
  {
    approvalBinding: {
      store,
      ticketId: approved.ticket!.id,
      destination: 'smtp://mail.example.test',
      scope: 'user_initiated',
    },
  },
);
// execute only decision.allowed; mutated args_B / replay → denied
```

## Soft residuals

1. **Host must wire HITL approve** into `approveAction` / digest-at-approve — engine ships bind/compare/consume; integrator supplies the human gate.
2. **Representation completeness depends on host UI** — engine refuses lossy approve when host supplies incomplete view metadata (`lossy: true`, omitted keys, or shown≠executable digest).
3. **argAllowlist remains complementary** — plan-level exact membership; ApprovalBinding is the per-approval-event close.

## Orthogonal (no-worsen)

- `TrustedPlan.argAllowlist` (DL-012b)
- `scanProposedToolArgs` (GhostSplice A) for `mcp_result` / `api_response`
- `SchemaConsentStore` / `assertContinuousSchemaIntegrity` (Deadbugz) — **schema** bind ≠ **action** ApprovalBinding

## Out of scope this tip

VSL · BragJack · deepset 80% / AttackIndex / IOC · DescGuard · dual-stream · MCPSEC · Plugin4Shell · session sticky
