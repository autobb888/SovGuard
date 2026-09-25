# PersistentBillable / Denial-of-Wallet retained-mass (thin land A–F)

**Item:** DL-PersistentBillable-PreReingestion (P1 retained-mass economic amplification)  
**Source shapes:** [arxiv 2609.28585](https://arxiv.org/abs/2609.28585) · Zhang et al. (**shapes only — no PoC / no DoW-Bench kit**)  
**Base tip:** `5164f50` (ApprovalLaundering tip-of-record)  
**Compose:** Soft-compose **ToolCallBudgetStore** same-tool volume + weighted invocation cost + Soft host wire (do **not** re-land A2M C as complete DoW close). Soft C-DoS elevated soft **owned here** (volume **and** retained-mass). `applyReturnIfc` / `labelToolReturn` trust label stays — not a pre-reingestion substitute. Soft mcp_config / AL Pred₆ stays AL soft. Soft async Chronos / Soft C–E / Soft D stay soft. **Do not reopen** ControlToken / Chronos / A2A / A2M. **Do not land TraceIntegrity / InstrumentalEvasion / ApprovalLaundering here.**  
**Non-goals:** deepset 80% · paper attack PoC / kit · freelancing beyond A–F · merge/prod without RA APPROVE

## A — PreReingestionGate

Before next billable model call, transform / compress / tombstone untrusted tool returns (`source=mcp_result` and peers). Raw retained mass must **not** re-enter prompt unchanged.

```typescript
import {
  preReingestUntrustedReturn,
  applyPreReingestionBeforeBillable,
  denyRawReenterUntrusted,
} from '@sovguard/engine';

preReingestUntrustedReturn({
  raw: '…large untrusted mcp_result…',
  source: 'mcp_result',
});
// → ALLOW_TRANSFORMED or TOMBSTONE; rawReenterBlocked: true

denyRawReenterUntrusted({
  source: 'mcp_result',
  raw: 'PAD',
  proposedPromptFragment: 'PAD',
});
// → DENY_RAW_REENTER

applyPreReingestionBeforeBillable({
  returns: [{ raw: 'x', source: 'mcp_result' }],
});
// → safeBodies are transformed only
```

## B — D1 TokenMassBound

Bound retained tool-return + prompt token mass across turns; trip → compress harder / HITL / DENY further retention.

```typescript
import { TokenMassBoundStore, gateTokenMassBound } from '@sovguard/engine';

const store = new TokenMassBoundStore();
gateTokenMassBound(store, {
  sessionId: 's1',
  proposedRetainedToolTokens: 9000,
  proposedPromptTokenMass: 40000,
});
// → COMPRESS_HARDER / HITL / DENY_FURTHER_RETENTION when over bound
```

## C — D2 AdjacentGrowthBound (Δp)

Bound adjacent prompt-growth; delayed / stealth padding still trips.

```typescript
import { AdjacentGrowthBoundStore, gateAdjacentGrowthBound } from '@sovguard/engine';

const g = new AdjacentGrowthBoundStore();
gateAdjacentGrowthBound(g, { sessionId: 's1', promptTokenMass: 1000 }); // baseline
gateAdjacentGrowthBound(g, {
  sessionId: 's1',
  promptTokenMass: 5000,
  delayedOrStealthSignal: true,
});
// → HITL / DENY_GROWTH (delayed/stealth still trips)
```

## D — D3 ToolTurnDepth / RecursiveOpportunity

Bound recursive opportunity / tool-turn depth **across tools**. Compose with (do not replace) same-tool `CDoSCap.same_tool_reinvocation`.

```typescript
import { ToolTurnDepthStore, gateToolTurnDepth, ToolCallBudgetStore } from '@sovguard/engine';

const depth = new ToolTurnDepthStore();
const volume = new ToolCallBudgetStore(); // compose — volume stays
gateToolTurnDepth(depth, {
  sessionId: 's1',
  tool: 'tool_b',
  sameToolCdosChecked: true,
});
```

## E — D4 CumulativeSpend + ProgressAuthorized

Session cumulative spend ceiling; exemptions require **host-verified** milestones (not model self-report).

```typescript
import { CumulativeSpendStore, gateCumulativeSpend } from '@sovguard/engine';

const spend = new CumulativeSpendStore();
spend.recordHostVerifiedMilestone('s1', {
  id: 'm1',
  hostAttestation: 'host-signed-token',
  unlockSpendUnits: 5000,
  hostSetAt: Date.now(),
});
// model self-report alone → DENY_model_self_report
gateCumulativeSpend(spend, {
  sessionId: 's1',
  proposedSpend: 20000,
  modelClaim: { claimedSpendExemption: true, claimedProgress: 'done' },
});
```

## F — Polymorphic / stealth trip

Representation-changing or delayed-growth padding must still trip growth or spend (forces D2/D4 evaluation on morph/delay signals; no exact-string match required).

```typescript
import {
  tripPolymorphicStealth,
  AdjacentGrowthBoundStore,
  CumulativeSpendStore,
} from '@sovguard/engine';

tripPolymorphicStealth(new AdjacentGrowthBoundStore(), new CumulativeSpendStore(), {
  sessionId: 's1',
  promptTokenMass: 8000,
  proposedSpend: 100,
  signal: { representationChanged: true, delayedGrowth: true },
});
// → TRIP_GROWTH / TRIP_SPEND / TRIP_BOTH / HITL
```

## Soft / follow-on (not this land)

| Soft | Note |
|------|------|
| Host wire PreReingestion before provider call | Soft until host bakes |
| Richer compress policies | follow-on |
| SessionScorer soft correlator (mass×velocity) | not a substitute |
| Soft mcp_config → Approval Laundering | **do not land AL** |
| Soft async Chronos / Soft C–E / Soft D | stay soft |
| TraceIntegrity / InstrumentalEvasion / ApprovalLaundering | serial lands elsewhere — do not land here |

## Soft-compose notes (closed lands untouched)

- **ToolCallBudgetStore** — same-tool volume + weighted cost **stay**; Soft C-DoS owned here covers volume **and** retained-mass.
- **`applyReturnIfc` / `labelToolReturn`** — trust label stays; label ≠ compress/tombstone.
- ControlToken / Chronos / A2A / A2M — GATE CLOSED; do not reopen.
- TraceIntegrity / InstrumentalEvasion / ApprovalLaundering — do not land in this pack.
- Soft mcp_config / AL Pred₆ — stays AL soft.

## Acceptance gates

PB1 Pre-reingestion · PB2 D1 mass · PB3 D2 Δp · PB4 D3 depth · PB5 D4 spend+host milestones · PB6 polymorphic/stealth · PB7 compose C-DoS volume · PB8 honesty/orthogonal · F1 pack · R1 no-worsen.

## Escalate

**BLOCK**. Not deepset 80%. Soft residuals stand. No merge until DL PASS + RA written APPROVE.
