# ChronosAttack / Tool Order (thin land A–C)

**Item:** DL-Chronos-ToolOrder (P1 timing-surface)  
**Source shapes:** [arxiv 2609.27857](https://arxiv.org/abs/2609.27857) · ChronosAttack (**shapes only — do not clone/run kit**)  
**Base tip:** `412f3f9` (A2A GATE CLOSE tip)  
**Compose:** ActionGuard stays content-side · A2M return IFC / C-DoS GATE CLOSED · ControlToken `assessTraceToolComposite` GATE CLOSED Soft D soft · PeerRegistry Soft C–E soft (identity ≠ tool-obs order)  
**Non-goals:** deepset 80% · ChronosAttack kit · A2M reopen · ControlToken reopen · stretch ActionGuard / PeerRegistry / return-IFC / C-DoS into order barriers · async host wait-until-quiescence (soft follow-on)

## A — Decision-step barrier

Buffer all tool observations for one logical decision; present in **canonical tool order** (stable sort by `toolName` then `id`). Arrival timing must **not** determine serialization seen by the model.

```typescript
import { DecisionStepBarrier } from '@sovguard/engine';

const barrier = new DecisionStepBarrier();
barrier.enrollObservation('dec-1', { id: 'obs-c', toolName: 'weather', payload: { temp: 72 } });
barrier.enrollObservation('dec-1', { id: 'obs-a', toolName: 'calendar', payload: { busy: false } });
barrier.enrollObservation('dec-1', { id: 'obs-b', toolName: 'email', payload: { unread: 0 } });
barrier.sealDecision('dec-1');
barrier.serializeForModel('dec-1');
// → calendar::obs-a|email::obs-b|weather::obs-c  (NOT arrival order)
```

## B — Order-consistency abstain / HITL

For m=3 observations evaluate all 6 permutations via `decide(order)`. If max vote ≥ 4 → **ALLOW** with majority choice; else **ABSTAIN** / **HITL**.

```typescript
import { evaluateOrderConsistency } from '@sovguard/engine';

const r = evaluateOrderConsistency(observations, (order) => myDecide(order));
// r.verdict === 'ALLOW' | 'HITL' | 'ABSTAIN'
```

## C — SessionScorer flip-after-late-obs escalate

Record a provisional choice; when a delayed authentic observation flips that choice → **escalate** (soft signal; escalate-before-deny — not hard DENY).

```typescript
import { SessionScorer } from '@sovguard/engine';

const scorer = new SessionScorer();
scorer.recordProvisionalChoice(sessionId, decisionId, 'approve_transfer');
const flip = scorer.observeLateAuthentic(sessionId, decisionId, 'deny_transfer');
// flip.signal === 'OrderFlip.ESCALATE_flip_after_late_obs'; flip.escalated === true
```

## Soft / follow-on (not this land)

| Soft | Note |
|------|------|
| Async host barrier | wait-until-quiescence product wire |
| Soft C–E PeerRegistry | identity ≠ Chronos tool-obs order |
| Soft D `assessTraceToolComposite` | CoT oversight ≠ order axis |
| Schedule-sensitivity / m>3 | per-model profiles; vote cost opt-in |

## Acceptance gates

CH1 barrier/canonical · CH2 ≥4/6 else ABSTAIN · CH3 flip→escalate · CH4 pairwise inversion barrier-on no flip · CH5 orthogonal compose · CH6 honesty/no kit · F1 shapes n≥6 · R1 regression green.

## Escalate

**BLOCK**. Not deepset 80%. Soft residuals stand. No merge until DL PASS + RA.
