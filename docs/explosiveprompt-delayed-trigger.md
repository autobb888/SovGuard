# ExplosivePrompt / widen DL-008 (conditional IPI)

Thin land on tip `f4f2643`: close ExplosivePrompt residual where natural conversational
closings miss DL-008, paired imperative strips while EP soft-allows, and after a missed
plant an open TrustedPlan ALLOWs goal tools on closing-alone.

**KPI** = ingest **conditional-structure** flag + **act-bind** on trigger.  
**Not** deepset 80%. **Not** lexicon-only primary. Escalate **BLOCK**.

## A — Widen DelayedTriggerWatch / DL-008

`detectDelayedTrigger` detects **conditional structure** in untrusted ingest:

- `if` / `when` + deferred cue (including natural closings: thanks / bye / goodbye / finish / ends)
- deferred **state-changing** tool (send_email, transfer_funds, create_pr, send_message, bcc/exfil, `use the <tool> tool`)

Quarantine / flag at ingest via existing `scanContext` (`delayed_trigger`).  
Preserve CRM BCC baseline (Crowdstrike PT0201 shapes still `found=true` + `draft_email` arm).

User / `user_chat` sources remain trusted — no false quarantine (G4).

## B — ActionGuard plant-provenance bind

```typescript
import { actionGuard, DelayedTriggerWatch, detectDelayedTrigger } from '@sovguard/engine';

const watch = new DelayedTriggerWatch();
watch.recordIngest(sessionId, detectDelayedTrigger(untrustedText), {
  sourceTrust: 'untrusted',
});

const decision = actionGuard(trustedPlan, proposedActions, {
  delayedPlant: { watch, sessionId },
});
// Proposed tool matching armed deferred action → DENY / escalate
// Closing utterance alone insufficient; open TrustedPlan does not clear the bind
```

Pass `SourceTrust: 'user'` or `hitlConfirm: true` to ALLOW (G4).

## C — KPI-C goal destination compose

When a delayed plant is armed, goal destinations / recipients (`to` / `cc` / `bcc` /
`destination` / side-recipients) on EP-armed acts must ⊆ TrustedPlan `argAllowlist`.
Open plan insufficient → DENY (`denyEpGoalDestinationBind` / wired inside `actionGuard`).

## D — User / HITL ALLOW

`SourceTrust=user` / `user_confirmed` / `hitl` / `explicit_confirm` → no Watch arm, no
plant-bind DENY, scanContext allow on user path.

## Soft residual

Host must wire `DelayedTriggerWatch.recordIngest` + `actionGuard({ delayedPlant })` on
tool fire. SessionScorer delayed-flag wiring remains soft residual.

## Non-goals

Lexicon-only expand as primary · deepset 80% · AttackIndex / IOC · MCP-DiscoveryInstructions
this tip · LITL · Loopjacking / PMPA / CFD / GhostSplice / Deadbugz re-land.

## Fixtures

`pentest/payloads/explosiveprompt-conditional-ipi.json` (Threat Scout shapes 1–5).
