# MemoryWriteGate (PMPA thin land)

Durable preference/rule persist from untrusted content requires **explicit user confirm**. Mid-doc “remember / store in memory” alone → **no write**.

**KPI = durable write-gate + post-retrieve egress.** Not deepset 80%. Not lexicon-primary. Compose CPE SourceTrust; keep GhostSplice / Deadbugz / Loopjacking no-worsen. Soft residual: host must wire the memory-write hook.

## Layers

| Layer | API | Behavior |
|-------|-----|----------|
| **A — MemoryWriteGate** | `memoryWriteGate(attempt, store?)` | Untrusted / unconfirmed write-intent → `NO_DURABLE_WRITE`. Explicit user + `explicitConfirm` → `ALLOW_AFTER_CONFIRM` + persist. No write-intent → `NO_TRIP`. |
| **B — PreferenceRule provenance** | `{ sourceSession, contentTrust, origin }` · `preferenceRuleActTrust` | Stamp every durable rule. On recall, `untrusted` / non-`user_confirmed` → untrusted for AG/KPI-C (compose CPE). |
| **C — Side-recipient bind** | `actionGuard(..., { preferenceProvenance })` · `denySideRecipientBind` | `invitees` / `cc` / `bcc` / `sync` ⊆ TrustedPlan `argAllowlist`. Open plan insufficient for preference-driven side recipients → DENY. |

## Integrator hook

```typescript
import {
  memoryWriteGate,
  PreferenceRuleStore,
  preferenceRuleActTrust,
  actionGuard,
} from '@sovguard/engine';

const store = new PreferenceRuleStore();

// Mid-doc untrusted content — no durable write without confirm
const gated = memoryWriteGate({
  sessionId: 's-qa-1',
  role: 'untrusted_content',
  text: docText, // may contain "remember this requirement in the memory…"
}, store);
// gated.verdict === 'NO_DURABLE_WRITE'; gated.durableWrite === false

// Explicit user save preference
const saved = memoryWriteGate({
  sessionId: 's-user-1',
  role: 'user',
  text: 'Please save this preference: always CC me on project emails.',
  explicitConfirm: true,
}, store);
// saved.verdict === 'ALLOW_AFTER_CONFIRM'; provenance.contentTrust === 'user_confirmed'

// Later session: recalled untrusted PreferenceRule → side-recipient bind
const poison = store.list()[0]; // or host durable recall
const trust = preferenceRuleActTrust(poison);
const decision = actionGuard(trustedPlan, proposedActions, {
  preferenceProvenance: poison.provenance, // forces invitees/cc/bcc/sync ⊆ argAllowlist
});
```

## Non-goals

CFD artifact lineage · lexicon expand as primary · deepset 80% · AttackIndex / IOC · VSL/BragJack · GhostSplice / Deadbugz / CPE / Loopjacking re-land
