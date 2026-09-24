# A2A NameCollision (thin land A–B)

**Item:** DL-A2A-NameCollision (P1)  
**Source shapes:** [arxiv 2609.27624](https://arxiv.org/abs/2609.27624) · agent-name-collision-attacks (**shapes only — do not weaponize / do not clone kit**)  
**Base tip:** ControlToken freeze `45cfdd3` (not `afe91a6` alone)  
**Compose:** peer-envelope data↛instruction (`from` not authority) · ApprovalBinding if diverted peer steers config · GhostSplice on wrong-peer response channel  
**Non-goals:** deepset 80% · Chronos · A2M reopen · stretch `resolveToolShadowing` / A2M `preferPinnedTool` as identity fix · name-collision attack kit · freelancing past A–B

## A — Origin-bound stable ID

Enroll peers under **authenticated origin** + **opaque stable principal**. Routes / tools / workflows / auth **must** resolve by `stableId` — never by `AgentCard.name` / display name.

```typescript
import { PeerRegistry } from '@sovguard/engine';

const reg = new PeerRegistry();
const enroll = reg.enroll(
  {
    name: 'HelperAgent',
    origin: 'https://partner-a.example.test',
    transportAuthenticated: true,
  },
  { stableId: 'peer:origin-a:opaque-principal-1' }, // optional host pin; else mintStablePeerId
);
// enroll.verdict === 'ALLOW'; enroll.gate === 'PeerEnrollment.origin_bound_stable_id'

reg.resolveSelector({ stableId: enroll.peer!.stableId }); // ALLOW
reg.resolveSelector({ name: 'HelperAgent' });             // DENY — name not authority
```

## B — Fail-closed duplicates

Exact **or** normalization-equivalent (`HelperAgent` ≈ `helper-agent` ≈ `Helper Agent`) name collisions from **distinct origins** → **DENY** second register. Enrolled origin sticks regardless of admission order. Name-keyed dispatch is refused (no silent wrong-peer / last-replace collapse).

```typescript
reg.enroll({ name: 'HelperAgent', origin: 'https://partner-a.example.test', transportAuthenticated: true });
reg.enroll({ name: 'helper-agent', origin: 'https://attacker-b.evil.test', transportAuthenticated: true });
// → DENY_duplicate_name_distinct_origin; stuckPeer = A
```

## NC3 — Presentational rename (control)

`updateDisplayName` updates `displayName` only. **Does not** retarget `stableId` / origin. Selectors still resolve by ID.

```typescript
reg.updateDisplayName(stableId, 'HelperAgent-Renamed');
// retarget === false; resolveById(stableId) still A
```

## Soft C–E (document / host follow-on — omit thin implementation)

| Soft | Note |
|------|------|
| **C** | UI may show name; selectors resolve ID (covered as NC3 control) |
| **D** | Broker topics = stable principal; reject name-derived routes — optional `isNameDerivedBrokerTopic` helper |
| **E** | Authority / credentials attach only after authenticated identity resolution |

## Orthogonal (do not subsume / do not reopen)

- `resolveToolShadowing` — same-name **MCP tool** quarantine by trust  
- A2M `preferPinnedTool` / ToolAdmission — GATE CLOSED (`afe91a6` / site `0469a8c`); MCP-tool Attraction layer  
- peer-envelope `from` — display/provenance only; **not** enrolled stable principal  

## Acceptance gates

NC1 origin-bound ID · NC2 exact+norm DENY/stick · NC3 presentational rename · X1/X2 no-worsen · F1 shapes n≥4 · R1 regression green.

## Escalate

**BLOCK**. Not deepset 80%. Soft residuals stand. No merge until DL PASS + RA.
