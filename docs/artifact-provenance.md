# ArtifactProvenance (CFD thin land)

Close Context-Fractured Decomposition residual: instruction-free artifact plant across sessions composes into harmful outbound with Accept=1 leaves and no lineage.

**KPI = artifact lineage + composed egress.** Not deepset 80%. Not leaf PI lexicon. Distinct from PMPA MemoryWriteGate / PreferenceRule. Compose ActionGuard; keep GhostSplice / Deadbugz / Loopjacking / CPE no-worsen. Soft residual: host must wire write hooks.

## Layers

| Layer | API | Behavior |
|-------|-----|----------|
| **A — Tag-on-write** | `ArtifactProvenanceStore.tagOnWrite(path, {sessionId, intent, role, SourceTrust})` | Stamp provenance at file/log/ticket/template write. Leaf plant alone does not DENY. |
| **B — Inconsistent-tag compose gate** | `checkComposeProvenance(store, {artifactRefs, composeSessionId})` | Cross-session plant→compose or inconsistent `sessionId`/`SourceTrust` across composed refs → `DENY_REAPPROVE`. Honest same-session consistent tags → `ALLOW`. No tagged refs → `NO_TRIP` (soft-allow). |
| **C — KPI-C / AG composed egress** | `actionGuard(..., { artifactProvenance: { store, composeSessionId, artifactRefs? } })` · `denyInconsistentArtifactCompose` | Score compose with provenance; open plan + omitted origin insufficient when tags inconsistent. Does not replace GhostSplice / Deadbugz / Loopjacking / PMPA / CPE. |

## Integrator hook

```typescript
import {
  ArtifactProvenanceStore,
  checkComposeProvenance,
  actionGuard,
} from '@sovguard/engine';

const store = new ArtifactProvenanceStore();

// Session A — host wires write hook
store.tagOnWrite('artifacts/backup_manifest.txt', {
  sessionId: 'sess-A',
  intent: 'plant_buffer',
  role: 'untrusted_tool',
  SourceTrust: 'untrusted',
});

// Context wipe → Session B innocuous compose
const gate = checkComposeProvenance(store, {
  artifactRefs: ['artifacts/backup_manifest.txt'],
  composeSessionId: 'sess-B',
});
// gate.verdict === 'DENY_REAPPROVE'

const decision = actionGuard(
  { tools: ['send_email'] }, // open plan insufficient
  [{ type: 'tool', name: 'send_email', args: { attachment: 'artifacts/backup_manifest.txt', to: 'ops@example.test' } }],
  { artifactProvenance: { store, composeSessionId: 'sess-B' } },
);
// decision.denied — ArtifactProvenance cross_session_compose

// Honest same-session backup (FP bar)
store.clear();
store.tagOnWrite('backup/notes.txt', {
  sessionId: 'sess-honest',
  intent: 'user_backup',
  role: 'user',
  SourceTrust: 'user',
});
const honest = actionGuard(
  { tools: ['run_backup'] },
  [{ type: 'tool', name: 'run_backup', args: { include: ['backup/notes.txt'] } }],
  { artifactProvenance: { store, composeSessionId: 'sess-honest' } },
);
// honest.allowed — consistent tags
```

## Non-goals

PMPA MemoryWriteGate / PreferenceRule conflation · deepset 80% · AttackIndex / IOC · leaf PI lexicon expand · blanket sticky-untrusted without opt-out · GhostSplice / Deadbugz / Loopjacking / PMPA re-land · website bake
