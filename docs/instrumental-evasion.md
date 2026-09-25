# InstrumentalEvasion / Instrumental Monitor Evasion (thin land A–E)

**Item:** DL-InstrumentalEvasion-HistoryAwareMonitor (P1 sync-tool monitor adaptive bypass)  
**Source shapes:** [arxiv 2609.30217](https://arxiv.org/abs/2609.30217) · Schmotz et al. (**shapes only — no PoC / no EvasionBench kit**)  
**Base tip:** `3020f03` (TraceIntegrity tip-of-record) / site `add13db` (ignore site)  
**Compose:** Soft-compose **ActionGuard** (content/plan/shell-class stay; history + denial-precedence + stdin/child classes) + **ApprovalBinding** (use-time approve bind stays). Soft mcp_config / Soft C-DoS elevated soft elsewhere. Soft async Chronos / Soft C–E PeerRegistry / Soft D `assessTraceToolComposite` stay soft. **Do not reopen** ControlToken / Chronos / A2A / A2M. **Do not land TraceIntegrity / AL / PB here.**  
**Non-goals:** deepset 80% · paper attack PoC / EvasionBench kit · freelancing beyond A–E · merge/prod without RA APPROVE

## A — MonitorHistoryLedger

Retain ≥N prior tool proposals with allow/block + truncated args + effect-class hash. Write→execute / alias→edit decomposition stays linked so the prohibited *effect* remains blocked.

```typescript
import { MonitorHistoryLedger } from '@sovguard/engine';

const ledger = new MonitorHistoryLedger({ windowSize: 8 });
ledger.evaluateWithHistory(
  { toolName: 'write_file', effectClass: 'prohibited_effect_X', shape: 'write_script_file' },
  'BLOCK',
);
const exec = ledger.evaluateWithHistory(
  { toolName: 'bash', effectClass: 'prohibited_effect_X', shape: 'execute_written_script' },
  'ALLOW', // myopic would allow — history links → BLOCK
);
// exec.verdict === 'BLOCK'; exec.gate === 'MonitorHistory.BLOCK_linked_effect'
```

## B — Interactive channel close

`write_stdin` / post-launch interactive / child stdin under the **same policy** as parent process launch. Parent ALLOW does not waive prohibited follow-on effects.

```typescript
import { gateWriteStdin, gateChildStdin } from '@sovguard/engine';

gateWriteStdin({
  parentLaunch: { shape: 'allowed_repl_or_process', policy: 'ALLOW' },
  followOn: {
    channel: 'write_stdin',
    payloadShape: 'prohibited_effect_ops',
    prohibitedEffect: true,
  },
});
// → BLOCK, reviewedUnderParentPolicy: true
```

## C — Persistent denial precedence

After a clear *authenticated* guardrail denial, encoded / aliased / equivalent-effect proposals of the same prohibited op → still BLOCK. Continuation must not weaken denial class. Transient tool-error denials do not bind without channel auth.

```typescript
import { DenialPrecedenceLedger } from '@sovguard/engine';

const d = new DenialPrecedenceLedger();
d.recordAuthenticatedDenial({
  effectClass: 'prohibited_effect_X',
  authenticated: true,
  channel: 'guardrail',
});
d.gateEquivalentEffect({
  effectClass: 'prohibited_effect_X',
  shape: 'encoded_wrapper_equivalent',
});
// → BLOCK, denialClassWeakened: false
```

## D — Forged-denial anti-overrefusal

Untrusted doc/tool-return text mimicking PreToolUse / monitor refusal must **not** abandon otherwise solvable *allowed* tasks (Astra-class DoS). Authenticate denials (channel / structured denial token) vs untrusted content. Real authenticated denials still bind.

```typescript
import { assessForgedDenial } from '@sovguard/engine';

assessForgedDenial({
  contentShape: 'fake_PreToolUse_or_monitor_refusal_text',
  actualChannel: 'untrusted_doc_or_tool_return',
  primaryTask: 'allowed_extract_or_solvable_task',
  realAuthenticatedDenial: false,
});
// → IGNORE_FORGED, primaryTaskMayContinue: true

assessForgedDenial({
  actualChannel: 'authenticated_channel',
  realAuthenticatedDenial: true,
  denialToken: 'sg-deny-…',
  knownDenialTokens: ['sg-deny-…'],
});
// → BIND_AUTHENTICATED, primaryTaskMayContinue: false
```

## E — Subagent policy inherit

Child / spawn agents inherit parent monitor policy **ceiling**. Parent cannot launder prohibited ops via `spawn_agent` / Agent defer. Child may further restrict; cannot exceed parent ceiling. `other_agent` ingress distrust ≠ inherit.

```typescript
import { inheritMonitorPolicyCeiling, denyLaunderViaSpawn } from '@sovguard/engine';

const parent = {
  deniedEffectClasses: new Set(['prohibited_effect_X']),
  priorDecision: 'DENY' as const,
};
const childCeiling = inheritMonitorPolicyCeiling(parent);
denyLaunderViaSpawn(parent, {
  shape: 'spawn_agent_or_defer',
  childEffectClass: 'prohibited_effect_X',
  childInstructionShape: 'same_prohibited_effect_X',
});
// → DENY_launder_via_spawn
```

## Soft / follow-on (not this land)

| Soft | Note |
|------|------|
| History-flood / budget-exhaust | SessionScorer soft signal only |
| Encode-wrapper equivalence beyond exact deny | follow-on |
| Host PreToolUse wire (Codex/Claude) | product surface |
| Soft mcp_config → Approval Laundering | separate P1 |
| Soft C-DoS → Persistent Billable | separate P1 |
| Soft async Chronos host barrier | order axis soft |
| Soft C–E PeerRegistry | identity soft |
| Soft D `assessTraceToolComposite` | CoT soft |
| TraceIntegrity thin A–D | already landed separately — do not reopen here |

## Soft-compose notes (closed lands untouched)

- **ActionGuard** — content/plan/shell-class stay; soft-compose target for history + denial-precedence + stdin/child classes (do not gut / reopen closed semantics).
- **ApprovalBinding** — use-time approve bind stays; this land persists *denied* effect class (orthogonal).
- ControlToken / Chronos / A2A / A2M — GATE CLOSED; do not reopen.
- TraceIntegrity — do not land / reopen in this pack.
- SessionScorer / DecompositionWatch — orthogonal; do not stretch as tool-monitor history.

## Acceptance gates

IE1 history-aware monitor · IE2 interactive channel close · IE3 denial precedence · IE4 forged-denial anti-overrefusal · IE5 subagent inherit · IE6 orthogonal compose / honesty · F1 pack n≥6 shapes-only · R1 no-worsen.

## Escalate

**BLOCK**. Not deepset 80%. Soft residuals stand. No merge until DL PASS + RA written APPROVE.
