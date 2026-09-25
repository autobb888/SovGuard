# TraceIntegrity / Trace Tampering (thin land A–D)

**Item:** DL-TraceIntegrity-IndependentRecorder (P1 host audit integrity)  
**Source shapes:** [arxiv 2609.30266](https://arxiv.org/abs/2609.30266) · Qin et al. (**shapes only — do not clone/run PoC/kit**)  
**Base tip:** `dd96030` (Chronos GATE CLOSE tip) / site `add13db`  
**Compose:** ActionGuard content/plan-side may compose session-path class · ControlToken `assessTraceToolComposite` GATE CLOSED Soft D soft · Chronos DecisionStepBarrier / OrderConsistency GATE CLOSED Soft async soft · A2A PeerRegistry Soft C–E soft · A2M return IFC / C-DoS GATE CLOSED · Soft ApprovalBinding stay soft  
**Non-goals:** deepset 80% · paper attack PoC/kit · ControlToken / Chronos / A2A / A2M reopen · treating `scan_log`/`audit_log` as independent recorder · Soft host gateway / Soft async/C–E/D / Soft ApprovalBinding/C-DoS land wires

## A — IndependentRecorder

Append-only record of model request/response/stream chunks into a store marked **`outsideSandbox: true`**. Fail-closed if append fails (block privileged continue). Agent wipe of harness session paths must leave the recorder intact.

```typescript
import { IndependentRecorder, simulateHarnessSessionWipe } from '@sovguard/engine';

const rec = new IndependentRecorder();
rec.record('model_request', { prompt: '…' });
rec.record('model_response', { text: '…' });
rec.record('stream_chunk', { delta: '…' });

// Agent wipes harness paths — recorder stays intact
const harness = { 'harness:session.jsonl': '…', 'harness:transcript.db': '…' };
const wiped = simulateHarnessSessionWipe(harness, ['harness:session.jsonl', 'harness:transcript.db']);
// wiped missing those keys; rec.list() unchanged
```

**Not** a substitute: in-sandbox `scan_log` / `audit_log`.

## B — SessionPathGate

Known harness session path **shapes** → write/delete/truncate/unlink → **DENY + escalate**. Privacy / reward framing does not authorize.

```typescript
import { gateSessionPath } from '@sovguard/engine';

gateSessionPath({ path: 'harness:session.jsonl', op: 'delete' });
// → DENY, escalate: true

gateSessionPath({
  path: 'harness:session.jsonl',
  op: 'delete',
  framing: 'privacy_protection_skill_or_reward_cue',
});
// → DENY (privacy framing does not authorize)
```

## C — SkillTamperGate

Skill (or injected instruction) demanding session wipe / fabricate lifecycle after a benign primary task → **REFUSE** skill step; primary task may complete.

```typescript
import { gateSkillTamper } from '@sovguard/engine';

const r = gateSkillTamper({
  primaryTask: 'benign_coding_edit',
  skillDemand: {
    shape: 'wipe_or_fabricate_session_after_task',
    lifecycleFabricate: true,
  },
});
// r.verdict === 'REFUSE'; r.primaryTaskMayComplete === true
```

## D — ToolAuthenticity

`BASH_ENV` / shell-snapshot mutation that redefines known tool binaries → **FLAG**; subsequent results untrusted until absolute-path re-verify.

```typescript
import { ToolAuthenticityTracker } from '@sovguard/engine';

const t = new ToolAuthenticityTracker();
t.observeMutation({
  channel: 'BASH_ENV_or_shell_snapshot',
  toolName: 'curl',
  shape: 'redefine_known_tool_binary',
});
t.assessToolResult({ claimedTool: 'curl', viaRedefinedPath: true });
// → UNTRUSTED, requiresAbsolutePathReverify: true
```

## Soft / follow-on (not this land)

| Soft | Note |
|------|------|
| Host independent gateway wire | product surface |
| Delayed/background scrubber detection | follow-on |
| Soft async Chronos host barrier | order axis soft |
| Soft C–E PeerRegistry | identity ≠ host audit |
| Soft D `assessTraceToolComposite` | CoT ≠ host FS wipe |
| Soft ApprovalBinding / Soft C-DoS | later P1 tracks |

## Acceptance gates

TI1 recorder survives wipe · TI2 session-path DENY · TI3 skill→tamper refuse · TI4 tool authenticity · TI5 orthogonal compose no-reopen · TI6 honesty/shapes-only · F1 pack n≥6 · R1 no-worsen.

## Escalate

**BLOCK**. Not deepset 80%. Soft residuals stand. No merge until DL PASS + RA written APPROVE.
