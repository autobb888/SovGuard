# J41 opt-in data-protection / PII wrapper (thin productization)

**Item:** DL-011 J41 opt-in PII wrapper  
**Design:** `/workspace/defense-lab/DL-011-J41-opt-in-PII-wrapper-design-acceptance-2026-09-25.md`  
**Land acceptance:** `/workspace/defense-lab/DL-011-J41-opt-in-PII-wrapper-land-acceptance-2026-09-25.md`  
**Prior land (reuse):** opt-in `dataProtection` @ `76d4a3c` · AgentCore DP session hygiene · GhostSplice `scanProposedToolArgs`  
**Base tip:** `f9e9008` (PersistentBillable on main)  
**Non-goals:** deepset 80% · forced-on / default-ON · new postal/mailing pack · detector rewrite · prior-land reopen · DLP-complete claims

**Escalate BLOCK. Soft residuals stay soft. Opt-in only.**

## Product rule

Global / chat default remains **OFF**. Integrators opt in per job, tenant, or session by passing `dataProtection: true` on outbound `scanOutput` / `POST /v1/scan/output`. Engine never infers DP from chat mode.

This is **not** a new DLP product. Detectors already existed; this land productizes the contract (docs + optional redact helper + named profile enum).

## Detectors (unchanged)

| Buyer label | Detector | Gate |
|-------------|----------|------|
| API keys / secrets | `scanSecrets` (+ GhostSplice tool-arg path) | Outbound: `dataProtection===true`. Tool args (`mcp_result`/`api_response`): **always-on** (orthogonal) |
| Cards | `scanPII` (Luhn CC) | `dataProtection===true` |
| Address-class today | email/phone via `scanPII`; crypto wallets via `scanFinancial` | `dataProtection===true` |
| Postal / street mailing | **HOLD** — no pack this land | — |

`scanOutput` still skips PII/secrets/financial unless `dataProtection === true`. Canary / egress / URL exfil / code / contamination / toxicity **always** run (KPI-C no-worsen).

## A — Docs opt-in contract (J41-11 / J41-13)

Honesty bars for Dashboard / host copy:

- Opt-in only; default OFF forever on Marketplace / J41 chat unless host opts in
- Not DLP-complete; not deepset 80%
- Postal/mailing HOLD (email/phone warn is the address-class stand-in today)
- Soft residuals stay soft (host toggle persistence, Dashboard claims wording, Soft C-DoS / Soft mcp_config Pred₆)
- Do not reopen TraceIntegrity / InstrumentalEvasion / ApprovalLaundering / PersistentBillable / ControlToken / Chronos / A2A / A2M

## B — Optional `redactOutput` helper

Hosts that want scrubbed buyer-facing text may call:

```typescript
import { scanOutput, redactOutput } from '@sovguard/engine';

const result = scanOutput(agentText, { jobId, dataProtection: true });
const scrubbed = redactOutput(result.flags, agentText);
// scrubbed replaces action:'redact' spans with [REDACTED_KEY] / [REDACTED_CC] / …
```

- **Host-callable only** — **not** auto-wired into `scanOutput`
- Only rewrites flags with `action: 'redact'` (`warn` / `block` / `flag` untouched)
- Secret flags store `evidence: '(redacted)'` in the payload; the helper re-applies secret *shapes* to locate spans in the original text
- Placeholders: `[REDACTED_KEY]`, `[REDACTED_CC]`, `[REDACTED_SSN]`, `[REDACTED_EMAIL]`, `[REDACTED_PHONE]`, `[REDACTED_WALLET]`, `[REDACTED]`

## C — Named policy profiles `flag` | `redact` | `block`

```typescript
import {
  J41_POLICY_PROFILES,
  J41_POLICY_DEFAULT_PER_FLAG,
  j41ProfileToActions,
  isJ41PolicyProfile,
} from '@sovguard/engine';

j41ProfileToActions('flag');   // → ['flag', 'warn']  — deliver + surface
j41ProfileToActions('redact'); // → ['redact']        — optional redactOutput
j41ProfileToActions('block');  // → ['block']         — hold / HITL
```

| Profile | Host behavior | Maps to `OutputFlag.action` |
|---------|---------------|------------------------------|
| `flag` | Deliver + surface flags to operator/UI | `flag`, `warn` |
| `redact` | Replace redact spans (via `redactOutput` or host) | `redact` |
| `block` | Hold message; HITL / re-gen; ApprovalBinding if act | `block` |

**Default when DP ON:** `J41_POLICY_DEFAULT_PER_FLAG` (`per_flag_actions`) — today's per-flag actions with **no remap** (SSN/CC/wallets `block`, email/phone `warn`, many API keys `redact`/`block` by severity). Hosts that want `flag`-only must set an explicit profile override in product config (engine does not auto-remap).

**“Wrap” clarification:** SovGuard `/v1/wrap` is inbound Spotlighting delivery — **not** a PII mask. Do not conflate Spotlighting wrap with DP redact in product copy.

## Session hygiene (compose, unchanged)

```typescript
import { sessionGateDataProtection, scanOutput } from '@sovguard/engine';

const gate = sessionGateDataProtection({ hasVault: true, hasBearerAuth: true });
scanOutput(agentText, { jobId, dataProtection: gate.dataProtection });
```

Recommend/gate for vault/Bearer/identity agents only — **never** flips the global default alone.

## Soft residuals (stay soft)

| Residual | Owner |
|----------|-------|
| Job/tenant toggle persistence + pass `dataProtection` | J41 integrator / site |
| Postal/street address pack | Threat Scout → Auto green → EK (HOLD) |
| Dashboard external claims wording | Dashboard |
| HITL on DP `block` → later tool send | Host + ApprovalBinding wire (soft) |
| Soft C-DoS / Soft mcp_config Pred₆ UI | DL/Coord labels (AL soft) — do not invent new soft labels |

## Non-goals

- Forced-on-all-traffic or default-ON
- New postal regex pack
- Inbound PI promote / chat sole-clf escalate / deepset 80%
- Redeveloping `scanPII` / `scanSecrets` / `scanFinancial`
- Reopening ApprovalBinding / GhostSplice / AgentCore / PersistentBillable / Trace / IME / AL / CT / Chronos / A2A / A2M
- Auto-applying redact inside `scanOutput`
