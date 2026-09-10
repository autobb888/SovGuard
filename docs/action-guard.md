# ActionGuard integrator hook (DL-004)

SovGuard cannot own every agent runtime. Integrators should:

1. Build a **trusted plan** from the *user* turn only (`tools` / `actions` / `urls`).
2. Never merge tools/URLs extracted from `email` / `file` / `web` / `mcp_result` / `other_agent` into that plan.
3. Before executing model tool calls, run:

```typescript
import { actionGuard, flagUntrustedUrlEcho, extractRemoteUrls } from '@sovguard/engine';

const decision = actionGuard(trustedPlan, proposedActions, { source: 'email' });
// execute only decision.allowed; log decision.denied

const untrustedUrls = extractRemoteUrls(emailBody);
const echoed = flagUntrustedUrlEcho(modelOutput, trustedPlan, untrustedUrls);
// if echoed.length, block/rewrite via egress
```

EchoLeak-shaped recipient-framed mail without AI keywords still cannot expand the plan.
