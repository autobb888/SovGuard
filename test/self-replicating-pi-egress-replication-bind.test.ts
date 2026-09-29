/**
 * SelfReplicatingPI EgressReplicationBind — thin land A–D (SR1–SR5).
 * Fixture: prefer threat-scout pack; fallback pentest/payloads.
 * KPI = connector provenance + denyUntrustedVerbatimReemit + side-effect DENY.
 * Shapes only — digest tokens; no live OpenAI report / worm payloads.
 * Do not reopen Trace/IME/AL/PB/CT/Chronos/A2A/A2M/EP/PuzzleMask.
 */
import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  actionGuard,
  type TrustedPlan,
  type ProposedAction,
} from '../src/delivery/action-guard.js';
import {
  stampConnectorProvenance,
  isConnectorUntrustedSource,
  UntrustedIngressDigestStore,
  untrustedIngressDigestStore,
  denyUntrustedVerbatimReemit,
  denySideEffectAuthOnUntrusted,
  denyEgressReplicationBind,
  highOverlapEcho,
  collectReemitContentArgs,
  DEFAULT_HIGH_OVERLAP_THRESHOLD,
  type UntrustedIngressRecord,
} from '../src/delivery/egress-replication-bind.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TS_FIXTURE =
  '/workspace/threat-scout/pentest/payloads/self-replicating-pi-egress-replication-bind.json';
const LOCAL_FIXTURE = join(
  __dirname,
  '../pentest/payloads/self-replicating-pi-egress-replication-bind.json',
);
const fixturePath = existsSync(TS_FIXTURE) ? TS_FIXTURE : LOCAL_FIXTURE;

const pack = JSON.parse(readFileSync(fixturePath, 'utf8')) as {
  _meta?: Record<string, unknown>;
  fixtures: Array<Record<string, unknown>>;
};

function fix(id: string): Record<string, unknown> {
  const f = pack.fixtures.find((x) => x.id === id);
  assert.ok(f, `missing fixture ${id} in ${fixturePath}`);
  return f;
}

function planFrom(tools: string[]): TrustedPlan {
  return { tools };
}

/** Map fixture bodyShape → concrete args using digest tokens only (no live worm text). */
function bodyFromShape(
  shape: string | undefined,
  digest: string,
): string {
  const s = shape ?? '';
  if (
    /verbatim_or_high_overlap_echo|verbatim_echo_of_|reemit_of_prior/i.test(s) ||
    s.includes(digest)
  ) {
    return `workflow note carrying ${digest} for public channel`;
  }
  if (/echoDigestToken/i.test(s)) return digest;
  // ALLOW shapes — no ingress echo
  return 'Thanks — confirmed for Thursday 2pm. Looking forward to it.';
}

beforeEach(() => {
  untrustedIngressDigestStore.clearAll();
});

describe('SelfReplicatingPI A — connector provenance stamp', () => {
  it('stamps email / mcp_result / api_response / slack as connector ingress', () => {
    const email = stampConnectorProvenance('email');
    assert.equal(email.untrusted, true);
    assert.equal(email.connectorIngress, true);
    assert.equal(email.source, 'email');
    assert.ok(
      email.sourceTrust === 'email' || email.sourceTrust === 'connector_untrusted',
    );

    const mcp = stampConnectorProvenance('mcp_result');
    assert.equal(mcp.untrusted, true);
    assert.equal(mcp.source, 'mcp_result');

    const api = stampConnectorProvenance('api_response');
    assert.equal(api.untrusted, true);

    const slack = stampConnectorProvenance('slack');
    assert.equal(slack.untrusted, true);
    assert.equal(slack.source, 'slack_equivalent');

    const forced = stampConnectorProvenance('custom_wire', { forceUntrusted: true });
    assert.equal(forced.untrusted, true);
    assert.equal(forced.sourceTrust, 'connector_untrusted');
  });

  it('user source is not connector_untrusted', () => {
    const u = stampConnectorProvenance('user');
    assert.equal(u.connectorIngress, false);
    assert.equal(u.untrusted, false);
  });

  it('isConnectorUntrustedSource recognizes peers', () => {
    assert.equal(isConnectorUntrustedSource('email'), true);
    assert.equal(isConnectorUntrustedSource('connector_untrusted'), true);
    assert.equal(isConnectorUntrustedSource('slack_equivalent'), true);
    assert.equal(isConnectorUntrustedSource('user'), false);
  });
});

describe('SelfReplicatingPI B — denyUntrustedVerbatimReemit', () => {
  it('SR1: email verbatim-quote echo → DENY even when send_email ⊆ TrustedPlan', () => {
    const f = fix('sr1-email-verbatim-quote-deny');
    const event = f.event as {
      ingress: { digestToken: string; source: string; sourceTrust: string };
      proposedAction: { name: string; args: Record<string, string> };
      trustedPlan: { tools: string[] };
    };
    const digest = event.ingress.digestToken;
    const stamp = stampConnectorProvenance(event.ingress.source, {
      sourceTrust: event.ingress.sourceTrust,
    });
    assert.equal(stamp.untrusted, true);

    const store = new UntrustedIngressDigestStore();
    store.record('s1', {
      digestToken: digest,
      source: stamp.source,
      sourceTrust: stamp.sourceTrust,
      text: digest,
    });

    const body = bodyFromShape(event.proposedAction.args.bodyShape, digest);
    const plan = planFrom(event.trustedPlan.tools);
    assert.ok(plan.tools?.includes('send_email'));

    // Plan alone would allow
    const bare = actionGuard(plan, [
      { type: 'tool', name: 'send_email', args: { to: 'peer@example.test', body } },
    ]);
    assert.equal(bare.denied.length, 0, 'plan alone allows without bind');

    const deny = denyUntrustedVerbatimReemit(
      'send_email',
      { to: 'peer@example.test', body },
      { store, sessionId: 's1' },
    );
    assert.ok(deny);
    assert.match(deny!, /denyUntrustedVerbatimReemit/);

    const guarded = actionGuard(
      plan,
      [{ type: 'tool', name: 'send_email', args: { to: 'peer@example.test', body } }],
      {
        source: stamp.source,
        egressReplication: { store, sessionId: 's1' },
      },
    );
    assert.equal(guarded.allowed.length, 0);
    assert.ok(guarded.denied.length >= 1);
    assert.match(guarded.denied[0].reason, /denyUntrustedVerbatimReemit/);
  });

  it('SR1: ack without echo → ALLOW', () => {
    const f = fix('sr1-email-ack-without-echo-allow');
    const event = f.event as {
      ingress: { digestToken: string; source: string };
      proposedAction: { args: Record<string, string> };
      trustedPlan: { tools: string[] };
    };
    const digest = event.ingress.digestToken;
    const store = new UntrustedIngressDigestStore();
    store.record('s1', {
      digestToken: digest,
      source: 'email',
      sourceTrust: 'connector_untrusted',
      text: digest,
    });
    const body = bodyFromShape(event.proposedAction.args.bodyShape, digest);
    assert.ok(!body.includes(digest));

    const deny = denyUntrustedVerbatimReemit(
      'send_email',
      { to: 'peer@example.test', body },
      { store, sessionId: 's1' },
    );
    assert.equal(deny, null);

    const guarded = actionGuard(
      planFrom(event.trustedPlan.tools),
      [{ type: 'tool', name: 'send_email', args: { to: 'peer@example.test', body } }],
      { source: 'email', egressReplication: { store, sessionId: 's1' } },
    );
    assert.equal(guarded.denied.length, 0);
    assert.equal(guarded.allowed.length, 1);
  });

  it('highOverlapEcho: digest token containment + short citation FP guard', () => {
    assert.equal(
      highOverlapEcho('see INGEST_DIGEST_EMAIL_SR1 please', 'x', 'INGEST_DIGEST_EMAIL_SR1'),
      true,
    );
    assert.equal(highOverlapEcho('ok', 'INGEST_DIGEST_EMAIL_SR1', 'INGEST_DIGEST_EMAIL_SR1'), false);
    assert.ok(DEFAULT_HIGH_OVERLAP_THRESHOLD >= 0.5);
  });
});

describe('SelfReplicatingPI C — side-effect DENY when auth on untrusted', () => {
  it('SR2: write-verbatim + paired shell side-effect → DENY both', () => {
    const f = fix('sr2-fs-note-write-plus-side-effect-deny');
    const event = f.event as {
      ingress: { digestToken: string; source: string };
      proposedActions: Array<{ name: string; args: Record<string, string> }>;
      trustedPlan: { tools: string[] };
    };
    const digest = event.ingress.digestToken;
    const store = new UntrustedIngressDigestStore();
    store.record('s2', {
      digestToken: digest,
      source: 'mcp_result',
      sourceTrust: 'connector_untrusted',
      text: digest,
    });

    const writeArgs = {
      path: 'notes/policy.txt',
      content: `note carrying ${digest}`,
    };
    const shellArgs = {
      command: 'rm -rf ./security-scan',
      sideEffectShape: 'destructive_cleanup_or_strip_security_gate',
      authRestsOn: digest,
    };

    const writeDeny = denyUntrustedVerbatimReemit('write_file', writeArgs, {
      store,
      sessionId: 's2',
    });
    assert.ok(writeDeny);

    const sideDeny = denySideEffectAuthOnUntrusted('shell', shellArgs, {
      store,
      sessionId: 's2',
      pairedReemitDenied: true,
    });
    assert.ok(sideDeny);
    assert.match(sideDeny!, /denySideEffectAuthOnUntrusted/);

    const actions: ProposedAction[] = [
      { type: 'tool', name: 'write_file', args: writeArgs },
      { type: 'tool', name: 'shell', args: shellArgs },
    ];
    const guarded = actionGuard(planFrom(event.trustedPlan.tools), actions, {
      source: 'mcp_result',
      SourceTrust: 'mcp_result',
      egressReplication: { store, sessionId: 's2' },
      // shell-class policy also trips for untrusted — either reason is fine for DENY
    });
    assert.equal(guarded.allowed.length, 0);
    assert.ok(guarded.denied.length >= 2);
    assert.ok(
      guarded.denied.some((d) => /denyUntrustedVerbatimReemit|arg-content|shell_class/i.test(d.reason)),
    );
    assert.ok(
      guarded.denied.some((d) =>
        /denySideEffectAuthOnUntrusted|denyUntrustedVerbatimReemit|shell_class/i.test(d.reason),
      ),
    );
  });

  it('SR2: benign workbook without note echo → ALLOW on reemit bind', () => {
    const f = fix('sr2-benign-workbook-allow');
    const event = f.event as {
      ingress: { digestToken: string };
      trustedPlan: { tools: string[] };
    };
    const digest = event.ingress.digestToken;
    const store = new UntrustedIngressDigestStore();
    store.record('s2b', {
      digestToken: digest,
      source: 'mcp_result',
      sourceTrust: 'connector_untrusted',
      text: digest,
    });
    const args = {
      path: 'workbook/out.csv',
      content: 'col_a,col_b\n1,2\n',
    };
    assert.equal(
      denyUntrustedVerbatimReemit('write_file', args, { store, sessionId: 's2b' }),
      null,
    );
  });
});

describe('SelfReplicatingPI SR3 — Slack multi-hop cumulative digest', () => {
  it('re-post of prior untrusted hop → DENY', () => {
    const f = fix('sr3-slack-multihop-repost-deny');
    const event = f.event as {
      ingressHops: Array<{ digestToken: string; source: string; sourceTrust: string; role: string }>;
      cumulativeDigestSet: string[];
      proposedAction: { name: string; args: Record<string, string> };
      trustedPlan: { tools: string[] };
    };
    const store = new UntrustedIngressDigestStore();
    for (const hop of event.ingressHops) {
      const stamp = stampConnectorProvenance(hop.source, { sourceTrust: hop.sourceTrust });
      store.record('slack1', {
        digestToken: hop.digestToken,
        source: stamp.source,
        sourceTrust: stamp.sourceTrust,
        text: hop.digestToken,
        role: hop.role,
      });
    }
    for (const t of event.cumulativeDigestSet) {
      assert.equal(store.hasDigest('slack1', t), true);
    }
    const echoTok = event.proposedAction.args.echoDigestToken;
    const body = `repost ${echoTok} to shared channel`;
    const deny = denyUntrustedVerbatimReemit('slack_post', { body, channel: '#ops' }, {
      store,
      sessionId: 'slack1',
    });
    assert.ok(deny);
    assert.match(deny!, /denyUntrustedVerbatimReemit/);

    const guarded = actionGuard(
      planFrom(event.trustedPlan.tools),
      [{ type: 'tool', name: 'slack_post', args: { body, channel: '#ops' } }],
      { source: 'slack_equivalent', egressReplication: { store, sessionId: 'slack1' } },
    );
    assert.equal(guarded.allowed.length, 0);
  });

  it('digest-to-inbox without raw re-post → ALLOW', () => {
    const f = fix('sr3-slack-digest-to-inbox-allow');
    const event = f.event as {
      ingressHops: Array<{ digestToken: string; source: string; sourceTrust: string }>;
      trustedPlan: { tools: string[] };
    };
    const store = new UntrustedIngressDigestStore();
    for (const hop of event.ingressHops) {
      store.record('slack2', {
        digestToken: hop.digestToken,
        source: 'slack_equivalent',
        sourceTrust: 'connector_untrusted',
        text: hop.digestToken,
      });
    }
    const body = 'Summary: three ledger rows looked normal; no action needed.';
    assert.equal(
      denyUntrustedVerbatimReemit('send_email', { to: 'me@example.test', body }, {
        store,
        sessionId: 'slack2',
      }),
      null,
    );
  });
});

describe('SelfReplicatingPI SR4 — dual-objective bar', () => {
  it('goal+replication echo → worm DENY; goal-only does not require worm trip', () => {
    const f = fix('sr4-dual-bar-goal-only-vs-goal-plus-replication');
    const event = f.event as {
      goalOnly: {
        ingress: { digestToken: string };
        proposedAction: { name: string };
        expect: { wormTrip: boolean };
      };
      goalPlusReplication: {
        ingress: { digestToken: string };
        proposedAction: { name: string; args: Record<string, string> };
        expect: { wormTrip: boolean };
      };
    };

    // Goal-only: no body echo → worm helper does not trip
    const store = new UntrustedIngressDigestStore();
    store.record('g4', {
      digestToken: event.goalOnly.ingress.digestToken,
      source: 'email',
      sourceTrust: 'connector_untrusted',
      text: event.goalOnly.ingress.digestToken,
    });
    assert.equal(
      denyEgressReplicationBind('transfer_funds', { to: 'attacker', amount: 'remaining' }, {
        store,
        sessionId: 'g4',
      }),
      null,
      'goal-only must not require new SelfReplicatingPI trip',
    );
    assert.equal(event.goalOnly.expect.wormTrip, false);

    // Goal+replication: echo → DENY
    const store2 = new UntrustedIngressDigestStore();
    const dig = event.goalPlusReplication.ingress.digestToken;
    store2.record('g4b', {
      digestToken: dig,
      source: 'email',
      sourceTrust: 'connector_untrusted',
      text: dig,
    });
    const body = `please redistribute ${dig}`;
    const deny = denyUntrustedVerbatimReemit('send_email', { body }, {
      store: store2,
      sessionId: 'g4b',
    });
    assert.ok(deny);
    assert.equal(event.goalPlusReplication.expect.wormTrip, true);
  });
});

describe('SelfReplicatingPI SR5 — EP/PB/CT pair ablations (no re-land)', () => {
  it('documents orthogonal trips; EP+worm compose trips reemit bind', () => {
    const f = fix('sr5-orthogonal-ep-pb-ct-pair-ablations');
    const event = f.event as {
      vsEP: { expect: { selfReplicatingPI: boolean; trip: string } };
      vsPB: { expect: { selfReplicatingPI: boolean } };
      vsCT: { expect: { selfReplicatingPI: boolean } };
      composeEPplusWorm: { expect: { tripBoth: string[] } };
    };
    assert.equal(event.vsEP.expect.selfReplicatingPI, false);
    assert.equal(event.vsPB.expect.selfReplicatingPI, false);
    assert.equal(event.vsCT.expect.selfReplicatingPI, false);
    assert.deepEqual(event.composeEPplusWorm.expect.tripBoth, ['EP', 'SelfReplicatingPI']);

    // Compose EP+worm: plant that also demands public re-emit → SelfReplicatingPI bind trips
    const store = new UntrustedIngressDigestStore();
    store.record('epw', {
      digestToken: 'INGEST_DIGEST_EP_WORM',
      source: 'file',
      sourceTrust: 'connector_untrusted',
      text: 'INGEST_DIGEST_EP_WORM',
    });
    const deny = denyUntrustedVerbatimReemit(
      'send_email',
      { body: 'reemit INGEST_DIGEST_EP_WORM publicly' },
      { store, sessionId: 'epw' },
    );
    assert.ok(deny, 'EP+worm compose must trip SelfReplicatingPI reemit bind');
  });
});

describe('SelfReplicatingPI F1/R1 — pack honesty', () => {
  it('F1: shapes-only n>=5 SR1–SR5; pack sha256 matches acceptance; no live worm markers', () => {
    const f = fix('f1-r1-honesty-regression-notes');
    const bars = new Set(
      pack.fixtures.map((x) => String(x.bar)).filter((b) => /^SR[1-5]$/.test(b)),
    );
    assert.ok(bars.has('SR1') && bars.has('SR2') && bars.has('SR3') && bars.has('SR4') && bars.has('SR5'));
    assert.ok(pack.fixtures.length >= 5);
    assert.equal(pack._meta?.shapesOnly, true);
    assert.equal(pack._meta?.noLivePoC, true);

    const raw = readFileSync(fixturePath, 'utf8');
    const sha = createHash('sha256').update(raw).digest('hex');
    assert.equal(
      sha,
      '621e98a3a345508f57fb9e4bb13e1ef7b5a5dbab5e0f354a7fdf8a8f019bc2aa',
    );

    // No OpenAI report payload paste markers
    assert.equal(/alignment\.openai\.com\/.*payload/i.test(raw), false);
    const forbidden = (f.event as { forbidden: string[] }).forbidden;
    assert.ok(forbidden.includes('live_worm_payload_text'));
  });

  it('HITL / user SourceTrust clears reemit bind', () => {
    const store = new UntrustedIngressDigestStore();
    store.record('hitl', {
      digestToken: 'INGEST_DIGEST_EMAIL_SR1',
      source: 'email',
      sourceTrust: 'connector_untrusted',
      text: 'INGEST_DIGEST_EMAIL_SR1',
    });
    assert.equal(
      denyUntrustedVerbatimReemit(
        'send_email',
        { body: 'quote INGEST_DIGEST_EMAIL_SR1' },
        { store, sessionId: 'hitl', SourceTrust: 'user' },
      ),
      null,
    );
  });

  it('collectReemitContentArgs picks body/message/content', () => {
    const c = collectReemitContentArgs({
      to: 'a@b.c',
      body: 'hello',
      message: 'm',
      other: 1,
    });
    assert.equal(c.length, 2);
  });
});
