/**
 * J41 opt-in PII wrapper thin land — productization follow-on.
 * Pack: pentest/payloads/j41-optin-pii-wrapper.json (shapes only).
 * Detectors unchanged; default OFF; redactOutput host-callable only.
 * Not DLP / not deepset 80%. Escalate BLOCK. Soft stay soft.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanOutput } from '../src/outbound/index.js';
import {
  redactOutput,
  REDACT_PLACEHOLDERS,
} from '../src/outbound/redact-output.js';
import {
  J41_POLICY_PROFILES,
  J41_POLICY_DEFAULT_PER_FLAG,
  j41ProfileToActions,
  isJ41PolicyProfile,
} from '../src/outbound/j41-policy-profile.js';
import { scanProposedToolArgs } from '../src/delivery/action-guard.js';
import type { OutputFlag } from '../src/types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PACK = join(__dirname, '../pentest/payloads/j41-optin-pii-wrapper.json');
const EXPECT_SHA =
  '6d255a956abea5ef6a9135fa1a2d0241bd81e6a84b18005fd5bf39fa3cee57c4';

/** Well-known synthetic shapes only — no live credentials. */
const SSN_SHAPE = 'Your SSN is 123-45-6789';
const PAN_SHAPE = 'Card 4111 1111 1111 1111';
const AKIA_SHAPE = 'creds: AKIAIOSFODNN7EXAMPLE';
const SK_SHAPE = 'OPENAI=sk-abcdefghijklmnopqrstuvwxyz0123';
const GHP_SHAPE = 'token ghp_abcdefghijklmnopqrstuvwxyzABCDEF0123';
const ETH_SHAPE = 'pay 0x000000000000000000000000000000000000dead';
const CANARY = 'CANARY_J41_DP_TEST';

describe('J41 pack integrity (F1 shapes fence)', () => {
  it('mirrors scout pack sha256 n=8', () => {
    assert.ok(existsSync(PACK), `missing ${PACK}`);
    const buf = readFileSync(PACK);
    const sha = createHash('sha256').update(buf).digest('hex');
    assert.equal(sha, EXPECT_SHA);
    const meta = JSON.parse(buf.toString('utf8'))._meta;
    assert.equal(meta.n, 8);
    assert.equal(meta.optInOnly, true);
    assert.equal(meta.defaultOffForever, true);
    assert.equal(meta.postalHold, true);
  });
});

describe('J41-1 default OFF', () => {
  it('does not emit pii/secret/financial without dataProtection', () => {
    for (const text of [SSN_SHAPE, PAN_SHAPE, AKIA_SHAPE, ETH_SHAPE]) {
      const r = scanOutput(text, { jobId: 'j41' });
      assert.equal(
        r.flags.some((f) =>
          f.type === 'pii_detected' ||
          f.type === 'secret_leak' ||
          f.type === 'financial_manipulation',
        ),
        false,
        text,
      );
    }
  });
});

describe('J41-2…J41-5 opt-in ON', () => {
  it('J41-2 SSN → pii_detected critical block', () => {
    const r = scanOutput(SSN_SHAPE, { jobId: 'j41', dataProtection: true });
    const f = r.flags.find((x) => x.type === 'pii_detected');
    assert.ok(f);
    assert.equal(f!.severity, 'critical');
    assert.equal(f!.action, 'block');
  });

  it('J41-3 Luhn test PAN → pii_detected', () => {
    const r = scanOutput(PAN_SHAPE, { jobId: 'j41', dataProtection: true });
    assert.ok(r.flags.some((f) => f.type === 'pii_detected'));
  });

  it('J41-4 API key shapes → secret_leak with redacted evidence', () => {
    for (const text of [AKIA_SHAPE, SK_SHAPE, GHP_SHAPE]) {
      const r = scanOutput(text, { jobId: 'j41', dataProtection: true });
      const f = r.flags.find((x) => x.type === 'secret_leak');
      assert.ok(f, text);
      assert.equal(f!.evidence, '(redacted)');
    }
  });

  it('J41-5 wallet flags unless whitelisted', () => {
    const hit = scanOutput(ETH_SHAPE, { jobId: 'j41', dataProtection: true });
    assert.ok(hit.flags.some((f) => f.type === 'financial_manipulation'));
    const addr = '0x000000000000000000000000000000000000dead';
    const miss = scanOutput(ETH_SHAPE, {
      jobId: 'j41',
      dataProtection: true,
      whitelistedAddresses: new Set([addr]),
    });
    assert.equal(
      miss.flags.some((f) => f.type === 'financial_manipulation'),
      false,
    );
  });
});

describe('J41-6 KPI-C still on when DP OFF', () => {
  it('canary fires without dataProtection', () => {
    const r = scanOutput(`leak ${CANARY}`, {
      jobId: 'j41',
      canaryToken: CANARY,
    });
    assert.ok(r.flags.length >= 1);
  });
});

describe('J41-7 GhostSplice tool-arg orthogonal', () => {
  it('DENY secret in mcp_result args without dataProtection', () => {
    const scan = scanProposedToolArgs({
      body: AKIA_SHAPE,
    });
    assert.equal(scan.deny, true);
  });
});

describe('J41 profile enum (C)', () => {
  it('exposes flag|redact|block and maps to OutputFlag.action', () => {
    assert.deepEqual([...J41_POLICY_PROFILES], ['flag', 'redact', 'block']);
    assert.deepEqual(j41ProfileToActions('flag'), ['flag', 'warn']);
    assert.deepEqual(j41ProfileToActions('redact'), ['redact']);
    assert.deepEqual(j41ProfileToActions('block'), ['block']);
    assert.equal(J41_POLICY_DEFAULT_PER_FLAG, 'per_flag_actions');
    assert.equal(isJ41PolicyProfile('redact'), true);
    assert.equal(isJ41PolicyProfile('wrap'), false);
  });
});

describe('optional redactOutput (B) — host-callable only', () => {
  it('rewrites action:redact secret shapes to [REDACTED_KEY]', () => {
    const r = scanOutput(SK_SHAPE, { jobId: 'j41', dataProtection: true });
    assert.ok(r.flags.some((f) => f.action === 'redact'));
    const scrubbed = redactOutput(r.flags, SK_SHAPE);
    assert.ok(scrubbed.includes(REDACT_PLACEHOLDERS.key));
    assert.equal(scrubbed.includes('sk-abcdefghijklmnopqrstuvwxyz0123'), false);
  });

  it('rewrites concrete evidence when action is redact', () => {
    const flags: OutputFlag[] = [
      {
        type: 'pii_detected',
        severity: 'critical',
        detail: 'Credit card number detected in output',
        evidence: '4111 1111 1111 1111',
        action: 'redact',
      },
    ];
    const scrubbed = redactOutput(flags, PAN_SHAPE);
    assert.ok(scrubbed.includes(REDACT_PLACEHOLDERS.cc));
    assert.equal(scrubbed.includes('4111 1111 1111 1111'), false);
  });

  it('leaves warn/block spans alone', () => {
    const r = scanOutput(SSN_SHAPE, { jobId: 'j41', dataProtection: true });
    assert.ok(r.flags.some((f) => f.action === 'block'));
    const scrubbed = redactOutput(r.flags, SSN_SHAPE);
    assert.equal(scrubbed, SSN_SHAPE);
  });

  it('scanOutput does not auto-apply redact (behavior unchanged)', () => {
    const text = SK_SHAPE;
    const r = scanOutput(text, { jobId: 'j41', dataProtection: true });
    // Result carries flags only — original text is caller-owned; helper optional.
    assert.ok(r.flags.some((f) => f.action === 'redact'));
    assert.equal(redactOutput([], text), text);
  });
});

describe('J41 honesty fence', () => {
  it('does not infer dataProtection from omitted context', () => {
    const r = scanOutput(SSN_SHAPE, { jobId: 'j41' });
    assert.equal(r.flags.some((f) => f.type === 'pii_detected'), false);
  });
});
