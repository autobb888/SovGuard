/**
 * DL-002 acceptance: Unicode normalize-to-fixed-point on untrusted ingress.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  normalizeToFixedPoint,
  shouldEscalateUnicodeSignals,
  stripBidiOverrides,
} from '../src/scanner/unicode-fixed-point.js';
import { normalizeStrip, regexScan } from '../src/scanner/regex.js';
import { scanContext } from '../src/scanner/context.js';
import { SovGuardEngine } from '../src/index.js';
import { handleWrapRoute } from '../src/wrap-route.js';
import { SessionScorer } from '../src/scanner/session-scorer.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtures = JSON.parse(
  readFileSync(join(__dirname, '../pentest/payloads/dl002-unicode.json'), 'utf8'),
) as {
  fixtures: Array<Record<string, unknown>>;
};

function fixture(id: string) {
  const f = fixtures.fixtures.find((x) => x.id === id);
  assert.ok(f, `missing fixture ${id}`);
  return f;
}

describe('DL-002 normalizeToFixedPoint', () => {
  it('Tags-encoded ignore/call tool with benign visible → decode + detect', async () => {
    const f = fixture('dl002-tags-peer') as { raw: string; visible: string };
    const fp = normalizeToFixedPoint(f.raw);
    assert.ok(fp.iters >= 1 || fp.signals.includes('unicode_tag'));
    assert.match(fp.text, /ignore previous|send_email|attacker@evil\.test/i);
    const layer = regexScan(f.raw);
    assert.ok(
      layer.score >= 0.3 ||
        layer.flags.some((x) => /unicode_tag|invisible_payload|stego_reassembly|ignore/i.test(x)),
      `expected detection, flags=${layer.flags.join(',')}`,
    );
    // visible-only should not carry the hidden keywords
    assert.ok(!/send_email|attacker@evil/i.test(f.visible));
  });

  it('nested \\u{Tag} escapes need fixed-point (iter≥2 / stegoReassembly)', () => {
    const f = fixture('dl002-nested-escape-tags') as { raw: string };
    const once = normalizeStrip(f.raw);
    // One strip leaves escapes or tags unresolved for keyword match
    const onceFpLite = once;
    const fp = normalizeToFixedPoint(f.raw);
    assert.match(fp.text, /ignore previous instructions/i);
    assert.ok(
      fp.stegoReassembly || fp.iters >= 2 || fp.signals.includes('unicode_escape'),
      `expected multi-pass signals, got iters=${fp.iters} signals=${fp.signals}`,
    );
    assert.ok(shouldEscalateUnicodeSignals(fp));
    const layer = regexScan(f.raw);
    assert.ok(layer.score >= 0.3 || layer.flags.length > 0);
    // Document: one-shot strip alone is insufficient for keyword
    assert.ok(
      !/ignore previous instructions/i.test(onceFpLite) || onceFpLite.includes('\\u'),
      'one-shot strip should not fully yield plaintext for this fixture',
    );
  });

  it('bidi + ZW mid-instruction → strip + match', () => {
    const f = fixture('dl002-bidi-zw') as { raw: string };
    assert.ok(/[\u202A-\u202E\u2066-\u2069]/.test(f.raw) || f.raw.includes('\u202E'));
    const stripped = stripBidiOverrides(f.raw);
    assert.ok(!/[\u202A-\u202E\u2066-\u2069]/.test(stripped));
    const fp = normalizeToFixedPoint(f.raw);
    assert.ok(fp.signals.includes('bidi') || fp.signals.includes('zw'));
    assert.match(fp.text.replace(/\s+/g, ' '), /ignore previous instructions.*send_email/i);
    assert.ok(shouldEscalateUnicodeSignals(fp));
  });

  it('homoglyph + ZW mid-word still match after fold', () => {
    const f = fixture('dl002-homoglyph-zw') as {
      cases: Array<{ id: string; raw: string }>;
    };
    for (const c of f.cases) {
      const fp = normalizeToFixedPoint(c.raw);
      assert.match(
        fp.text.toLowerCase(),
        /ignore previous instructions/,
        `case ${c.id}: ${JSON.stringify(fp.text)}`,
      );
    }
  });

  it('international benign text not escalated solely for NFKC', () => {
    const f = fixture('dl002-fp-international') as { raw: string };
    const fp = normalizeToFixedPoint(f.raw);
    assert.equal(shouldEscalateUnicodeSignals(fp), false);
    const layer = regexScan(f.raw);
    assert.ok(layer.score < 0.3, `FP risk: score=${layer.score} flags=${layer.flags}`);
  });
});

describe('DL-002 scanContext/wrap other_agent Tags', () => {
  it('scanContext source:other_agent on Tags peer → suspicious or unicode signals', async () => {
    const f = fixture('dl002-tags-peer') as { raw: string };
    const res = await scanContext(f.raw, { source: 'other_agent', policy: 'quarantine' });
    assert.ok(
      !res.scan.safe ||
        res.scan.classification !== 'safe' ||
        res.scan.flags.some((x) => /unicode|stego|invisible|ignore/i.test(x)),
      `expected flag/contain, got cls=${res.scan.classification} action=${res.action}`,
    );
    assert.ok(res.flagged || res.action !== 'allow' || res.scan.score >= 0.3);
  });

  it('wrap source:other_agent runs same pipeline', async () => {
    const engine = new SovGuardEngine();
    const scorer = new SessionScorer();
    const f = fixture('dl002-tags-peer') as { raw: string };
    const out = await handleWrapRoute(engine, scorer, {
      text: f.raw,
      source: 'other_agent',
      policy: 'quarantine',
    });
    assert.ok(out.scan);
    assert.ok(
      out.action === 'quarantine' ||
        out.action === 'strip' ||
        out.action === 'block' ||
        out.scan.score >= 0.3 ||
        out.scan.flags.length > 0,
    );
  });
});
