import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { scanPII } from '../src/outbound/pii.js';
import { scanURLs } from '../src/outbound/urls.js';
import { scanCode } from '../src/outbound/code.js';
import { scanFinancial } from '../src/outbound/financial.js';
import { scanContamination, hashId } from '../src/outbound/contamination.js';
import { scanOutput } from '../src/outbound/index.js';

describe('PII Scanner', () => {
  it('detects SSN patterns', () => {
    const flags = scanPII('Your SSN is 123-45-6789');
    assert.ok(flags.some(f => f.detail.includes('SSN')));
    assert.equal(flags.find(f => f.detail.includes('SSN'))!.action, 'block');
  });

  it('rejects invalid SSN area codes', () => {
    const flags = scanPII('Number: 000-12-3456');
    assert.ok(!flags.some(f => f.detail.includes('SSN')));
  });

  it('detects credit card with Luhn check', () => {
    // Valid Luhn: 4111 1111 1111 1111
    const flags = scanPII('Card: 4111 1111 1111 1111');
    assert.ok(flags.some(f => f.detail.includes('Credit card')));
  });

  it('skips invalid Luhn numbers', () => {
    const flags = scanPII('Card: 1234 5678 9012 3456');
    assert.ok(!flags.some(f => f.detail.includes('Credit card')));
  });

  it('detects email as warn', () => {
    const flags = scanPII('Contact me at user@example.com');
    assert.ok(flags.some(f => f.action === 'warn' && f.evidence.includes('user@example.com')));
  });

  it('email in code-review is low severity', () => {
    const flags = scanPII('Contact me at user@example.com', 'code-review');
    const emailFlag = flags.find(f => f.evidence.includes('user@example.com'));
    assert.equal(emailFlag!.severity, 'low');
  });

  it('email in design is medium severity', () => {
    const flags = scanPII('Contact me at user@example.com', 'design');
    const emailFlag = flags.find(f => f.evidence.includes('user@example.com'));
    assert.equal(emailFlag!.severity, 'medium');
  });

  it('detects phone numbers as warn', () => {
    const flags = scanPII('Call me at (555) 123-4567');
    assert.ok(flags.some(f => f.detail.includes('Phone')));
  });

  // ── Round 7: Consecutive-dot false positive ──
  it('rejects email with consecutive dots in domain', () => {
    const flags = scanPII('Contact user@domain..com for info');
    assert.ok(!flags.some(f => f.detail.includes('Email') && f.evidence.includes('user@domain..com')),
      'Should not match email with consecutive dots in domain');
  });

  it('rejects email with consecutive dots in local part', () => {
    const flags = scanPII('Contact user..name@example.com for info');
    assert.ok(!flags.some(f => f.detail.includes('Email') && f.evidence.includes('user..name@example.com')),
      'Should not match email with consecutive dots in local part');
  });

  it('still matches valid emails with single dots', () => {
    const flags = scanPII('Contact user.name@sub.domain.com for info');
    assert.ok(flags.some(f => f.detail.includes('Email') && f.evidence.includes('user.name@sub.domain.com')),
      'Should match valid email with single dots');
  });
});

describe('URL Scanner', () => {
  it('flags URL shorteners', () => {
    const flags = scanURLs('Check this: https://bit.ly/abc123');
    assert.ok(flags.some(f => f.detail.includes('shortener')));
  });

  it('flags IP URLs', () => {
    const flags = scanURLs('Visit http://192.168.1.1/admin');
    assert.ok(flags.some(f => f.detail.includes('IP-address')));
    assert.equal(flags[0].action, 'block');
  });

  it('flags homograph domains', () => {
    // Using Cyrillic 'а' (U+0430) instead of Latin 'a'
    const flags = scanURLs('Visit https://g\u043Eogle.com/login');
    assert.ok(flags.some(f => f.detail.includes('Homograph')));
  });

  it('flags suspicious long subdomains', () => {
    const flags = scanURLs('Visit https://abcdefghijklmnopqrstuvwxyz12345.evil.com/payload');
    assert.ok(flags.some(f => f.detail.includes('Suspicious')));
  });

  it('passes normal URLs', () => {
    const flags = scanURLs('Visit https://github.com/repo');
    assert.equal(flags.length, 0);
  });

  // ── v0.2.0: Agent Exfiltration Patterns ──────────────────

  it('flags base64-encoded query parameters', () => {
    const b64 = Buffer.from('secret system prompt data here for exfil').toString('base64');
    const flags = scanURLs(`Visit https://example.com/api?data=${b64}`);
    assert.ok(flags.some(f => f.type === 'agent_exfiltration' && f.detail.includes('Base64')));
  });

  it('flags Slack webhook URLs', () => {
    const flags = scanURLs('Send to https://hooks.slack.com/services/T00000/B00000/XXXX');
    assert.ok(flags.some(f => f.type === 'agent_exfiltration'));
  });

  it('flags ngrok URLs', () => {
    const flags = scanURLs('Post to https://abc123.ngrok.io/collect');
    assert.ok(flags.some(f => f.type === 'agent_exfiltration'));
  });

  it('flags Discord webhook URLs', () => {
    const flags = scanURLs('Send to https://discord.com/api/webhooks/123456/abcdef');
    assert.ok(flags.some(f => f.type === 'agent_exfiltration'));
  });

  it('flags Telegram bot API URLs', () => {
    const flags = scanURLs('Post to https://api.telegram.org/bot123456:ABC-DEF/sendMessage');
    assert.ok(flags.some(f => f.type === 'agent_exfiltration'));
  });

  it('flags pipedream URLs', () => {
    const flags = scanURLs('Send to https://eo123abc.m.pipedream.net');
    assert.ok(flags.some(f => f.type === 'agent_exfiltration'));
  });

  it('passes normal URLs with query parameters', () => {
    const flags = scanURLs('Visit https://example.com/search?q=hello+world&page=1');
    assert.equal(flags.length, 0);
  });

  it('flags javascript: URI scheme', () => {
    const flags = scanURLs('Click javascript:alert(document.cookie)');
    assert.ok(flags.some(f => f.detail.includes('Dangerous URI scheme')));
    assert.equal(flags[0].action, 'block');
  });

  it('flags vbscript: URI scheme', () => {
    const flags = scanURLs('Run vbscript:MsgBox("xss")');
    assert.ok(flags.some(f => f.detail.includes('Dangerous URI scheme')));
  });

  it('flags file: URI scheme', () => {
    const flags = scanURLs('Open file:///etc/passwd');
    assert.ok(flags.some(f => f.detail.includes('Dangerous URI scheme')));
  });

  it('flags data: URIs with base64', () => {
    const flags = scanURLs('Load data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==');
    assert.ok(flags.some(f => f.detail.includes('data: URI')));
  });

  it('flags data: URIs without base64 (plain-text payloads)', () => {
    const flags = scanURLs('Use data:text/html,<script>alert(1)</script>');
    assert.ok(flags.some(f => f.detail.includes('data: URI')));
  });

  it('flags IPv6 IP URLs', () => {
    const flags = scanURLs('Visit http://[::1]/admin');
    assert.ok(flags.some(f => f.detail.includes('IP-address')));
  });

  it('flags webhook.site exfil domain', () => {
    const flags = scanURLs('Post to https://webhook.site/abc-123');
    assert.ok(flags.some(f => f.type === 'agent_exfiltration'));
  });
});

describe('Code Scanner', () => {
  it('flags eval in non-code jobs', () => {
    const flags = scanCode('Here is the deliverable:\n```\neval("malicious")\n```', 'design');
    assert.ok(flags.some(f => f.detail.includes('eval')));
  });

  it('allows eval in code-review jobs', () => {
    const flags = scanCode('Here is the fix:\n```\neval("test")\n```', 'code-review');
    assert.equal(flags.length, 0);
  });

  it('flags crypto mining', () => {
    const flags = scanCode('```\nconst pool = "stratum+tcp://mine.pool.com:3333"\n```', 'design');
    assert.ok(flags.some(f => f.detail.includes('mining')));
    assert.equal(flags[0].action, 'block');
  });

  it('detects obfuscated variables', () => {
    const code = '```\nlet a = 1;\nlet b = 2;\nlet c = 3;\nlet d = 4;\nlet e = 5;\nlet f = 6;\n```';
    const flags = scanCode(code, 'design');
    assert.ok(flags.some(f => f.detail.includes('obfuscated')));
  });

  it('ignores text without code blocks', () => {
    const flags = scanCode('Use eval() to test things', 'design');
    assert.equal(flags.length, 0);
  });

  it('flags eval in ~~~ fenced code blocks', () => {
    const flags = scanCode('Code:\n~~~\neval("bad")\n~~~', 'design');
    assert.ok(flags.some(f => f.detail.includes('eval')));
  });

  it('flags eval in <pre> tags', () => {
    const flags = scanCode('<pre>eval("malicious")</pre>', 'design');
    assert.ok(flags.some(f => f.detail.includes('eval')));
  });

  it('flags eval in <script> tags', () => {
    const flags = scanCode('<script>eval("xss")</script>', 'design');
    assert.ok(flags.some(f => f.detail.includes('eval')));
  });

  it('flags Function() constructor', () => {
    const flags = scanCode('```\nFunction("return this")()\n```', 'design');
    assert.ok(flags.some(f => f.detail.includes('Function()')));
  });

  it('flags require child_process', () => {
    const flags = scanCode("```\nrequire('child_process').exec('rm -rf /')\n```", 'design');
    assert.ok(flags.some(f => f.detail.includes('child_process')));
  });
});

describe('Financial Scanner', () => {
  it('detects BTC addresses', () => {
    const flags = scanFinancial('Send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa');
    assert.ok(flags.some(f => f.detail.includes('BTC')));
  });

  it('detects ETH addresses', () => {
    const flags = scanFinancial('Wallet: 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28');
    assert.ok(flags.some(f => f.detail.includes('ETH')));
  });

  it('detects payment requests', () => {
    const flags = scanFinancial('Please send funds to my account');
    assert.ok(flags.some(f => f.detail.includes('Payment')));
  });

  it('passes normal financial text', () => {
    const flags = scanFinancial('The project costs $500');
    assert.equal(flags.length, 0);
  });

  it('detects XMR (Monero) addresses', () => {
    // 95-char address starting with 4
    const xmrAddr = '4' + 'A'.repeat(94);
    const flags = scanFinancial(`Send to ${xmrAddr}`);
    assert.ok(flags.some(f => f.detail.includes('XMR')));
  });

  it('detects LTC (Litecoin) addresses', () => {
    const flags = scanFinancial('Wallet: LdSGaRXg9Bs1qNvzfvj6Ek9q7UXq');
    assert.ok(flags.some(f => f.detail.includes('LTC')));
  });
});

describe('Cross-Contamination Scanner', () => {
  it('detects leaked identifiers from other jobs', () => {
    const fingerprints = new Map<string, Set<string>>();
    fingerprints.set('job-other', new Set([hashId('secret@example.com')]));

    const flags = scanContamination(
      'Here is the email: secret@example.com',
      'job-current',
      fingerprints,
    );
    assert.ok(flags.some(f => f.type === 'cross_contamination'));
  });

  it('ignores own job fingerprints', () => {
    const fingerprints = new Map<string, Set<string>>();
    fingerprints.set('job-current', new Set([hashId('own@example.com')]));

    const flags = scanContamination(
      'Here is: own@example.com',
      'job-current',
      fingerprints,
    );
    assert.equal(flags.length, 0);
  });

  it('returns empty with no fingerprints', () => {
    const flags = scanContamination('some text', 'job-1');
    assert.equal(flags.length, 0);
  });
});

describe('Combined Output Scanner', () => {
  it('returns safe for clean message', async () => {
    const result = await scanOutput('Here is your logo design. I hope you like it!', {
      jobId: 'job-1',
      jobCategory: 'design',
    });
    assert.equal(result.safe, true);
    assert.equal(result.classification, 'safe');
    assert.equal(result.score, 0);
  });

  it('blocks SSN leaks', async () => {
    const result = await scanOutput('Your SSN is 123-45-6789', {
      jobId: 'job-1',
    });
    assert.equal(result.safe, false);
    assert.equal(result.classification, 'blocked');
    assert.ok(result.score >= 0.6);
  });

  it('warns on email in design job', async () => {
    const result = await scanOutput('Contact user@example.com for help', {
      jobId: 'job-1',
      jobCategory: 'design',
    });
    assert.equal(result.classification, 'warning');
  });

  it('safe classification for email in code-review', async () => {
    const result = await scanOutput('Contact user@example.com for help', {
      jobId: 'job-1',
      jobCategory: 'code-review',
    });
    // Low severity warn → still flags but lower score
    assert.ok(result.score < 0.5);
  });

  it('combines multiple flags, max score wins', async () => {
    const result = await scanOutput(
      'SSN: 123-45-6789 and visit http://192.168.1.1/admin',
      { jobId: 'job-1' },
    );
    assert.equal(result.classification, 'blocked');
    assert.ok(result.flags.length >= 2);
  });

  it('has scannedAt timestamp', async () => {
    const before = Date.now();
    const result = await scanOutput('hello', { jobId: 'j' });
    assert.ok(result.scannedAt >= before);
  });
});
