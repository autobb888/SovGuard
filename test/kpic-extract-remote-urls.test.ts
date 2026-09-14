import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { extractRemoteUrls, flagUntrustedUrlEcho, actionGuard } from '../src/delivery/action-guard.js';

describe('KPI-C extractRemoteUrls expand', () => {
  it('keeps markdown image + img src', () => {
    const urls = extractRemoteUrls(
      '![x](https://cdn.attacker.test/b.gif) <img src="https://pixel.attacker.test/o.png">',
    );
    assert.ok(urls.some((u) => u.includes('cdn.attacker.test')));
    assert.ok(urls.some((u) => u.includes('pixel.attacker.test')));
  });

  it('extracts HTML anchor href', () => {
    const urls = extractRemoteUrls('<a href="https://click.attacker.test/r?x=1">View</a>');
    assert.ok(urls.some((u) => u.startsWith('https://click.attacker.test/r')));
  });

  it('extracts CSS url() with and without quotes', () => {
    const quoted = extractRemoteUrls("background:url('https://style.attacker.test/p.png?c=1')");
    const bare = extractRemoteUrls('background:url(https://style.attacker.test/p.png?c=2)');
    assert.ok(quoted.some((u) => u.includes('style.attacker.test')));
    assert.ok(bare.some((u) => u.includes('style.attacker.test')));
  });

  it('extracts link preload href', () => {
    const urls = extractRemoteUrls(
      '<link rel="preload" href="https://preload.attacker.test/x.js?c=1" as="script">',
    );
    assert.ok(urls.some((u) => u.includes('preload.attacker.test')));
  });

  it('extracts meta refresh URL case-insensitive', () => {
    const urls = extractRemoteUrls(
      '<meta http-equiv="refresh" content="0;url=https://go.attacker.test/m?c=1">',
    );
    assert.ok(urls.some((u) => u.includes('go.attacker.test')));
    const flipped = extractRemoteUrls(
      '<META HTTP-EQUIV="REFRESH" content="0; URL=https://go.attacker.test/m?c=2">',
    );
    assert.ok(flipped.some((u) => u.includes('go.attacker.test')));
  });

  it('flagUntrustedUrlEcho hits new shapes when echoed and not allowlisted', () => {
    const introduced = ['https://click.attacker.test/r?x=1'];
    const hits = flagUntrustedUrlEcho(
      '<a href="https://click.attacker.test/r?x=1">x</a>',
      { urls: [] },
      introduced,
    );
    assert.ok(hits.length >= 1);
  });

  it('allowlist regression: allowlisted docs image is not an echo hit', () => {
    const hits = flagUntrustedUrlEcho(
      '<img src="https://docs.sovguard.example/assets/diagram.png">',
      { urls: ['https://docs.sovguard.example'] },
      ['https://docs.sovguard.example/assets/diagram.png'],
    );
    assert.equal(hits.length, 0);
  });

  it('does not expand trusted-plan allowlist via extracted URLs', () => {
    const decision = actionGuard(
      { urls: ['https://docs.sovguard.example'] },
      [{ type: 'fetch', url: 'https://click.attacker.test/r?x=1' }],
    );
    assert.equal(decision.allowed.length, 0);
    assert.equal(decision.denied.length, 1);
  });
});
