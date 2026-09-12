import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { join } from 'node:path';
import { prepareCompatTokenizer } from '../src/scanner/classifier-piguard.js';

describe('DL-011d D1 follow-on: tokenizer.compat never writes PIGUARD_DIR', () => {
  it('reuses existing compat in dir — no write', () => {
    const writes: string[] = [];
    const dir = '/ro/models/piguard-onnx';
    const r = prepareCompatTokenizer(dir, {
      existsSync: (p) => p === join(dir, 'tokenizer.compat.json'),
      writeFileSync: (p) => {
        writes.push(String(p));
      },
    });
    assert.equal(r.path, join(dir, 'tokenizer.compat.json'));
    assert.equal(r.wrote, false);
    assert.deepEqual(writes, []);
  });

  it('missing compat -> write only under tmp, never under dir', () => {
    const writes: string[] = [];
    const dir = '/ro/models/piguard-onnx';
    const tmp = '/tmp';
    const official = join(dir, 'tokenizer.json');
    const r = prepareCompatTokenizer(dir, {
      existsSync: (p) => p === official,
      readFileSync: () => JSON.stringify({
        pre_tokenizer: { type: 'Metaspace', prepend_scheme: 'always', split: true, replacement: '▁' },
      }),
      writeFileSync: (p) => {
        writes.push(String(p));
      },
      tmpdir: () => tmp,
    });
    assert.equal(r.path, join(tmp, 'sovguard-piguard-tokenizer.compat.json'));
    assert.equal(r.wrote, true);
    assert.deepEqual(writes, [join(tmp, 'sovguard-piguard-tokenizer.compat.json')]);
    assert.equal(writes.some((w) => w.startsWith(dir)), false);
  });

  it('tmp compat already present -> no second write', () => {
    const writes: string[] = [];
    const dir = '/ro/models/piguard-onnx';
    const tmp = '/tmp';
    const dest = join(tmp, 'sovguard-piguard-tokenizer.compat.json');
    const r = prepareCompatTokenizer(dir, {
      existsSync: (p) => p === dest || p === join(dir, 'tokenizer.json'),
      readFileSync: () => '{}',
      writeFileSync: (p) => {
        writes.push(String(p));
      },
      tmpdir: () => tmp,
    });
    assert.equal(r.path, dest);
    assert.equal(r.wrote, false);
    assert.deepEqual(writes, []);
  });
});
