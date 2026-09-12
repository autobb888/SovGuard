import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { join } from 'node:path';
import { resolveCompatTokenizer } from '../src/scanner/classifier-piguard.js';

describe('DL-011d D1.10 RO mount: never write PIGUARD_DIR', () => {
  it('reuses existing readable compat in dir', () => {
    const dir = '/ro/models/piguard-onnx';
    const r = resolveCompatTokenizer(dir, {
      existsSync: (p) => p === join(dir, 'tokenizer.compat.json'),
    });
    assert.equal(r.kind, 'file');
    if (r.kind === 'file') assert.equal(r.path, join(dir, 'tokenizer.compat.json'));
  });

  it('missing compat -> in-memory json, no write', () => {
    const writes: string[] = [];
    const dir = '/ro/models/piguard-onnx';
    const official = join(dir, 'tokenizer.json');
    const r = resolveCompatTokenizer(dir, {
      existsSync: (p) => p === official,
      readFileSync: () => JSON.stringify({
        pre_tokenizer: { type: 'Metaspace', prepend_scheme: 'always', split: true, replacement: '▁' },
      }),
    });
    assert.equal(r.kind, 'json');
    if (r.kind === 'json') {
      assert.match(r.json, /add_prefix_space/);
      assert.doesNotMatch(r.json, /prepend_scheme/);
    }
    assert.deepEqual(writes, []);
  });

  it('RO dir: writeFileSync throw still yields json (D1.10 / D1.11)', () => {
    const dir = '/ro/models/piguard-onnx';
    const official = join(dir, 'tokenizer.json');
    const r = resolveCompatTokenizer(dir, {
      existsSync: (p) => p === official,
      readFileSync: (p) => {
        if (String(p).endsWith('tokenizer.json')) {
          return '{"pre_tokenizer":{"type":"Metaspace","prepend_scheme":"always"}}';
        }
        throw new Error('EROFS');
      },
    });
    assert.equal(r.kind, 'json');
  });
});
