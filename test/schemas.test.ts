import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ScanFileContentBody } from '../src/schemas.js';

describe('ScanFileContentBody.context', () => {
  it('accepts an optional context object', () => {
    const parsed = ScanFileContentBody.parse({
      content: 'aGk=', mimeType: 'text/plain',
      context: { path: '.git/hooks/pre-commit', executes_on_host: true, source: 'other_agent' },
    });
    assert.equal(parsed.context?.path, '.git/hooks/pre-commit');
    assert.equal(parsed.context?.executes_on_host, true);
  });
  it('accepts a body with no context', () => {
    const parsed = ScanFileContentBody.parse({ content: 'aGk=', mimeType: 'text/plain' });
    assert.equal(parsed.context, undefined);
  });
  it('rejects a non-string path', () => {
    assert.throws(() => ScanFileContentBody.parse({
      content: 'aGk=', mimeType: 'text/plain', context: { path: 123 },
    }));
  });
});
