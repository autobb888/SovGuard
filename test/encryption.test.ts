import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'crypto';
import { encryptPayload, decryptPayload } from '../src/crypto/encryption.js';

describe('AES-256-GCM Payload Encryption', () => {
  const key = randomBytes(32);

  it('should round-trip encrypt and decrypt', () => {
    const plaintext = '{"text":"Hello world"}';
    const encrypted = encryptPayload(plaintext, key);
    const decrypted = decryptPayload(encrypted.iv, encrypted.tag, encrypted.data, key);
    assert.equal(decrypted, plaintext);
  });

  it('should fail with wrong key', () => {
    const encrypted = encryptPayload('secret', key);
    const wrongKey = randomBytes(32);
    assert.throws(() => {
      decryptPayload(encrypted.iv, encrypted.tag, encrypted.data, wrongKey);
    });
  });

  it('should fail with tampered data', () => {
    const encrypted = encryptPayload('secret', key);
    const tamperedData = Buffer.from(encrypted.data, 'base64');
    tamperedData[0] ^= 0xff;
    assert.throws(() => {
      decryptPayload(encrypted.iv, encrypted.tag, tamperedData.toString('base64'), key);
    });
  });

  it('should fail with tampered tag', () => {
    const encrypted = encryptPayload('secret', key);
    const tamperedTag = Buffer.from(encrypted.tag, 'base64');
    tamperedTag[0] ^= 0xff;
    assert.throws(() => {
      decryptPayload(encrypted.iv, tamperedTag.toString('base64'), encrypted.data, key);
    });
  });

  it('should produce different IVs for same plaintext', () => {
    const a = encryptPayload('same input', key);
    const b = encryptPayload('same input', key);
    assert.notEqual(a.iv, b.iv);
    assert.notEqual(a.data, b.data);
    // Both should decrypt to same value
    assert.equal(decryptPayload(a.iv, a.tag, a.data, key), 'same input');
    assert.equal(decryptPayload(b.iv, b.tag, b.data, key), 'same input');
  });

  it('should handle empty string', () => {
    const encrypted = encryptPayload('', key);
    const decrypted = decryptPayload(encrypted.iv, encrypted.tag, encrypted.data, key);
    assert.equal(decrypted, '');
  });

  it('should handle large payload', () => {
    const large = 'x'.repeat(100_000);
    const encrypted = encryptPayload(large, key);
    const decrypted = decryptPayload(encrypted.iv, encrypted.tag, encrypted.data, key);
    assert.equal(decrypted, large);
  });

  it('should handle unicode', () => {
    const unicode = 'Hello \u{1F600} \u4F60\u597D \u043F\u0440\u0438\u0432\u0435\u0442';
    const encrypted = encryptPayload(unicode, key);
    const decrypted = decryptPayload(encrypted.iv, encrypted.tag, encrypted.data, key);
    assert.equal(decrypted, unicode);
  });
});
