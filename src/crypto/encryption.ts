/**
 * SovGuard — AES-256-GCM Payload Encryption
 * Defense-in-depth: encrypts request/response payloads so middleboxes can't read content.
 */

import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

const ALGO = 'aes-256-gcm';
const IV_BYTES = 12;

export interface EncryptedPayload {
  iv: string;   // base64
  tag: string;  // base64
  data: string; // base64
}

export function encryptPayload(plaintext: string, key: Buffer): EncryptedPayload {
  if (key.length !== 32) {
    throw new Error(`Invalid key size: expected 32 bytes, got ${key.length}`);
  }
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGO, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    data: encrypted.toString('base64'),
  };
}

export function decryptPayload(iv: string, tag: string, data: string, key: Buffer): string {
  if (key.length !== 32) {
    throw new Error(`Invalid key size: expected 32 bytes, got ${key.length}`);
  }
  const decipher = createDecipheriv(ALGO, key, Buffer.from(iv, 'base64'));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  const decrypted = Buffer.concat([decipher.update(Buffer.from(data, 'base64')), decipher.final()]);
  return decrypted.toString('utf8');
}
