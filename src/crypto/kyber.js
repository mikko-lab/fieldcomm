/**
 * kyber.js — Post-quantum key exchange
 * ML-KEM-768 (NIST FIPS 203) + AES-256-GCM
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';

export function generateKeyPair() {
  const seed = randomBytes(64);
  const { publicKey, secretKey } = ml_kem768.keygen(seed);
  return { publicKey, secretKey };
}

export function encapsulate(recipientPublicKey) {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(recipientPublicKey);
  return { cipherText, sharedSecret };
}

export function decapsulate(cipherText, secretKey) {
  return ml_kem768.decapsulate(cipherText, secretKey);
}

export function encryptPayload(plaintext, sharedSecret) {
  const nonce = randomBytes(12);
  const key = Buffer.from(sharedSecret.slice(0, 32));
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 tavua
  return { encrypted, nonce, tag };
}

export function decryptPayload(ciphertext, nonce, tag, sharedSecret) {
  const key = Buffer.from(sharedSecret.slice(0, 32));
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
