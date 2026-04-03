/**
 * ─────────────────────────────────────────────────────────────
 * ENCRYPTION MODULE (AES-256-GCM)
 * ─────────────────────────────────────────────────────────────
 *
 * Provides authenticated encryption/decryption for sensitive
 * data (e.g., TOTP secrets).
 *
 * Security properties:
 *   - AES-256-GCM (authenticated encryption with associated data)
 *   - Random IV per encryption operation
 *   - Authentication tag validation on decryption
 *   - Key versioning for rotation support
 *
 * ⚠️  Keys are loaded exclusively from the config module.
 * ─────────────────────────────────────────────────────────────
 */
import crypto from 'crypto';
import { encryption } from '../config/index.js';

const { algorithm, ivLength } = encryption;

/**
 * Encrypt plaintext using AES-256-GCM.
 *
 * @param {string} text    - Plaintext to encrypt
 * @param {number} version - Key version to use
 * @returns {string} Format: iv:authTag:ciphertext (all hex)
 */
export const encrypt = (text, version) => {
  if (!version) throw new Error('Encryption requires a valid key version');
  if (!text) return text;

  const key = encryption.getKey(version);
  const iv = crypto.randomBytes(ivLength);
  const cipher = crypto.createCipheriv(algorithm, key, iv);

  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag().toString('hex');

  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
};

/**
 * Decrypt ciphertext using AES-256-GCM.
 *
 * @param {string} encryptedText - Format: iv:authTag:ciphertext (all hex)
 * @param {number} version       - Key version to use
 * @returns {string} Decrypted plaintext
 */
export const decrypt = (encryptedText, version) => {
  if (!version) throw new Error('Decryption requires a valid key version');
  if (!encryptedText) return encryptedText;

  const parts = encryptedText.split(':');

  if (parts.length !== 3) {
    throw new Error('Invalid encrypted secret');
  }

  const [ivHex, authTagHex, contentHex] = parts;

  const key = encryption.getKey(version);
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');

  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(contentHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
};
