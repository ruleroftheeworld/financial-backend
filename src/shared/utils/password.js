/**
 * ─────────────────────────────────────────────────────────────
 * PASSWORD HASHING MODULE (Argon2id)
 * ─────────────────────────────────────────────────────────────
 *
 * Single point of responsibility for password hashing and
 * verification. Uses Argon2id with OWASP-recommended parameters.
 *
 * Argon2id advantages over bcrypt:
 *   - Memory-hard: resistant to GPU/ASIC attacks
 *   - Configurable memory/time/parallelism
 *   - Constant-time comparison built-in
 *   - Winner of the Password Hashing Competition
 *
 * ⚠️  No other module should hash or compare passwords directly.
 * ─────────────────────────────────────────────────────────────
 */
import argon2 from 'argon2';
import { hashing } from '../config/index.js';

/**
 * Hash a plaintext password using Argon2id.
 *
 * @param {string} password - Plaintext password
 * @returns {Promise<string>} Argon2id hash string
 */
export async function hashPassword(password) {
  return argon2.hash(password, {
    type:        argon2.argon2id,
    memoryCost:  hashing.memoryCost,
    timeCost:    hashing.timeCost,
    parallelism: hashing.parallelism,
    hashLength:  hashing.hashLength,
  });
}

/**
 * Verify a password against an Argon2id hash.
 * Uses constant-time comparison internally.
 *
 * @param {string} hash     - Stored Argon2id hash
 * @param {string} password - Plaintext password to verify
 * @returns {Promise<boolean>} True if password matches
 */
export async function verifyPassword(hash, password) {
  try {
    return await argon2.verify(hash, password);
  } catch {
    // argon2.verify throws on malformed hashes — treat as no-match
    return false;
  }
}

/**
 * Perform a dummy hash to prevent timing-based user enumeration.
 * Call this when the user does not exist so the response time
 * is indistinguishable from a real password comparison.
 *
 * @param {string} password - Plaintext password (hashed then discarded)
 */
export async function dummyVerify(password) {
  // Hash and discard — just burns CPU time
  await argon2.hash(password, {
    type:        argon2.argon2id,
    memoryCost:  hashing.memoryCost,
    timeCost:    hashing.timeCost,
    parallelism: hashing.parallelism,
    hashLength:  hashing.hashLength,
  });
}
