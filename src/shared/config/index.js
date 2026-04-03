/**
 * ─────────────────────────────────────────────────────────────
 * CENTRALIZED CONFIGURATION MODULE
 * ─────────────────────────────────────────────────────────────
 *
 * This is the SINGLE SOURCE OF TRUTH for all configuration.
 *
 * Secret loading priority:
 *   1. File path (e.g., Docker / Kubernetes mounted secret)
 *   2. Environment variable
 *   3. Default fallback (non-secrets only)
 *
 * Future compatibility:
 *   - Kubernetes Secrets → mount as files in /run/secrets/*
 *   - HashiCorp Vault   → inject as ENV or file
 *   - Docker Secrets    → mount at /run/secrets/*
 *
 * ⚠️  ALL other modules MUST import from this file.
 *     No other file should read process.env for secrets.
 * ─────────────────────────────────────────────────────────────
 */
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

// ─────────────────────────────────────────────────────────────
// HELPER: Load secret from file or environment variable
// ─────────────────────────────────────────────────────────────

/**
 * Loads a secret with the following priority:
 *   1. If `fileEnvKey` is set and points to a file → read from file
 *   2. Else if `envKey` is set → use its value
 *   3. Else → return defaultValue (only for non-critical config)
 *
 * @param {string}  envKey       - Primary env var name (e.g., 'JWT_PRIVATE_KEY')
 * @param {object}  opts
 * @param {string}  [opts.fileEnvKey]   - Env var pointing to a file path (e.g., 'JWT_PRIVATE_KEY_FILE')
 * @param {string}  [opts.defaultValue] - Fallback for non-secret config
 * @param {boolean} [opts.required]     - Throw if value is missing
 * @param {string}  [opts.description]  - Human-readable description for error messages
 */
function loadSecret(envKey, opts = {}) {
  const { fileEnvKey, defaultValue, required = false, description } = opts;

  // Priority 1: File-based secret (Kubernetes/Docker Secrets compatible)
  if (fileEnvKey && process.env[fileEnvKey]) {
    const filePath = process.env[fileEnvKey];
    try {
      return fs.readFileSync(filePath, 'utf8').trim();
    } catch (err) {
      throw new Error(
        `Failed to read secret from file ${filePath} (${fileEnvKey}): ${err.message}`
      );
    }
  }

  // Priority 2: Environment variable
  if (process.env[envKey]) {
    return process.env[envKey];
  }

  // Priority 3: Default value (non-secrets only)
  if (defaultValue !== undefined) {
    return defaultValue;
  }

  // Required but missing
  if (required) {
    throw new Error(
      `Missing required configuration: ${envKey}${description ? ` (${description})` : ''}. ` +
      `Set ${envKey} as an environment variable` +
      (fileEnvKey ? ` or ${fileEnvKey} as a path to a secret file.` : '.')
    );
  }

  return undefined;
}

/**
 * Loads an RSA key from file or environment variable.
 * Handles newline normalization for keys stored in env vars.
 */
function loadRsaKey(envKey, fileEnvKey, description) {
  let key = loadSecret(envKey, { fileEnvKey, required: true, description });

  // If the key is stored in an env var, newlines may be escaped as \n
  if (key && !key.includes('\n') && key.includes('\\n')) {
    key = key.replace(/\\n/g, '\n');
  }

  return key;
}

// ═══════════════════════════════════════════════════════════════
//  CONFIGURATION OBJECTS
// ═══════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────
// APP CONFIG
// ─────────────────────────────────────────────────────────────
export const app = Object.freeze({
  nodeEnv:    process.env.NODE_ENV || 'development',
  port:       parseInt(process.env.PORT, 10) || 3000,
  corsOrigin: process.env.CORS_ORIGIN
    ? process.env.CORS_ORIGIN.split(',')
    : ['http://localhost:3000'],
  isProduction: (process.env.NODE_ENV || 'development') === 'production',
  isDevelopment: (process.env.NODE_ENV || 'development') === 'development',
});

// ─────────────────────────────────────────────────────────────
// DATABASE CONFIG
// ─────────────────────────────────────────────────────────────
export const database = Object.freeze({
  url: loadSecret('DATABASE_URL', {
    fileEnvKey: 'DATABASE_URL_FILE',
    required: true,
    description: 'PostgreSQL connection string',
  }),
});

// ─────────────────────────────────────────────────────────────
// REDIS CONFIG
// ─────────────────────────────────────────────────────────────
export const redis = Object.freeze({
  url: loadSecret('REDIS_URL', {
    fileEnvKey: 'REDIS_URL_FILE',
    defaultValue: 'redis://localhost:6379',
  }),
});

// ─────────────────────────────────────────────────────────────
// JWT CONFIG (RS256 — Multi-Key / KID Rotation)
// ─────────────────────────────────────────────────────────────

/**
 * Discovers and loads all KID-based key pairs from environment variables.
 *
 * Convention: JWT_KEY_{KID}_PRIVATE_FILE, JWT_KEY_{KID}_PUBLIC_FILE
 *   e.g., JWT_KEY_KEY1_PRIVATE_FILE=./keys/key1/private.pem
 *
 * Falls back to legacy single-key config (JWT_PRIVATE_KEY_FILE) as
 * KID "default" if no KID-specific keys are found.
 */
function loadJwtKeys() {
  const keys = {};

  // ── Auto-discover KID-based key pairs from env ──────────────
  const kidPattern = /^JWT_KEY_(.+)_PRIVATE_FILE$/;
  for (const envKey of Object.keys(process.env)) {
    const match = envKey.match(kidPattern);
    if (!match) continue;

    const kid = match[1].toLowerCase(); // normalize to lowercase
    const publicEnvKey = `JWT_KEY_${match[1]}_PUBLIC_FILE`;

    if (!process.env[publicEnvKey]) {
      throw new Error(
        `Found ${envKey} but missing corresponding ${publicEnvKey}. ` +
        `Both private and public key files are required for KID "${kid}".`
      );
    }

    try {
      const privateKey = loadRsaKey(
        `JWT_KEY_${match[1]}_PRIVATE`,
        envKey,
        `RSA private key for KID "${kid}"`
      );
      const publicKey = loadRsaKey(
        `JWT_KEY_${match[1]}_PUBLIC`,
        publicEnvKey,
        `RSA public key for KID "${kid}"`
      );

      keys[kid] = Object.freeze({ privateKey, publicKey });
    } catch (err) {
      throw new Error(`Failed to load key pair for KID "${kid}": ${err.message}`);
    }
  }

  // ── Fallback: legacy single-key as KID "default" ────────────
  if (Object.keys(keys).length === 0) {
    try {
      const privateKey = loadRsaKey(
        'JWT_PRIVATE_KEY',
        'JWT_PRIVATE_KEY_FILE',
        'RSA private key for JWT signing (PEM format)'
      );
      const publicKey = loadRsaKey(
        'JWT_PUBLIC_KEY',
        'JWT_PUBLIC_KEY_FILE',
        'RSA public key for JWT verification (PEM format)'
      );
      keys['default'] = Object.freeze({ privateKey, publicKey });
      console.log('[CONFIG] No KID-based keys found — using legacy key pair as KID "default"');
    } catch {
      throw new Error(
        'No JWT keys configured. Set JWT_KEY_{KID}_PRIVATE_FILE / JWT_KEY_{KID}_PUBLIC_FILE, ' +
        'or fallback JWT_PRIVATE_KEY_FILE / JWT_PUBLIC_KEY_FILE.'
      );
    }
  }

  return keys;
}

const jwtKeys = loadJwtKeys();
const jwtActiveKid = (process.env.JWT_ACTIVE_KID || 'default').toLowerCase();

// Validate activeKid references a loaded key pair
if (!jwtKeys[jwtActiveKid]) {
  const available = Object.keys(jwtKeys).join(', ');
  throw new Error(
    `JWT_ACTIVE_KID="${jwtActiveKid}" does not match any loaded key pair. ` +
    `Available KIDs: [${available}]`
  );
}

console.log(`[CONFIG] JWT keys loaded: [${Object.keys(jwtKeys).join(', ')}]  active: "${jwtActiveKid}"`);

export const jwt = Object.freeze({
  algorithm: 'RS256',
  algorithms: ['RS256'],

  // ── Multi-key support ──────────────────────────────────────
  activeKid:  jwtActiveKid,
  keys:       Object.freeze(jwtKeys),

  // Convenience: active key pair (for signing)
  privateKey: jwtKeys[jwtActiveKid].privateKey,
  publicKey:  jwtKeys[jwtActiveKid].publicKey,

  /**
   * Look up a public key by KID for verification.
   * @param {string} kid - Key ID from JWT header
   * @returns {string} PEM-encoded public key
   * @throws {Error} if KID is unknown
   */
  getPublicKey(kid) {
    const normalized = (kid || '').toLowerCase();
    const entry = jwtKeys[normalized];
    if (!entry) {
      throw new Error(`Unknown JWT KID: "${kid}"`);
    }
    return entry.publicKey;
  },

  accessExpiresIn:  process.env.JWT_EXPIRES_IN || '15m',
  refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
  tempExpiresIn:    process.env.JWT_TEMP_EXPIRES_IN || '5m',

  issuer:   'cloud-iam-platform',
  audience: 'cloud-iam-users',
});

// ─────────────────────────────────────────────────────────────
// ENCRYPTION CONFIG (AES-256-GCM)
// ─────────────────────────────────────────────────────────────
const activeKeyVersion = parseInt(process.env.ACTIVE_KEY_VERSION, 10);
if (!activeKeyVersion) {
  throw new Error('ACTIVE_KEY_VERSION is missing or invalid');
}

/**
 * Loads and validates a versioned AES-256 encryption key.
 */
function loadEncryptionKey(version) {
  const envKey = `ENCRYPTION_KEY_V${version}`;
  const fileKey = `ENCRYPTION_KEY_V${version}_FILE`;

  const key = loadSecret(envKey, {
    fileEnvKey: fileKey,
    required: true,
    description: `AES-256 encryption key version ${version}`,
  });

  if (key.length !== 64 || !/^[0-9a-fA-F]+$/.test(key)) {
    throw new Error(
      `Invalid ${envKey}: must be exactly 64 hex characters (256-bit key)`
    );
  }

  return key;
}

// Pre-load all available key versions
const encryptionKeys = {};
for (let v = 1; v <= 10; v++) {
  const envKey = `ENCRYPTION_KEY_V${v}`;
  const fileKey = `ENCRYPTION_KEY_V${v}_FILE`;
  if (process.env[envKey] || process.env[fileKey]) {
    encryptionKeys[v] = loadEncryptionKey(v);
  }
}

// Ensure the active version is loaded
if (!encryptionKeys[activeKeyVersion]) {
  throw new Error(`Active encryption key V${activeKeyVersion} is not configured`);
}

export const encryption = Object.freeze({
  algorithm: 'aes-256-gcm',
  ivLength: 16,
  activeKeyVersion,
  keys: Object.freeze(encryptionKeys),
  getKey(version) {
    const key = encryptionKeys[version];
    if (!key) throw new Error(`Encryption key V${version} is not configured`);
    return Buffer.from(key, 'hex');
  },
});

// ─────────────────────────────────────────────────────────────
// PASSWORD HASHING CONFIG (Argon2id)
// ─────────────────────────────────────────────────────────────
export const hashing = Object.freeze({
  // Argon2id parameters — OWASP recommended
  type:        2,       // argon2id
  memoryCost:  65536,   // 64 MiB
  timeCost:    3,       // 3 iterations
  parallelism: 4,       // 4 threads
  hashLength:  32,      // 256-bit hash
});

// ─────────────────────────────────────────────────────────────
// SECURITY CONFIG
// ─────────────────────────────────────────────────────────────
export const security = Object.freeze({
  maxLoginAttempts: 5,
  lockTime: app.isDevelopment
    ? 60 * 1000        // 1 min (dev)
    : 15 * 60 * 1000,  // 15 min (prod)
  maxSessions: 5,
});

// ─────────────────────────────────────────────────────────────
// ACTIVE DEFENSE CONFIG (Toggle + Tuning)
// ─────────────────────────────────────────────────────────────
export const activeDefense = Object.freeze({
  enabled: (process.env.ACTIVE_DEFENDER || 'true').toLowerCase() === 'true',
});

// ─────────────────────────────────────────────────────────────
// GOOGLE OAUTH CONFIG
// ─────────────────────────────────────────────────────────────
export const google = Object.freeze({
  clientId: loadSecret('GOOGLE_CLIENT_ID', {
    fileEnvKey: 'GOOGLE_CLIENT_ID_FILE',
    defaultValue: '',
  }),
  clientSecret: loadSecret('GOOGLE_CLIENT_SECRET', {
    fileEnvKey: 'GOOGLE_CLIENT_SECRET_FILE',
    defaultValue: '',
  }),
  redirectUri: process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/api/v1/auth/google/callback',
});

// ─────────────────────────────────────────────────────────────
// INTERNAL SERVICE TOKEN (Zero Trust)
// ─────────────────────────────────────────────────────────────
export const internal = Object.freeze({
  serviceToken: loadSecret('INTERNAL_SERVICE_TOKEN', {
    fileEnvKey: 'INTERNAL_SERVICE_TOKEN_FILE',
    defaultValue: '',
  }),
});

// ─────────────────────────────────────────────────────────────
// SEED CONFIG
// ─────────────────────────────────────────────────────────────
export const seed = Object.freeze({
  adminPassword:    process.env.SEED_ADMIN_PASSWORD    || 'Admin@1234!',
  analystPassword:  process.env.SEED_ANALYST_PASSWORD  || 'Analyst@1234!',
  userPassword:     process.env.SEED_USER_PASSWORD     || 'User@1234!',
  mfaTargetEmail:   process.env.MFA_TARGET_EMAIL       || 'admin_attack@example.com',
  mfaTargetPassword: process.env.MFA_TARGET_PASSWORD   || undefined,
});

// ─────────────────────────────────────────────────────────────
// DEFAULT EXPORT — full config tree
// ─────────────────────────────────────────────────────────────
const config = Object.freeze({
  app,
  database,
  redis,
  jwt,
  encryption,
  hashing,
  security,
  activeDefense,
  google,
  internal,
  seed,
});

export default config;
