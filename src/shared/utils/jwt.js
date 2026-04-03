/**
 * ─────────────────────────────────────────────────────────────
 * JWT SERVICE (RS256 — Asymmetric, KID-based Key Rotation)
 * ─────────────────────────────────────────────────────────────
 *
 * Centralized JWT generation and verification using RS256 with
 * KID (Key ID) support for seamless key rotation.
 *
 * Key rotation design:
 *   - SIGNING: Always uses the activeKid's private key
 *   - VERIFICATION: Extracts kid from JWT header, looks up the
 *     corresponding public key from config (supports all loaded keys)
 *   - Old tokens signed with previous keys remain valid as long
 *     as the old key pair is still loaded in config
 *
 * Security controls:
 *   - Single allowed algorithm: RS256
 *   - Mandatory expiration, issuer, audience claims
 *   - kid is injected into JWT header (not payload)
 *   - Structural pre-validation (defense-in-depth)
 *   - Blocked algorithms list (none, None, NONE, HS*)
 *   - Rejects tokens with missing or unknown kid
 *   - No fallback: verification uses ONLY the kid-resolved key
 *   - Granular security logging for SIEM integration
 *   - Prometheus metrics for verification failures
 *
 * ⚠️  Keys are loaded exclusively from the config module.
 * ─────────────────────────────────────────────────────────────
 */
import jwtLib from 'jsonwebtoken';
import crypto from 'crypto';
import AppError from './AppError.js';
import logger from './logger.js';
import { jwt as jwtConfig } from '../config/index.js';
import { jwtVerificationFailures } from '../../metrics/metrics.js';

// ─────────────────────────────────────────────
// CONSTANTS (all from centralized config)
// ─────────────────────────────────────────────
const PRIVATE_KEY        = jwtConfig.privateKey;
const PUBLIC_KEY         = jwtConfig.publicKey;
const ACTIVE_KID         = jwtConfig.activeKid;
const ALGORITHM          = jwtConfig.algorithm;        // 'RS256'
const ALLOWED_ALGORITHMS = jwtConfig.algorithms;       // ['RS256']
const ACCESS_EXPIRES     = jwtConfig.accessExpiresIn;  // '15m'
const REFRESH_EXPIRES    = jwtConfig.refreshExpiresIn; // '7d'
const TEMP_EXPIRES       = jwtConfig.tempExpiresIn;    // '5m'
const ISSUER             = jwtConfig.issuer;
const AUDIENCE           = jwtConfig.audience;

// ─────────────────────────────────────────────
// SECURITY EVENT LOGGER (defense-in-depth)
// Structured logging for SIEM/forensic analysis
// ─────────────────────────────────────────────

/**
 * Logs a JWT security event and increments the Prometheus counter.
 *
 * @param {string} reason  - Machine-readable reason code
 * @param {string} message - Human-readable detail
 * @param {object} [meta]  - Additional context (kid, alg, etc.)
 */
const logJwtSecurityEvent = (reason, message, meta = {}) => {
  logger.warn('JWT_SECURITY_EVENT', {
    reason,
    message,
    ...meta,
  });
  jwtVerificationFailures.inc({ reason });
};

// ─────────────────────────────────────────────
// GENERATE ACCESS TOKEN
// ─────────────────────────────────────────────
export const generateAccessToken = (payload) => {
  return jwtLib.sign(
    {
      sub:   payload.sub,
      email: payload.email,
      role:  payload.role,
      type:  'access',
      jti:   payload.jti,
    },
    PRIVATE_KEY,
    {
      expiresIn: ACCESS_EXPIRES,
      issuer:    ISSUER,
      audience:  AUDIENCE,
      algorithm: ALGORITHM,
      keyid:     ACTIVE_KID,        // ← kid injected into JWT header
    }
  );
};

// ─────────────────────────────────────────────
// GENERATE REFRESH TOKEN
// ─────────────────────────────────────────────
export const generateRefreshToken = (payload, jti) => {
  return jwtLib.sign(
    {
      sub:  payload.sub,
      type: 'refresh',
    },
    PRIVATE_KEY,
    {
      expiresIn: REFRESH_EXPIRES,
      issuer:    ISSUER,
      audience:  AUDIENCE,
      algorithm: ALGORITHM,
      jwtid:     jti,
      keyid:     ACTIVE_KID,        // ← kid injected into JWT header
    }
  );
};

// ─────────────────────────────────────────────
// GENERATE TEMP TOKEN (MFA flow)
// ─────────────────────────────────────────────
export const generateTempToken = (payload) => {
  const jti = crypto.randomUUID();
  return jwtLib.sign(
    {
      sub:  payload.sub || payload.id,
      type: 'temp',
      jti,
    },
    PRIVATE_KEY,
    {
      expiresIn: TEMP_EXPIRES,
      issuer:    ISSUER,
      audience:  AUDIENCE,
      algorithm: ALGORITHM,
      keyid:     ACTIVE_KID,        // ← kid injected into JWT header
    }
  );
};

// ─────────────────────────────────────────────
// STRUCTURAL PRE-VALIDATION (defense-in-depth)
// Rejects malformed tokens before they reach
// jwt.verify(), preventing edge-case parser bugs.
// ─────────────────────────────────────────────
const BLOCKED_ALGORITHMS = new Set([
  'none', 'None', 'NONE', 'nOnE',   // CVE-2015-9235 variants
  'HS256', 'HS384', 'HS512',        // Block HMAC to prevent alg confusion
]);

/**
 * Pre-validates token structure and extracts the kid from the header.
 * Returns the kid for use in key lookup during verification.
 *
 * @param {string} token - Raw JWT string
 * @returns {string} kid from the JWT header
 */
const validateTokenStructure = (token) => {
  if (typeof token !== 'string' || !token.length) {
    logJwtSecurityEvent('token_malformed', 'Token is empty or not a string');
    throw new AppError('Token is empty or not a string', 401, 'TOKEN_MALFORMED');
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    logJwtSecurityEvent('token_malformed', `Token has ${parts.length} parts instead of 3`);
    throw new AppError(
      `Token must have 3 parts, found ${parts.length}`,
      401,
      'TOKEN_MALFORMED'
    );
  }

  // Reject empty signature segment (alg:none attack indicator)
  if (!parts[2] || parts[2].trim().length === 0) {
    logJwtSecurityEvent('signature_missing', 'Empty signature segment — possible alg:none attack');
    throw new AppError(
      'Token has empty signature — possible alg:none attack',
      401,
      'SIGNATURE_MISSING'
    );
  }

  // Decode header to check algorithm and extract kid
  try {
    const headerStr = Buffer.from(parts[0], 'base64url').toString('utf8');
    const header = JSON.parse(headerStr);

    if (BLOCKED_ALGORITHMS.has(header.alg)) {
      logJwtSecurityEvent('algorithm_blocked', `Blocked algorithm: ${header.alg}`, {
        alg: header.alg,
        kid: header.kid || null,
      });
      throw new AppError(
        `Blocked algorithm: ${header.alg}`,
        401,
        'ALGORITHM_NOT_ALLOWED'
      );
    }

    // ── KID validation ────────────────────────────────────────
    if (!header.kid) {
      logJwtSecurityEvent('kid_missing', 'Token is missing kid (Key ID) in header', {
        alg: header.alg,
      });
      throw new AppError(
        'Token is missing kid (Key ID) in header',
        401,
        'KID_MISSING'
      );
    }

    return header.kid;

  } catch (err) {
    if (err instanceof AppError) throw err;
    logJwtSecurityEvent('token_malformed', 'Token header is malformed / unparseable');
    throw new AppError('Token header is malformed', 401, 'TOKEN_MALFORMED');
  }
};

/**
 * Resolves the public key for a given kid.
 * Uses the config module's key registry for lookup.
 *
 * ⚠️  STRICT: No fallback. If the kid doesn't map to a loaded key,
 *     the request is rejected immediately. The system NEVER tries
 *     other keys on failure.
 *
 * @param {string} kid - Key ID from JWT header
 * @returns {string} PEM-encoded RSA public key
 */
const resolvePublicKey = (kid) => {
  try {
    return jwtConfig.getPublicKey(kid);
  } catch {
    logJwtSecurityEvent('kid_unknown', `Unknown key ID: "${kid}"`, { kid });
    throw new AppError(
      `Unknown key ID: "${kid}"`,
      401,
      'KID_UNKNOWN'
    );
  }
};

// ─────────────────────────────────────────────
// VERIFY ACCESS TOKEN (KID-aware)
// ─────────────────────────────────────────────
export const verifyAccessToken = (token) => {
  try {
    const kid = validateTokenStructure(token);
    const publicKey = resolvePublicKey(kid);

    const decoded = jwtLib.verify(token, publicKey, {
      issuer:          ISSUER,
      audience:        AUDIENCE,
      algorithms:      ALLOWED_ALGORITHMS,   // ONLY RS256
      clockTolerance:  5,
      ignoreExpiration: false,
    });

    if (!decoded.sub || decoded.type !== 'access') {
      logJwtSecurityEvent('token_invalid', 'Access token payload invalid (missing sub or wrong type)', { kid });
      throw new AppError('Invalid token payload', 401, 'TOKEN_INVALID');
    }

    return decoded;
  } catch (err) {
    if (err instanceof AppError) throw err;
    if (err.name === 'TokenExpiredError') {
      logJwtSecurityEvent('token_expired', 'Access token expired', { kid: _safeExtractKid(token) });
      throw new AppError('Access token expired', 401, 'TOKEN_EXPIRED');
    }
    if (err.name === 'JsonWebTokenError') {
      logJwtSecurityEvent('signature_invalid', `JWT verification failed: ${err.message}`, {
        kid: _safeExtractKid(token),
        detail: err.message,
      });
      throw new AppError(
        `JWT verification failed: ${err.message}`,
        401,
        'SIGNATURE_INVALID'
      );
    }
    logJwtSecurityEvent('token_invalid', 'Access token verification failed (unknown error)', {
      kid: _safeExtractKid(token),
    });
    throw new AppError('Invalid access token', 401, 'TOKEN_INVALID');
  }
};

// ─────────────────────────────────────────────
// VERIFY REFRESH TOKEN (KID-aware)
// ─────────────────────────────────────────────
export const verifyRefreshToken = (token) => {
  try {
    const kid = validateTokenStructure(token);
    const publicKey = resolvePublicKey(kid);

    const decoded = jwtLib.verify(token, publicKey, {
      issuer:          ISSUER,
      audience:        AUDIENCE,
      algorithms:      ALLOWED_ALGORITHMS,
      clockTolerance:  5,
      ignoreExpiration: false,
    });

    if (!decoded.sub || decoded.type !== 'refresh' || !decoded.jti) {
      logJwtSecurityEvent('token_invalid', 'Refresh token payload invalid', { kid });
      throw new AppError('Invalid refresh token payload', 401, 'REFRESH_TOKEN_INVALID');
    }

    return decoded;
  } catch (err) {
    if (err instanceof AppError) throw err;
    if (err.name === 'TokenExpiredError') {
      logJwtSecurityEvent('token_expired', 'Refresh token expired', { kid: _safeExtractKid(token) });
      throw new AppError('Refresh token expired', 401, 'REFRESH_TOKEN_EXPIRED');
    }
    logJwtSecurityEvent('signature_invalid', 'Refresh token verification failed', {
      kid: _safeExtractKid(token),
    });
    throw new AppError('Invalid refresh token', 401, 'REFRESH_TOKEN_INVALID');
  }
};

// ─────────────────────────────────────────────
// VERIFY TEMP TOKEN (KID-aware)
// ─────────────────────────────────────────────
export const verifyTempToken = (token) => {
  try {
    const kid = validateTokenStructure(token);
    const publicKey = resolvePublicKey(kid);

    const decoded = jwtLib.verify(token, publicKey, {
      issuer:          ISSUER,
      audience:        AUDIENCE,
      algorithms:      ALLOWED_ALGORITHMS,
      clockTolerance:  5,
      ignoreExpiration: false,
    });

    if (!decoded.sub || decoded.type !== 'temp' || !decoded.jti) {
      logJwtSecurityEvent('token_invalid', 'Temp token payload invalid', { kid });
      throw new AppError('Invalid temp token or missing JTI', 401, 'TOKEN_INVALID');
    }

    return decoded;
  } catch (err) {
    if (err instanceof AppError) throw err;
    if (err.name === 'TokenExpiredError') {
      logJwtSecurityEvent('token_expired', 'Temp token expired', { kid: _safeExtractKid(token) });
      throw new AppError('Temporary token expired', 401, 'TOKEN_EXPIRED');
    }
    logJwtSecurityEvent('signature_invalid', 'Temp token verification failed', {
      kid: _safeExtractKid(token),
    });
    throw new AppError('Invalid temp token', 401, 'TOKEN_INVALID');
  }
};

// ─────────────────────────────────────────────
// INTERNAL HELPER: safely extract kid from a
// token for logging (best-effort, no throw)
// ─────────────────────────────────────────────
function _safeExtractKid(token) {
  try {
    const header = JSON.parse(
      Buffer.from(token.split('.')[0], 'base64url').toString('utf8')
    );
    return header.kid || null;
  } catch {
    return null;
  }
}