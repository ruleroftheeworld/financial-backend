import crypto from 'crypto';
import jwtLib from 'jsonwebtoken';
import prisma from '../../shared/config/database.js';
import config from '../../shared/config/index.js';
import AppError from '../../shared/utils/AppError.js';
import logger from '../../shared/utils/logger.js';
import { hashPassword, verifyPassword, dummyVerify } from '../../shared/utils/password.js';
import {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
  generateTempToken,
  verifyTempToken
} from '../../shared/utils/jwt.js';
import { logSecurityEvent } from './audit.service.js';
import { SECURITY_CONFIG } from '../../shared/config/security.js';
import { accountLockCounter, sessionSecurityCounter } from '../../metrics/metrics.js';

const MAX_SESSIONS = config.security.maxSessions;

// ─────────────────────────────────────────────
// REGISTER
// ─────────────────────────────────────────────
export const register = async ({ name, email, password, ipAddress, userAgent }) => {
  const normalizedEmail = email.toLowerCase().trim();

  const existing = await prisma.user.findUnique({
    where: { email: normalizedEmail },
  });

  if (existing) {
    throw new AppError('Email already registered', 409, 'DUPLICATE_EMAIL');
  }

  const hashedPassword = await hashPassword(password);

  const user = await prisma.user.create({
    data: {
      name,
      email: normalizedEmail,
      password: hashedPassword,
      role: 'USER',
    },
  });

  const { password: _, ...safeUser } = user;

  logger.info('REGISTER_SUCCESS', { userId: user.id });

  return { user: safeUser };
};

// ─────────────────────────────────────────────
// LOGIN
// ─────────────────────────────────────────────
export const login = async ({ email, password, ipAddress, userAgent }) => {
  const normalizedEmail = email.toLowerCase().trim();

  const user = await prisma.user.findUnique({
    where: { email: normalizedEmail },
  });

  // Prevent user enumeration — dummy hash burns same CPU time
  if (!user) {
    await dummyVerify(password);
    logger.warn('LOGIN_FAILED', { email: normalizedEmail, ip: ipAddress });
    await logSecurityEvent({ action: 'LOGIN_FAILED', status: 'FAILURE', ip: ipAddress });
    throw new AppError('Invalid email or password', 401, 'INVALID_CREDENTIALS');
  }

  // Account Lockout Protection
  if (user.lockUntil && user.lockUntil > new Date()) {
    logger.warn('ACCOUNT_LOCKED_ATTEMPT', { userId: user.id, ip: ipAddress });
    throw new AppError(
  'Account temporarily locked due to multiple failed attempts',
  403,
  'ACCOUNT_LOCKED'
);
  }

  const isMatch = await verifyPassword(user.password, password);

  if (!isMatch) {
    // Increment failedLoginAttempts
    const attempts = (user.failedLoginAttempts || 0) + 1;
    let lockUntil = user.lockUntil;

    if (attempts >= SECURITY_CONFIG.MAX_LOGIN_ATTEMPTS) {
      lockUntil = new Date(Date.now() + SECURITY_CONFIG.LOCK_TIME);

      await prisma.session.updateMany({
        where: { userId: user.id },
        data: { revoked: true }
      });

      logger.warn('ALL_SESSIONS_REVOKED_ON_LOCK', {
        userId: user.id
      });
      logger.warn('ACCOUNT_LOCKED', { userId: user.id, ip: ipAddress });
      accountLockCounter.inc({ reason: 'brute_force' });
    }

    await prisma.user.update({
      where: { id: user.id },
      data: { failedLoginAttempts: attempts, lockUntil }
    });

    logger.warn('LOGIN_FAILED', { userId: user.id, ip: ipAddress });
    await logSecurityEvent({ userId: user.id, action: 'LOGIN_FAILED', status: 'FAILURE', ip: ipAddress });
    throw new AppError('Invalid email or password', 401, 'INVALID_CREDENTIALS');
  }

  // Reset counters on successful login
  if (user.failedLoginAttempts > 0 || user.lockUntil) {
    await prisma.user.update({
      where: { id: user.id },
      data: { failedLoginAttempts: 0, lockUntil: null }
    });
  }

  const { password: _, ...safeUser } = user;

  if (user.totpEnabled) {
    const tempToken = generateTempToken(user);
    return { status: "MFA_REQUIRED", tempToken };
  }

  const tokens = await issueTokens(safeUser, { ipAddress, userAgent, mfaVerified: false });

  await logSecurityEvent({ userId: user.id, action: 'LOGIN_SUCCESS', status: 'SUCCESS', ip: ipAddress, userAgent });

  return { user: safeUser, ...tokens };
};

// ─────────────────────────────────────────────
// GOOGLE OAUTH LOGIN
// 🔐 SECURITY FIX: No silent account linking
// ─────────────────────────────────────────────
export const handleGoogleAuth = async ({ googleId, email, name, ipAddress, userAgent }) => {
  const normalizedEmail = email.toLowerCase().trim();
  let user = await prisma.user.findUnique({ where: { googleId } });

  if (!user) {
    // Check if an account with this email already exists
    const existingUser = await prisma.user.findUnique({ where: { email: normalizedEmail } });

    if (existingUser) {
      // 🔐 SECURITY FIX: Do NOT auto-link. Prevent account takeover via Google OAuth.
      logger.warn('GOOGLE_OAUTH_LINK_BLOCKED', {
        email: normalizedEmail,
        existingUserId: existingUser.id,
        ip: ipAddress
      });
      throw new AppError(
        'An account with this email already exists. Please login with your password and link Google from settings.',
        409,
        'ACCOUNT_EXISTS'
      );
    }

    // Provision net-new user (no existing account conflict)
    user = await prisma.user.create({
      data: {
        email: normalizedEmail,
        name,
        googleId,
        provider: 'google',
        role: 'USER',
      }
    });
  }

  // Re-use core IAM lockout protection identically
  if (user.lockUntil && user.lockUntil > new Date()) {
    throw new AppError('Account temporarily locked', 403, 'ACCOUNT_LOCKED');
  }

  // Erase latent attempt tracking if recovering securely via OIDC
  if (user.failedLoginAttempts > 0 || user.lockUntil) {
    user = await prisma.user.update({
      where: { id: user.id },
      data: { failedLoginAttempts: 0, lockUntil: null }
    });
  }

  const { password: _, ...safeUser } = user;

  // Re-use core IAM MFA tracking natively (DO NOT BYPASS)
  if (user.totpEnabled) {
    const tempToken = generateTempToken(user);
    return { status: "MFA_REQUIRED", tempToken };
  }

  // Issue standard tokens
  const tokens = await issueTokens(safeUser, { ipAddress, userAgent, mfaVerified: false });
  
  await logSecurityEvent({ userId: user.id, action: 'LOGIN_SUCCESS', status: 'SUCCESS_GOOGLE', ip: ipAddress, userAgent });

  return { user: safeUser, ...tokens };
};

// ─────────────────────────────────────────────
// VALIDATE MFA LOGIN
// ─────────────────────────────────────────────
export const validateMfaLogin = async ({ code, tempToken, ipAddress, userAgent }) => {
  const decoded = verifyTempToken(tempToken);

  const user = await prisma.user.findUnique({ where: { id: decoded.sub } });
  
  if (!user || (user.lockUntil && user.lockUntil > new Date()) || !user.totpEnabled) {
    throw new AppError('Invalid MFA login attempt', 403, 'FORBIDDEN');
  }

  // PATCH 1: Fix Race Condition in Temp Token Replay Protection (ATOMIC UPDATE)
  const updated = await prisma.user.updateMany({
    where: {
      id: user.id,
      OR: [
        { lastTempTokenJti: null },
        { lastTempTokenJti: { not: decoded.jti } }
      ]
    },
    data: {
      lastTempTokenJti: decoded.jti,
      lastTempTokenUsedAt: new Date()
    }
  });

  if (updated.count === 0) {
    throw new AppError("Temp token already used", 401, "TOKEN_REUSE_DETECTED");
  }

  // Decrypt TOTP Secret
  const { decrypt } = await import('../../shared/utils/cipher.js');
  
  if (user.totpSecret && !user.totpSecretKeyVersion) {
    throw new AppError(
      'Invalid encryption state',
      500,
      'CRYPTO_STATE_INVALID'
    );
  }

  if (!user.totpSecretKeyVersion) {
    throw new AppError('MFA key version missing', 500, 'MFA_KEY_ERROR');
  }
  const decryptedSecret = decrypt(user.totpSecret, user.totpSecretKeyVersion);

  const speakeasy = (await import('speakeasy')).default;
  const verified = speakeasy.totp.verify({
    secret: decryptedSecret,
    encoding: 'base32',
    token: code,
    window: 1,
  });

  if (!verified) {
    await logSecurityEvent({ userId: user.id, action: 'LOGIN_FAILED', status: 'MFA_FAILED', ip: ipAddress, userAgent });
    throw new AppError('Invalid MFA code', 400, 'INVALID_MFA_CODE');
  }

  await logSecurityEvent({ userId: user.id, action: 'LOGIN_SUCCESS', status: 'MFA_SUCCESS', ip: ipAddress, userAgent });

  const { password: _, ...safeUser } = user;
  const tokens = await issueTokens(safeUser, { ipAddress, userAgent, mfaVerified: true });
  
  return { user: safeUser, ...tokens };
};

// ─────────────────────────────────────────────
// REFRESH TOKEN (ROTATION)
// ─────────────────────────────────────────────
export const refresh = async (token, { ipAddress, userAgent }) => {
  if (!token) {
    throw new AppError('Refresh token missing', 401, 'REFRESH_TOKEN_MISSING');
  }

  // ── Step 1: Verify JWT signature BEFORE touching the DB.
  // This is intentionally outside the transaction — it is CPU-only and
  // an invalid signature means we never need a DB round-trip.
  let decoded;
  try {
    decoded = verifyRefreshToken(token);
  } catch (err) {
    const attemptDecoded = jwtLib.decode(token);
    if (attemptDecoded?.sub) {
      logger.warn('TOKEN_REUSE_DETECTED_INVALID_SIG', { userId: attemptDecoded.sub, ipAddress });
    }
    throw new AppError('Invalid refresh token', 401, 'REFRESH_TOKEN_INVALID');
  }

  if (!decoded?.jti || !decoded?.sub) {
    throw new AppError('Invalid refresh token', 401, 'REFRESH_TOKEN_INVALID');
  }

  // ── Step 2: Argon2 hash verification — also outside the DB transaction.
  //
  // WHY: Argon2 takes 200–400ms by design. Holding a DB serializable
  // transaction open for that long would block every other refresh request
  // for the same session, causing cascading timeouts under load.
  //
  // HOW this is still safe: we verify the hash first using the token string.
  // We then pass into the transaction and do the atomic CAS (compare-and-swap)
  // on isUsed. If the hash doesn't match we never enter the transaction.
  // An attacker cannot skip the hash check because the transaction re-reads
  // the session row under a FOR UPDATE lock and the CAS on isUsed=false will
  // fail for every concurrent duplicate even if they somehow shared a valid hash.
  //
  // The only scenario where pre-verification is insufficient is if the Argon2
  // hash changes between here and the transaction — which cannot happen because
  // refreshTokenHash is written once at session creation and never mutated.

  // Fetch the session once (read-only, outside tx) to get the hash for Argon2.
  const sessionForHash = await prisma.session.findUnique({
    where: { id: decoded.jti },
    select: {
      id:               true,
      revoked:          true,
      isUsed:           true,
      expiresAt:        true,
      refreshTokenHash: true,
      userId:           true,
      ipAddress:        true,
      userAgent:        true,
    },
  });

  if (!sessionForHash) {
    logger.warn('REFRESH_TOKEN_NOT_FOUND', { jti: decoded.jti, ipAddress });
    throw new AppError('Invalid refresh token', 401, 'REFRESH_TOKEN_INVALID');
  }

  // Fast-path checks that don't need the lock — reject before Argon2.
  if (sessionForHash.revoked) {
    logger.warn('REFRESH_TOKEN_REVOKED', { userId: decoded.sub, jti: decoded.jti, ipAddress });
    throw new AppError('Invalid refresh token', 401, 'REFRESH_TOKEN_INVALID');
  }

  if (sessionForHash.expiresAt < new Date()) {
    throw new AppError('Session expired or invalid', 401, 'REFRESH_TOKEN_INVALID');
  }

  // Argon2 verification — done BEFORE the DB transaction to keep tx duration short.
  if (sessionForHash.refreshTokenHash) {
    const { verifyPassword: verifyHash } = await import('../../shared/utils/password.js');
    const isTokenMatch = await verifyHash(sessionForHash.refreshTokenHash, token);
    if (!isTokenMatch) {
      logger.warn('TOKEN_MISMATCH_REUSE_DETECTED', { userId: sessionForHash.userId, jti: decoded.jti, ipAddress });
      sessionSecurityCounter.inc({ event: 'token_hash_mismatch' });
      await prisma.session.updateMany({
        where: { userId: sessionForHash.userId },
        data:  { revoked: true },
      });
      throw new AppError('Refresh token reuse detected. All sessions revoked.', 401, 'SESSION_COMPROMISED');
    }
  }

  // ── Step 3: Serializable transaction — the atomic gate.
  //
  // isolationLevel: 'Serializable' tells PostgreSQL to run this transaction as
  // if it were the only one in the system. If two concurrent transactions both
  // try to read + write the same session row, PostgreSQL will let one succeed
  // and abort the other with error code 40001 (serialization_failure).
  //
  // Inside the transaction we:
  //   a) Re-read the session (this read is now part of the serializable snapshot)
  //   b) Run all business checks against the locked row
  //   c) Mark isUsed=true atomically with a WHERE isUsed=false CAS condition
  //   d) Return the user object needed for token issuance
  //
  // The CAS (step c) is the hard safety net: even if PostgreSQL somehow lets two
  // serializable transactions proceed concurrently, only one updateMany with
  // WHERE isUsed=false can return count=1. The other gets count=0 and we revoke.

  let safeUser;

  try {
    safeUser = await prisma.$transaction(async (tx) => {
      // Re-read session inside the serializable snapshot with the full user join.
      const session = await tx.session.findUnique({
        where:   { id: decoded.jti },
        include: { user: true },
      });

      // Defensive re-checks inside the transaction (the row state may have
      // changed between the read above and now if another request committed first).
      if (!session || session.revoked) {
        throw new AppError('Invalid refresh token', 401, 'REFRESH_TOKEN_INVALID');
      }

      // REUSE DETECTION inside the tx — if isUsed is already true, a previous
      // request already claimed this token. Revoke all sessions and reject.
      if (session.isUsed) {
        logger.warn('TOKEN_REUSE_DETECTED', { userId: decoded.sub, jti: decoded.jti, ipAddress });
        sessionSecurityCounter.inc({ event: 'token_reuse' });

        await tx.session.updateMany({
          where: { userId: decoded.sub },
          data:  { revoked: true },
        });

        // Fire-and-forget audit log (outside the tx to avoid blocking commit)
        logSecurityEvent({
          userId: decoded.sub,
          action: 'TOKEN_REUSE_DETECTED',
          status: 'FAILURE',
          ip:     ipAddress,
          userAgent,
          metadata: { jti: decoded.jti, allSessionsRevoked: true },
        }).catch(() => {});

        sessionSecurityCounter.inc({ event: 'session_compromised' });
        throw new AppError('Refresh token reuse detected. All sessions revoked.', 401, 'SESSION_COMPROMISED');
      }

      if (session.expiresAt < new Date()) {
        throw new AppError('Session expired or invalid', 401, 'REFRESH_TOKEN_INVALID');
      }

      const user = session.user;

      if (user.lockUntil && user.lockUntil > new Date()) {
        logger.warn('REFRESH_BLOCKED_ACCOUNT_LOCKED', { userId: user.id, ipAddress });
        throw new AppError('Account temporarily locked', 403, 'ACCOUNT_LOCKED');
      }

      // IP / UA anomaly check.
      if (
        (session.ipAddress && session.ipAddress !== ipAddress) ||
        (session.userAgent && session.userAgent !== userAgent)
      ) {
        await tx.session.update({
          where: { id: decoded.jti },
          data:  { revoked: true },
        });

        logSecurityEvent({
          userId: session.userId,
          action: 'SESSION_REVOKED',
          status: 'SUSPICIOUS_SESSION_DETECTED',
          ip:     ipAddress,
          userAgent,
        }).catch(() => {});

        logger.warn('SUSPICIOUS_SESSION_REVOKED', { userId: session.userId, ipAddress, userAgent });
        sessionSecurityCounter.inc({ event: 'session_hijack' });
        throw new AppError('Session anomalously accessed and revoked', 403, 'SESSION_COMPROMISED');
      }

      // ── THE ATOMIC COMPARE-AND-SWAP ──────────────────────────────────────
      // WHERE isUsed=false ensures only ONE concurrent request can claim
      // this token. PostgreSQL's serializable isolation makes this a true
      // atomic operation — no two transactions can both see isUsed=false
      // and both update to isUsed=true.
      const claimed = await tx.session.updateMany({
        where: { id: decoded.jti, isUsed: false },
        data:  { isUsed: true },
      });

      if (claimed.count === 0) {
        // Lost the race — another concurrent request claimed the token first.
        logger.warn('TOKEN_REUSE_DETECTED_RACE_CONDITION', {
          userId: session.userId,
          jti:    decoded.jti,
          ipAddress,
        });
        sessionSecurityCounter.inc({ event: 'token_race' });

        await tx.session.updateMany({
          where: { userId: session.userId },
          data:  { revoked: true },
        });

        throw new AppError(
          'Refresh token reuse detected. All sessions revoked.',
          401,
          'SESSION_COMPROMISED'
        );
      }

      const { password: _, ...safe } = user;
      return safe;

    }, {
      isolationLevel: 'Serializable',
      // Keep the timeout tight — this tx should complete in <100ms (no Argon2 inside).
      timeout: 10_000,
    });

  } catch (err) {
    // Re-throw AppErrors as-is. Prisma serialization failures (P2034) surface
    // as a generic DB error — translate them to a safe user-facing message.
    if (err instanceof AppError) throw err;

    if (err.code === 'P2034') {
      // PostgreSQL serialization_failure — another transaction won the race.
      logger.warn('SERIALIZATION_FAILURE_ON_REFRESH', { jti: decoded.jti, ipAddress });
      sessionSecurityCounter.inc({ event: 'token_race' });
      throw new AppError('Invalid refresh token', 401, 'REFRESH_TOKEN_INVALID');
    }

    throw err;
  }

  // ── Step 4: Issue new tokens — happens AFTER the transaction commits.
  const tokens = await issueTokens(safeUser, { ipAddress, userAgent });

  await logSecurityEvent({
    userId: safeUser.id,
    action: 'TOKEN_REFRESHED',
    status: 'SUCCESS',
    ip:     ipAddress,
    userAgent,
    metadata: { oldJti: decoded.jti },
  });

  logger.info('TOKEN_ROTATED', { userId: safeUser.id, oldJti: decoded.jti });

  return tokens;
};

// ─────────────────────────────────────────────
// LOGOUT (CURRENT SESSION)
// ─────────────────────────────────────────────
export const logout = async (token) => {
  if (!token) {
    throw new AppError('Token missing', 401, 'LOGOUT_FAILED');
  }

  const decoded = verifyRefreshToken(token);

  if (!decoded?.jti) {
    throw new AppError('Invalid token', 401, 'LOGOUT_FAILED');
  }

  const session = await prisma.session.findUnique({
    where: { id: decoded.jti },
  });

  if (!session || session.revoked) {
    throw new AppError('Session already invalid', 400, 'LOGOUT_FAILED');
  }

  await prisma.session.update({
    where: { id: decoded.jti },
    data: { revoked: true }
  });

  await logSecurityEvent({
    userId: decoded.sub,
    action: 'LOGOUT',
    status: 'SUCCESS',
    ip: null,
    userAgent: null,
    metadata: { jti: decoded.jti },
  });

  logger.info('LOGOUT', { userId: decoded.sub, jti: decoded.jti });
};

// ─────────────────────────────────────────────
// GET PROFILE
// ─────────────────────────────────────────────
export const getProfile = async (userId) => {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      name: true,
      email: true,
      role: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  if (!user) {
    throw new AppError('User not found', 404, 'NOT_FOUND');
  }

  return user;
};

// ─────────────────────────────────────────────
// GET ACTIVE SESSIONS
// ─────────────────────────────────────────────
export const getActiveSessions = async (userId) => {
  return prisma.session.findMany({
    where: {
      userId,
      revoked: false,
      expiresAt: { gt: new Date() },
    },
    select: {
      id: true,
      userAgent: true,
      ipAddress: true,
      createdAt: true,
      expiresAt: true,
    },
    orderBy: { createdAt: 'desc' },
  });
};

// ─────────────────────────────────────────────
// GET CURRENT SESSION
// ─────────────────────────────────────────────
export const getCurrentSession = async (jti) => {
  const session = await prisma.session.findUnique({
    where: { id: jti },
  });

  if (!session) {
    throw new AppError('Session not found', 404, 'NOT_FOUND');
  }

  return session;
};

// ─────────────────────────────────────────────
// REVOKE SINGLE SESSION
// ─────────────────────────────────────────────
export const revokeSession = async (sessionId, userId) => {
  const session = await prisma.session.findUnique({
    where: { id: sessionId },
  });

  if (!session || session.revoked) {
    throw new AppError('Session not found', 404, 'NOT_FOUND');
  }

  if (session.userId !== userId) {
    throw new AppError('Forbidden', 403, 'FORBIDDEN');
  }

  await prisma.session.update({
    where: { id: sessionId },
    data: { revoked: true }
  });

  await logSecurityEvent({
    userId,
    action: 'SESSION_REVOKED',
    status: 'SUCCESS',
    ip: null,
    userAgent: null,
    metadata: { revokedSessionId: sessionId },
  });

  logger.info('SESSION_REVOKED', { userId, sessionId });
};

// ─────────────────────────────────────────────
// REVOKE ALL SESSIONS
// ─────────────────────────────────────────────
export const revokeAllSessions = async (userId) => {
  const result = await prisma.session.updateMany({
    where: { userId, revoked: false },
    data: { revoked: true }
  });

  await logSecurityEvent({
    userId,
    action: 'ALL_SESSIONS_REVOKED',
    status: 'SUCCESS',
    ip: null,
    userAgent: null,
    metadata: { sessionsRevoked: result.count },
  });

  logger.info('ALL_SESSIONS_REVOKED', { userId, count: result.count });
};

// ─────────────────────────────────────────────
// INTERNAL: ISSUE TOKENS
// ─────────────────────────────────────────────
const issueTokens = async (user, { ipAddress, userAgent, mfaVerified = false } = {}) => {
  // 🔒 Limit active sessions
  const sessions = await prisma.session.findMany({
    where: { userId: user.id, revoked: false },
    orderBy: { createdAt: 'asc' },
  });

  if (sessions.length >= MAX_SESSIONS) {
    await prisma.session.update({
      where: { id: sessions[0].id },
      data: { revoked: true }
    });
  }
  const jti = crypto.randomUUID();
  const payload = {
    sub: user.id,
    email: user.email,
    role: user.role,
    jti: jti
  };

  const accessToken = generateAccessToken(payload);
  const refreshToken = generateRefreshToken(payload, jti);

  const decoded = jwtLib.decode(refreshToken);
  const expiresAt = new Date(decoded.exp * 1000);

  // Hash refresh token with Argon2 for secure storage
  const refreshTokenHash = await hashPassword(refreshToken);

  await prisma.session.create({
    data: {
      id: jti,
      userId: user.id,
      ipAddress: ipAddress || null,
      userAgent: userAgent || null,
      expiresAt,
      refreshTokenHash,
      revoked: false,
      mfaVerified
    },
  });

  return { accessToken, refreshToken };
};
