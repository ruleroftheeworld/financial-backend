import { verifyAccessToken } from '../utils/jwt.js';
import AppError from '../utils/AppError.js';
import prisma from '../config/database.js';
import logger from '../utils/logger.js';
import { extractClientInfo } from '../utils/clientInfo.js';
import { authFailureCounter } from '../../metrics/metrics.js';

export const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    // ─────────────────────────────────────────────
    // 1. Validate Authorization Header
    // ─────────────────────────────────────────────
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      authFailureCounter.inc({ reason: 'header_missing' });
      throw new AppError(
        'Authorization header missing or malformed',
        401,
        'AUTH_REQUIRED'
      );
    }

    const token = authHeader.split(' ')[1];

    if (!token) {
      authFailureCounter.inc({ reason: 'token_missing' });
      throw new AppError('Token missing', 401, 'AUTH_REQUIRED');
    }

    // ─────────────────────────────────────────────
    // 2. Verify JWT
    // ─────────────────────────────────────────────
    const decoded = verifyAccessToken(token);

    // ─────────────────────────────────────────────
    // 3. Validate payload (defensive check)
    // ─────────────────────────────────────────────
    if (!decoded.sub || !decoded.jti) {
      throw new AppError('Invalid token payload', 401, 'TOKEN_INVALID');
    }

    // ─────────────────────────────────────────────
    // 4. Session Revocation Defense
    // ─────────────────────────────────────────────
    const session = await prisma.session.findUnique({
      where: { id: decoded.jti },
      select: { revoked: true }
    });

    if (!session || session.revoked) {
      authFailureCounter.inc({ reason: 'session_revoked' });
      throw new AppError('Session invalidated or compromised', 401, 'SESSION_REVOKED');
    }

    // ─────────────────────────────────────────────
    // 5. Check user still exists & Token Version
    // ─────────────────────────────────────────────
    const user = await prisma.user.findUnique({
      where: { id: decoded.sub },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        tokenVersion: true
      },
    });

    if (!user) {
      authFailureCounter.inc({ reason: 'user_not_found' });
      throw new AppError('User no longer exists', 401, 'USER_NOT_FOUND');
    }

    // Version Check
    if (decoded.tokenVersion !== undefined && user.tokenVersion !== decoded.tokenVersion) {
      throw new AppError('Token version invalid or revoked', 401, 'TOKEN_REVOKED');
    }

    // ─────────────────────────────────────────────
    // 5. JWT-claim vs DB-role mismatch detection
    //    (defense-in-depth: catches tampered role claims)
    // ─────────────────────────────────────────────
    if (decoded.role && decoded.role !== user.role) {
      logger.warn('JWT_ROLE_MISMATCH', {
        userId: user.id,
        jwtRole: decoded.role,
        dbRole: user.role,
        path: req.originalUrl,
        ip: extractClientInfo(req).ip,
        hint: 'Possible JWT payload tampering detected',
      });
      // NOTE: We do NOT reject here — we always use DB role (below).
      // This log is for forensics / SIEM alerting.
    }

    // ─────────────────────────────────────────────
    // 6. Attach user to request (role from DB, NOT from JWT)
    // ─────────────────────────────────────────────
    req.user = user;

    // Attach decoded token for session/jti info only
    req.auth = decoded;

    next();

  } catch (err) {
    // 🔐 Optional: log suspicious access attempts
    logger.warn('AUTH_FAILURE', {
      path: req.originalUrl,
      ip: extractClientInfo(req).ip,
      error: err.message,
    });

    next(err);
  }
};
