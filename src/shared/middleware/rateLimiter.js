import { extractClientInfo, getClientIp } from '../utils/clientInfo.js';
import logger from '../utils/logger.js';
import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import redisClient from '../config/redis.js';
import { verifyTempToken } from '../utils/jwt.js';
import { rateLimitCounter } from '../../metrics/metrics.js';
import { app as appConfig } from '../config/index.js';

export const apiLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args) => redisClient.call(...args),
  }),
  windowMs: 15 * 60 * 1000,
  max: appConfig.isProduction ? 100 : 50,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => extractClientInfo(req).ip,
  handler: (req, res, next, options) => {
    rateLimitCounter.inc({ type: 'api' });
    res.status(options.statusCode).send(options.message);
  },
});

export const authLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args) => redisClient.call(...args),
  }),
  windowMs: 15 * 60 * 1000,
  max: 20,
  keyGenerator: (req) => `${extractClientInfo(req).ip}-${req.body?.email || 'anonymous'}`,
  handler: (req, res, next, options) => {
    rateLimitCounter.inc({ type: 'auth' });
    res.status(options.statusCode).send(options.message);
  },
});

// 🔐 SECURITY FIX: Strict MFA rate limiting to prevent TOTP brute-force
export const mfaLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args) => redisClient.call(...args),
  }),
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const ip = getClientIp(req);

    try {
      const tempToken = req.body?.tempToken;
      if (!tempToken) return `mfa-ip:${ip}`;

      const decoded = verifyTempToken(tempToken);

      // per-user limiter (prevents distributed MFA attacks)
      return `mfa:${decoded.sub}`;
    } catch {
      return `mfa-ip:${ip}`;
    }
  },
  message: {
    success: false,
    code: 'MFA_RATE_LIMITED',
    message: 'Too many MFA attempts. Please try again later.',
  },
  handler: (req, res, next, options) => {
    let type = 'mfa_ip';
    try {
      const tempToken = req.body?.tempToken;
      if (tempToken) {
        verifyTempToken(tempToken);
        type = 'mfa_user';
      }
    } catch {
      // ignore and leave as mfa_ip
    }
    rateLimitCounter.inc({ type });
    res.status(options.statusCode).send(options.message);
  },
});

// ─────────────────────────────────────────────
// INTERNAL LIMITER — service-to-service routes only
// Applied to /api/internal/* BEFORE internalAuth.
// 50 requests per 15 minutes, keyed by IP.
// ─────────────────────────────────────────────
export const internalLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args) => redisClient.call(...args),
  }),
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => extractClientInfo(req).ip,
  handler: (req, res, next, options) => {
    rateLimitCounter.inc({ type: 'internal' });
    // 🔒 SEC-16: Use structured logger instead of console.log
    logger.warn('INTERNAL_RATE_LIMITED', { ip: extractClientInfo(req).ip, path: req.originalUrl });
    res.status(options.statusCode).send(options.message);
  },
  message: {
    success: false,
    code: 'INTERNAL_RATE_LIMITED',
    message: 'Too many internal requests. Please try again later.',
  },
});

