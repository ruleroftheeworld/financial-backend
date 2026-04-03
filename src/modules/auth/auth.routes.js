import { Router } from 'express';
import * as authController from './auth.controller.js';
import { authenticate } from '../../shared/middleware/authenticate.js';
import { authLimiter, mfaLimiter, apiLimiter } from '../../shared/middleware/rateLimiter.js';
import { validate, registerRules, loginRules, sessionIdParamRule } from '../../shared/middleware/validate.js';

const router = Router();

// ─────────────────────────────────────────────
// Public routes
// ─────────────────────────────────────────────
router.post('/register', authLimiter, registerRules, validate, authController.register);

router.get('/google', authController.googleAuth);
router.get('/google/callback', authController.googleCallback);

router.post('/login', authLimiter, loginRules, validate, authController.login);

// 🔐 SECURITY FIX: mfaLimiter (5 attempts/15min) replaces authLimiter to prevent TOTP brute-force
router.post('/mfa/validate-login', mfaLimiter, authController.validateMfaLogin);

// 🔒 SEC-12: Rate-limit refresh endpoint (prevents token rotation abuse)
router.post('/refresh', authLimiter, authController.refresh);

// ─────────────────────────────────────────────
// Protected routes
// ─────────────────────────────────────────────
router.post('/logout', authenticate, authController.logout);

router.get('/profile', authenticate, apiLimiter, authController.getProfile);

// ─────────────────────────────────────────────
// Session management (IAM)
// ─────────────────────────────────────────────
router.get('/sessions', authenticate, authController.getSessions);

router.get('/sessions/current', authenticate, authController.getCurrentSession);

// Revoke single session
router.delete(
  '/sessions/:id',
  authenticate,
  sessionIdParamRule,
  validate,
  authController.revokeSession
);

// Revoke all sessions 
router.delete(
  '/sessions',
  authenticate,
  authController.revokeAllSessions
);

export default router;
