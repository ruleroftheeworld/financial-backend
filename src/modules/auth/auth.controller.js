import { extractClientInfo } from '../../shared/utils/clientInfo.js';
import * as authService from './auth.service.js';
import * as googleAuthService from './googleAuth.service.js';
import { successResponse } from '../../shared/utils/response.js';
import { loginCounter, mfaCounter, loginDuration } from '../../metrics/metrics.js';
import { app as appConfig } from '../../shared/config/index.js';

// Cookie config (reuse everywhere)
const REFRESH_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: appConfig.isProduction,
  sameSite: 'strict',
  path: '/api/v1/auth', // restrict cookie scope
};

// ─────────────────────────────────────────────
// GOOGLE OAUTH
// ─────────────────────────────────────────────
export const googleAuth = (req, res) => {
  res.redirect(googleAuthService.getAuthUrl());
};

export const googleCallback = async (req, res, next) => {
  try {
    const { code } = req.query;
    if (!code) {
      // In case they pass purely the ID token natively from a frontend SDK, support it natively
      const idTokenHeader = req.headers['x-google-id-token'];
      if (!idTokenHeader) throw new Error('Authorization code missing');
      req.query.idToken = idTokenHeader; // Forward for explicit manual flow handling below
    }

    const idToken = req.query.idToken || (await googleAuthService.exchangeCodeForIdToken(code));
    const { googleId, email, name } = await googleAuthService.verifyGoogleIdToken(idToken);

    const result = await authService.handleGoogleAuth({
      googleId,
      email,
      name,
      ipAddress: extractClientInfo(req).ip,
      userAgent: extractClientInfo(req).userAgent
    });

    if (result.status === 'MFA_REQUIRED') {
      return successResponse(res, result, 'MFA token required');
    }

    res.cookie('refreshToken', result.refreshToken, {
      ...REFRESH_COOKIE_OPTIONS,
      expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    return successResponse(res, { accessToken: result.accessToken, user: result.user }, 'Google login successful');
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// REGISTER
// ─────────────────────────────────────────────
export const register = async (req, res, next) => {
  try {
    const { name, email, password } = req.body;

    await authService.register({
      name,
      email,
      password,
      ipAddress: extractClientInfo(req).ip,
      userAgent: extractClientInfo(req).userAgent,
    });

    return res.status(201).json({
      success: true,
      message: 'User registered successfully'
    });
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// LOGIN
// ─────────────────────────────────────────────
export const login = async (req, res, next) => {
  const end = loginDuration.startTimer();
  try {
    const { email, password } = req.body;

    const result = await authService.login({
      email,
      password,
      ipAddress: extractClientInfo(req).ip,
      userAgent: extractClientInfo(req).userAgent,
    });

    if (result.status === 'MFA_REQUIRED') {
      loginCounter.inc({ status: 'mfa_required' });
      end();
      return successResponse(res, result, 'MFA token required');
    }

    loginCounter.inc({ status: 'success' });
    end();

    // Set refresh token in cookie
    res.cookie('refreshToken', result.refreshToken, {
      ...REFRESH_COOKIE_OPTIONS,
      expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    return successResponse(
      res,
      {
        accessToken: result.accessToken,
        user: result.user,
      },
      'Login successful'
    );
  } catch (err) {
    loginCounter.inc({ status: 'failure' });
    end();
    next(err);
  }
};

// ─────────────────────────────────────────────
// VALIDATE MFA LOGIN
// ─────────────────────────────────────────────
export const validateMfaLogin = async (req, res, next) => {
  try {
    const { code, tempToken } = req.body;

    const result = await authService.validateMfaLogin({
      code,
      tempToken,
      ipAddress: extractClientInfo(req).ip,
      userAgent: extractClientInfo(req).userAgent,
    });

    mfaCounter.inc({ status: 'success' });

    // Set refresh token in cookie
    res.cookie('refreshToken', result.refreshToken, {
      ...REFRESH_COOKIE_OPTIONS,
      expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    return successResponse(
      res,
      {
        accessToken: result.accessToken,
        user: result.user,
      },
      'Login successful'
    );
  } catch (err) {
    mfaCounter.inc({ status: 'failure' });
    next(err);
  }
};

// ─────────────────────────────────────────────
// REFRESH TOKEN (ROTATION)
// ─────────────────────────────────────────────
export const refresh = async (req, res, next) => {
  try {
    const refreshToken = req.cookies.refreshToken;

    const tokens = await authService.refresh(refreshToken, {
      ipAddress: extractClientInfo(req).ip,
      userAgent: extractClientInfo(req).userAgent,
    });

    // Rotate cookie (replace old token)
    res.cookie('refreshToken', tokens.refreshToken, {
      ...REFRESH_COOKIE_OPTIONS,
      expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    return successResponse(
      res,
      { accessToken: tokens.accessToken },
      'Token refreshed successfully'
    );
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// LOGOUT (CURRENT SESSION)
// ─────────────────────────────────────────────
export const logout = async (req, res, next) => {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (refreshToken) {
      await authService.logout(refreshToken);
    }

    // Clear cookie
    res.clearCookie('refreshToken', REFRESH_COOKIE_OPTIONS);

    return successResponse(res, {}, 'Logged out successfully');
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// GET PROFILE
// ─────────────────────────────────────────────
export const getProfile = async (req, res, next) => {
  try {
    const user = await authService.getProfile(req.user.id);

    return successResponse(res, { user }, 'Profile retrieved');
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// GET ALL ACTIVE SESSIONS
// ─────────────────────────────────────────────
export const getSessions = async (req, res, next) => {
  try {
    const sessions = await authService.getActiveSessions(req.user.id);

    return successResponse(res, { sessions }, 'Sessions retrieved');
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// GET CURRENT SESSION
// ─────────────────────────────────────────────
export const getCurrentSession = async (req, res, next) => {
  try {
    const session = await authService.getCurrentSession(req.auth.jti);

    return successResponse(res, { session }, 'Current session retrieved');
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// REVOKE SPECIFIC SESSION
// ─────────────────────────────────────────────
export const revokeSession = async (req, res, next) => {
  try {
    const { id } = req.params;

    await authService.revokeSession(id, req.user.id);

    return successResponse(res, {}, 'Session revoked');
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// REVOKE ALL SESSIONS
// ─────────────────────────────────────────────
export const revokeAllSessions = async (req, res, next) => {
  try {
    await authService.revokeAllSessions(req.user.id);

    // Clear cookie for security
    res.clearCookie('refreshToken', REFRESH_COOKIE_OPTIONS);

    return successResponse(res, {}, 'All sessions revoked');
  } catch (err) {
    next(err);
  }
};
