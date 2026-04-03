/**
 * Re-export security config from centralized configuration.
 * Kept for backward compatibility with existing imports.
 */
import { security } from './index.js';

export const SECURITY_CONFIG = Object.freeze({
  MAX_LOGIN_ATTEMPTS: security.maxLoginAttempts,
  LOCK_TIME:          security.lockTime,
});
