/**
 * authorizeRoles.js
 * -----------------
 * Factory middleware for Role-Based Access Control (RBAC).
 *
 * Usage:
 *   import authorizeRoles from '../middleware/authorizeRoles.js';
 *
 *   router.get('/admin-only',  authenticate, authorizeRoles('ADMIN'),                   handler);
 *   router.get('/analysts',    authenticate, authorizeRoles('ADMIN','SECURITY_ANALYST'), handler);
 *
 * Contract:
 *   - Must run AFTER authenticate (req.user must be populated).
 *   - Returns 401 if req.user is missing (belt-and-suspenders guard).
 *   - Returns 403 with a structured JSON body for any role mismatch.
 *   - Logs every denial as a WARN so it surfaces in your SIEM/log pipeline.
 *   - Throws 500 if called with zero roles (configuration error, caught
 *     early in development rather than silently denying everyone).
 */

import AppError from '../utils/AppError.js';
import logger from '../utils/logger.js';
import { extractClientInfo } from '../utils/clientInfo.js';
import { logSecurityEvent } from '../../modules/auth/audit.service.js';
import { authorizationFailures } from '../../metrics/metrics.js';

// ─────────────────────────────────────────────
// Allowed role universe — single source of truth.
// Keep in sync with the Prisma Role enum.
// ─────────────────────────────────────────────
export const ROLES = Object.freeze({
  USER:             'USER',
  ADMIN:            'ADMIN',
  SECURITY_ANALYST: 'SECURITY_ANALYST',
});

const ROLE_HIERARCHY = {
  ADMIN: ['ADMIN', 'SECURITY_ANALYST', 'USER'],
  SECURITY_ANALYST: ['SECURITY_ANALYST'],
  USER: ['USER'],
};

/**
 * @param  {...string} allowedRolesInput  One or more values from ROLES.
 * @returns Express middleware function.
 */
export const authorizeRoles = (...allowedRolesInput) => {
  // ── Fail-fast: catch misconfigured routes at startup / first request ──
  if (!allowedRolesInput.length) {
    throw new Error(
      '[authorizeRoles] No roles supplied. ' +
      'You must pass at least one role, e.g. authorizeRoles("ADMIN").'
    );
  }

  const allowedRoles = allowedRolesInput.map(r => r.toUpperCase());

  const unknownRoles = allowedRoles.filter(
    (r) => !Object.values(ROLES).includes(r)
  );
  if (unknownRoles.length) {
    throw new Error(
      `[authorizeRoles] Unknown role(s): ${unknownRoles.join(', ')}. ` +
      `Valid roles are: ${Object.values(ROLES).join(', ')}.`
    );
  }

  // ── Return the actual middleware ──
  return (req, res, next) => {
    try {
      // 1. Ensure authenticate() ran before this middleware
      if (!req.user) {
        throw new AppError(
          'Authentication required before authorization',
          401,
          'AUTH_REQUIRED'
        );
      }

      // 2. Defensive: role field must be present on the user object
      if (!req.user.role && (!req.user.roles || !Array.isArray(req.user.roles) || !req.user.roles.length)) {
        throw new AppError(
          'User account has no role assigned',
          403,
          'ROLE_MISSING'
        );
      }

      // Multi-Role Support
      const userRolesRaw = Array.isArray(req.user.roles)
        ? req.user.roles
        : [req.user.role];

      // Normalize all roles
      const userRoles = userRolesRaw.map(r => r?.toUpperCase()).filter(Boolean);

      // Expand roles based on hierarchy
      const expandedUserRoles = new Set();
      userRoles.forEach(role => {
        if (ROLE_HIERARCHY[role]) {
          ROLE_HIERARCHY[role].forEach(r => expandedUserRoles.add(r));
        } else {
          expandedUserRoles.add(role);
        }
      });

      // 3. Optional ABAC hook (future use)
      if (req.resource && req.user) {
        // Do not enforce anything yet
        // Just leave this as an extension point
      }

      // 4. Default-deny: check membership
      // Allow access if ANY role matches allowedRoles
      const hasAccess = allowedRoles.some(allowedRole => expandedUserRoles.has(allowedRole));

      if (!hasAccess) {
        const clientInfo = extractClientInfo(req);

        logger.warn('RBAC_DENIED', {
          userId:       req.user.id,
          userRoles:    userRoles,
          allowedRoles,
          method:       req.method,
          path:         req.originalUrl,
          ip:           clientInfo.ip,
          requestId:    req.id,
        });

        // 📋 AUDIT: Persist RBAC denial for forensic analysis
        logSecurityEvent({
          userId: req.user.id,
          action: 'RBAC_ACCESS_DENIED',
          status: 'FAILURE',
          ip: clientInfo.ip,
          userAgent: clientInfo.userAgent,
          metadata: {
            userRoles,
            requiredRoles: allowedRoles,
            method: req.method,
            path: req.originalUrl,
          },
        });

        authorizationFailures.inc({ type: 'rbac' });
        throw new AppError(
          `Access denied. Required role(s): ${allowedRoles.join(' | ')}. ` +
          `Your role(s): ${userRoles.join(', ')}.`,
          403,
          'FORBIDDEN'
        );
      }

      // 5. Access granted — pass control to the next handler
      next();

    } catch (err) {
      next(err);
    }
  };
};

