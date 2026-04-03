/**
 * ownershipGuard.js
 * ─────────────────────────────────────────────────────────────────────────────
 * ABAC-style resource ownership enforcement.
 *
 * Prevents IDOR: even if an attacker guesses a valid transaction UUID, this
 * middleware confirms the resource belongs to the requesting user before the
 * service layer is reached.  The service layer also enforces ownership — this
 * is defense-in-depth (belt AND suspenders).
 *
 * Usage:
 *   router.patch('/:id', ownershipGuard('transaction'), ctrl.update);
 * ─────────────────────────────────────────────────────────────────────────────
 */

import prisma from '../config/database.js';
import AppError from '../utils/AppError.js';
import logger from '../utils/logger.js';
import { extractClientInfo } from '../utils/clientInfo.js';

const RESOURCE_MAP = {
  transaction: {
    model:     'transaction',
    ownerKey:  'userId',
    notFound:  'Transaction not found',
    code:      'TRANSACTION_NOT_FOUND',
  },
  account: {
    model:     'account',
    ownerKey:  'userId',
    notFound:  'Account not found',
    code:      'ACCOUNT_NOT_FOUND',
  },
  category: {
    model:     'category',
    ownerKey:  'userId',
    notFound:  'Category not found',
    code:      'CATEGORY_NOT_FOUND',
  },
};

/**
 * @param {string} resourceType  - Key in RESOURCE_MAP
 * @param {object} opts
 * @param {boolean} [opts.allowSystem] - Allow system resources (userId=null). Default false.
 */
export const ownershipGuard = (resourceType, opts = {}) => {
  const config = RESOURCE_MAP[resourceType];

  if (!config) {
    throw new Error(`ownershipGuard: unknown resource type "${resourceType}"`);
  }

  return async (req, res, next) => {
    try {
      if (!req.user) {
        throw new AppError('Authentication required', 401, 'AUTH_REQUIRED');
      }

      const resourceId = req.params.id;
      if (!resourceId) return next(); // no ID → let the service handle it

      const record = await prisma[config.model].findUnique({
        where:  { id: resourceId },
        select: { [config.ownerKey]: true, deletedAt: true },
      });

      if (!record) {
        throw new AppError(config.notFound, 404, config.code);
      }

      const isOwner  = record[config.ownerKey] === req.user.id;
      const isSystem = record[config.ownerKey] === null;
      const isAdmin  = req.user.role === 'ADMIN';

      // Allow: owner | admin | system resource (if opts.allowSystem)
      if (!isOwner && !isAdmin && !(isSystem && opts.allowSystem)) {
        const { ip } = extractClientInfo(req);
        logger.warn('OWNERSHIP_GUARD_DENIED', {
          userId:       req.user.id,
          resourceType,
          resourceId,
          resourceOwner: record[config.ownerKey],
          ip,
          path: req.originalUrl,
        });

        // Return same 404 as "not found" to prevent enumeration
        throw new AppError(config.notFound, 404, config.code);
      }

      next();
    } catch (err) {
      next(err);
    }
  };
};
