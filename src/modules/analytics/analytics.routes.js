import { Router } from 'express';
import axios from 'axios';
import { authenticate } from '../../shared/middleware/authenticate.js';
import { authorizeRoles } from '../../shared/middleware/authorizeRoles.js';
import { authorizePolicy } from '../../shared/middleware/authorizePolicy.js';
import prisma from '../../shared/config/database.js';
import { successResponse } from '../../shared/utils/response.js';
import logger from '../../shared/utils/logger.js';
import { extractClientInfo } from '../../shared/utils/clientInfo.js';
import { internal as internalConfig } from '../../shared/config/index.js';

const router = Router();

// ─────────────────────────────────────────────
// Apply security middleware to every analytics route
// ─────────────────────────────────────────────
router.use(authenticate);
router.use(authorizeRoles('ADMIN', 'SECURITY_ANALYST'));

// ─────────────────────────────────────────────
// GET /summary
// ─────────────────────────────────────────────
router.get('/summary', authorizePolicy({ action: 'read', resource: 'analytics' }), async (req, res, next) => {
  try {
    const [totalUsers, roleBreakdown] = await Promise.all([
      prisma.user.count(),

      prisma.user.groupBy({
        by: ['role'],
        _count: { role: true },
      }),
    ]);

    const roles = roleBreakdown.reduce((acc, item) => {
      acc[item.role] = item._count.role;
      return acc;
    }, {});

    logger.info('ANALYTICS_ACCESSED', {
      userId: req.user.id,
      role:   req.user.role,
      ip:     extractClientInfo(req).ip,
      path:   req.originalUrl,
    });

    return successResponse(
      res,
      { totalUsers, roles },
      'Analytics summary retrieved'
    );

  } catch (err) {
    next(err);
  }
});

// ─────────────────────────────────────────────────────────────
// GET /internal-demo/:userId
// ─────────────────────────────────────────────────────────────
// ⚠️  DEMONSTRATION ONLY — shows how service-to-service calls
//    work using x-internal-token (Zero Trust pattern).
//    Accessible to ADMIN only; requires authenticated session.
// ─────────────────────────────────────────────────────────────
router.get(
  '/internal-demo/:userId',
  authorizeRoles('ADMIN'),
  async (req, res, next) => {
    try {
      const { userId } = req.params;
      const internalToken = internalConfig.serviceToken;

      if (!internalToken) {
        return res.status(503).json({
          success: false,
          message: 'INTERNAL_SERVICE_TOKEN not configured — demo unavailable',
        });
      }

      // Derive base URL from the current request so the demo works on any port
      const baseUrl = `${req.protocol}://${req.get('host')}`;
      const internalUrl = `${baseUrl}/api/internal/users/${userId}`;

      logger.info('INTERNAL_SERVICE_CALL_DEMO', {
        callerUserId: req.user.id,
        targetUserId: userId,
        url: internalUrl,
      });

      const { data } = await axios.get(internalUrl, {
        headers: {
          'x-internal-token': internalToken,
        },
        timeout: 5000,
      });

      return successResponse(res, data, 'Internal service call successful (demo)');

    } catch (err) {
      // Surface readable errors from the downstream call
      if (err.response) {
        return res.status(err.response.status).json({
          success: false,
          message: 'Internal service call failed',
          downstream: err.response.data,
        });
      }
      next(err);
    }
  }
);

export default router;
