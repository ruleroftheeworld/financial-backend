import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import morgan from 'morgan';
import { apiLimiter, internalLimiter } from './shared/middleware/rateLimiter.js';
import hpp from 'hpp';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import { randomUUID } from 'crypto';

import config, { activeDefense as activeDefenseConfig } from './shared/config/index.js';

import authRoutes from './modules/auth/auth.routes.js';
import userRoutes, { internalRouter as internalUserRouter } from './modules/user/user.routes.js';
import analyticsRoutes from './modules/analytics/analytics.routes.js';
import mfaRoutes from './modules/auth/mfa.routes.js';
import auditRoutes from './modules/audit/audit.routes.js';

// ── Finance Module ────────────────────────────
import transactionRoutes from './modules/finance/transaction/transaction.routes.js';
import categoryRoutes    from './modules/finance/category/category.routes.js';
import accountRoutes     from './modules/finance/account/account.routes.js';
import dashboardRoutes   from './modules/finance/dashboard/dashboard.routes.js';

import { errorHandler, notFoundHandler } from './shared/middleware/errorHandler.js';
import { authenticate } from './shared/middleware/authenticate.js';
import logger from './shared/utils/logger.js';
import { register, requestCounter } from './metrics/metrics.js';
import { activeDefenseMiddleware } from './shared/middleware/activeDefender.js';
import { setupSwagger } from './shared/config/swagger.js';

const app = express();

// ─────────────────────────────────────────────
// TRUST PROXY
// ─────────────────────────────────────────────
// 🔒 SEC-05: Trust only 1 proxy hop (prevents X-Forwarded-For spoofing)
app.set('trust proxy', true);

// ─────────────────────────────────────────────
// REQUEST ID (for tracing)
// ─────────────────────────────────────────────
app.use((req, res, next) => {
  req.id = randomUUID();
  next();
});

// ─────────────────────────────────────────────
// SECURITY HEADERS
// ─────────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
  })
);

// ─────────────────────────────────────────────
// CORS — 🔐 SECURITY FIX: No unsafe wildcard fallback
// ─────────────────────────────────────────────
app.use(
  cors({
    origin: config.app.corsOrigin,
    credentials: true,
  })
);

// ─────────────────────────────────────────────
// BODY PARSING
// ─────────────────────────────────────────────
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// ─────────────────────────────────────────────
// COOKIE + COMPRESSION
// ─────────────────────────────────────────────
app.use(cookieParser());
app.use(compression());

// ─────────────────────────────────────────────
// SECURITY: HPP
// ─────────────────────────────────────────────
app.use(hpp());

// ─────────────────────────────────────────────
// LOGGING
// ─────────────────────────────────────────────
app.use(
  morgan('combined', {
    stream: { write: (msg) => logger.http(msg.trim()) },
    skip: () => config.app.nodeEnv === 'test',
  })
);

// ─────────────────────────────────────────────
// ACTIVE DEFENSE — Ban enforcement layer (BEFORE rate limiter)
// When ON:  banned IPs rejected at edge → zero processing cost
// When OFF: system degrades to stateless per-request rejection
// ─────────────────────────────────────────────
if (activeDefenseConfig.enabled) {
  app.use(activeDefenseMiddleware);
  logger.info('ACTIVE_DEFENDER_ENABLED', { mode: 'adaptive_blocking' });
} else {
  logger.info('ACTIVE_DEFENDER_DISABLED', { mode: 'per_request_rejection_only' });
}

// ─────────────────────────────────────────────
// RATE LIMITING
// ─────────────────────────────────────────────
app.use(apiLimiter);

// ─────────────────────────────────────────────
// GLOBAL REQUEST TRACKING (Prometheus)
// ─────────────────────────────────────────────
app.use((req, res, next) => {
  res.on('finish', () => {
    const route = req.route ? (req.baseUrl + req.route.path) : 'unknown_route';
    requestCounter.inc({ method: req.method, route, status: res.statusCode });
  });
  next();
});

// ─────────────────────────────────────────────
// HEALTH CHECK & METRICS
// ─────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

app.get('/metrics', async (req, res) => {
  try {
    res.set('Content-Type', register.contentType);
    res.send(await register.metrics());
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// ─────────────────────────────────────────────
// SWAGGER / OpenAPI
// ─────────────────────────────────────────────
setupSwagger(app);

// ─────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/mfa', mfaRoutes);
app.use('/api/v1/users', authenticate, userRoutes);
app.use('/api/v1/analytics', authenticate, analyticsRoutes);
app.use('/api/v1/audit', auditRoutes);

// ── Finance Module (all routes require authentication) ────────────────────────
app.use('/api/v1/finance/transactions', authenticate, transactionRoutes);
app.use('/api/v1/finance/categories',   authenticate, categoryRoutes);
app.use('/api/v1/finance/accounts',     authenticate, accountRoutes);
app.use('/api/v1/finance/dashboard',    authenticate, dashboardRoutes);

// ─────────────────────────────────────────────
// INTERNAL ROUTES — Zero Trust (service-to-service only)
// Chain: internalLimiter → internalAuth (inside router)
// Separate prefix prevents collision with /api/v1/users.
// ─────────────────────────────────────────────
app.use('/api/internal/users', internalLimiter, internalUserRouter);

// ─────────────────────────────────────────────
// ERROR HANDLING
// ─────────────────────────────────────────────
app.use(notFoundHandler);
app.use(errorHandler);

export default app;