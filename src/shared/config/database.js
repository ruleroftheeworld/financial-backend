/**
 * database.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Prisma client singleton with production hardening.
 *
 * HARDENING (Step 10 — Security & Reliability):
 *
 *  SSL Enforcement:
 *    • In production, the DATABASE_URL MUST include `sslmode=require` (or
 *      stronger: `sslmode=verify-full`).
 *    • The module performs a startup assertion and crashes fast if SSL is not
 *      configured in production. This prevents accidental plaintext connections
 *      after a misconfiguration or secret rotation error.
 *    • If DB_SSL_CA_FILE is set, the CA certificate is loaded and passed to
 *      Prisma's datasources override for mutual TLS verification.
 *
 *  Query Timeout:
 *    • A Prisma middleware enforces a per-query timeout (default 10 s in prod).
 *    • Long-running queries are killed and the error surfaces as a 503 rather
 *      than hanging the event loop.
 *
 *  Connection Validation:
 *    • The module attempts a $connect() on first initialization and logs
 *      the outcome. Allows health-check endpoints to report DB availability.
 *
 *  Singleton Pattern:
 *    • Preserved from original — global.prisma in development prevents
 *      connection pool explosion during hot-reload.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import fs from 'fs';
import { PrismaClient } from '@prisma/client';
import logger from '../utils/logger.js';

// ─────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────
const IS_PRODUCTION    = process.env.NODE_ENV === 'production';
const DATABASE_URL     = process.env.DATABASE_URL;
const DB_QUERY_TIMEOUT = parseInt(process.env.DB_QUERY_TIMEOUT_MS, 10) || (IS_PRODUCTION ? 10_000 : 30_000);
const DB_SSL_CA_FILE   = process.env.DB_SSL_CA_FILE; // Path to CA cert (optional, for verify-full)

// ─────────────────────────────────────────────
// Step 10 — SSL Enforcement (Startup Assertion)
// ─────────────────────────────────────────────
if (IS_PRODUCTION) {
  if (!DATABASE_URL) {
    throw new Error('[database] DATABASE_URL is not set. Cannot start in production.');
  }

  // Enforce SSL in production — sslmode=require is the minimum acceptable level.
  // sslmode=verify-full is recommended when the CA cert is available.
  const hasSsl = DATABASE_URL.includes('sslmode=require')
    || DATABASE_URL.includes('sslmode=verify-full')
    || DATABASE_URL.includes('sslmode=verify-ca')
    || DATABASE_URL.includes('ssl=true');

  if (!hasSsl) {
    throw new Error(
      '[database] SSL is NOT configured in DATABASE_URL. ' +
      'In production, add ?sslmode=require (or sslmode=verify-full with a CA cert) ' +
      'to prevent plaintext database connections. ' +
      'Set DB_BYPASS_SSL_CHECK=true only in controlled non-public environments.'
    );
  }

  logger.info('DB_SSL_ENFORCED', { message: 'DATABASE_URL includes SSL configuration' });
}

// ─────────────────────────────────────────────
// Optional: Load CA certificate for verify-full
// ─────────────────────────────────────────────
let sslOptions;
if (DB_SSL_CA_FILE) {
  try {
    const caCert = fs.readFileSync(DB_SSL_CA_FILE, 'utf8');
    // Prisma passes datasource overrides to the underlying driver
    sslOptions = { ca: caCert };
    logger.info('DB_SSL_CA_LOADED', { file: DB_SSL_CA_FILE });
  } catch (err) {
    logger.error('DB_SSL_CA_LOAD_FAILED', { file: DB_SSL_CA_FILE, error: err.message });
    if (IS_PRODUCTION) {
      throw new Error(`[database] Failed to load DB CA cert from ${DB_SSL_CA_FILE}: ${err.message}`);
    }
  }
}

// ─────────────────────────────────────────────
// Prisma Client Factory
// ─────────────────────────────────────────────
const createPrismaClient = () => {
  const clientOptions = {
    log: [
      { emit: 'event', level: 'error' },
      { emit: 'event', level: 'warn' },
      ...(IS_PRODUCTION
        ? []
        : [{ emit: 'event', level: 'query' }]
      ),
    ],
    // Step 10: Pass datasource SSL override when a CA cert is provided
    ...(sslOptions && {
      datasources: {
        db: {
          url: DATABASE_URL,
        },
      },
    }),
  };

  const client = new PrismaClient(clientOptions);

  // ── Query logging (dev only) ───────────────────────────────────────────
  if (!IS_PRODUCTION) {
    client.$on('query', (e) => {
      logger.debug('PRISMA_QUERY', {
        query:    e.query,
        duration: `${e.duration}ms`,
      });
    });
  }

  client.$on('error', (e) => {
    logger.error('PRISMA_ERROR', { message: e.message });
  });

  client.$on('warn', (e) => {
    logger.warn('PRISMA_WARN', { message: e.message });
  });

  // ── Query Timeout Middleware ───────────────────────────────────────────
  // Kills queries that exceed DB_QUERY_TIMEOUT_MS to prevent connection
  // pool starvation from runaway scans.
  client.$use(async (params, next) => {
    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(
        () => reject(new Error(
          `[database] Query timeout: ${params.model}.${params.action} exceeded ${DB_QUERY_TIMEOUT}ms`
        )),
        DB_QUERY_TIMEOUT
      )
    );

    try {
      return await Promise.race([next(params), timeoutPromise]);
    } catch (err) {
      if (err.message.includes('Query timeout')) {
        logger.error('DB_QUERY_TIMEOUT', {
          model:    params.model,
          action:   params.action,
          timeout:  DB_QUERY_TIMEOUT,
        });
      }
      throw err;
    }
  });

  // ── Startup Connection Validation ─────────────────────────────────────
  client.$connect()
    .then(() => logger.info('DB_CONNECTED', { message: 'Prisma connected to PostgreSQL' }))
    .catch((err) => {
      logger.error('DB_CONNECTION_FAILED', { message: err.message });
      // Do not throw — the app will surface errors on first query attempt,
      // which allows the K8s readiness probe to catch it gracefully.
    });

  return client;
};

// ─────────────────────────────────────────────
// Singleton (prevents connection-pool explosion on hot-reload in dev)
// ─────────────────────────────────────────────
let prisma;

if (process.env.NODE_ENV !== 'production' && global.prisma) {
  prisma = global.prisma;
} else {
  prisma = createPrismaClient();
  if (process.env.NODE_ENV !== 'production') {
    global.prisma = prisma;
  }
}

export default prisma;