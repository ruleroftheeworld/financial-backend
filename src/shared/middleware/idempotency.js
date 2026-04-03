/**
 * idempotency.js
 * ─────────────────────────────────────────────────────────────────────────────
 * HTTP-level idempotency middleware (Step 2).
 *
 * Why two layers?
 *   The service layer handles idempotency at the DB/Redis level (per-operation).
 *   This middleware handles it at the HTTP level — it short-circuits the entire
 *   request pipeline and replays the original HTTP response body + status code.
 *   This covers cases where the service already completed but the response was
 *   lost in transit (network timeout, client disconnect, etc.).
 *
 * How it works:
 *   1. Reads the `Idempotency-Key` header (must be a UUID ≤ 128 chars).
 *   2. Checks Redis for a stored response under `idem:http:{userId}:{key}`.
 *   3. If found → returns the cached response with `Idempotency-Replayed: true`.
 *   4. If a concurrent request with the same key is in-flight → 409.
 *   5. If new → monkey-patches res.json to capture and cache the response
 *      after the request completes successfully (2xx only).
 *
 * Scope:
 *   • Keyed per authenticated user — two different users may reuse the same
 *     Idempotency-Key string without conflict.
 *   • Only applies when the `Idempotency-Key` header is present.
 *   • Only caches 2xx responses (errors are never replayed).
 *   • Designed for mutation routes: POST (create).
 *
 * Usage in routes:
 *   import { idempotency } from '../../shared/middleware/idempotency.js';
 *   router.post('/', idempotency, validate, ctrl.create);
 *
 * ─────────────────────────────────────────────────────────────────────────────
 */

import redisClient from '../config/redis.js';
import logger from '../utils/logger.js';
import AppError from '../utils/AppError.js';

// ─────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────
const RESPONSE_TTL  = 86_400; // 24 hours — how long cached responses live
const LOCK_TTL      = 30;     // 30 seconds — in-flight request lock
const MAX_KEY_LEN   = 128;    // Reject suspiciously long keys

// UUID v4 pattern — reject keys that look invalid to prevent cache-flooding attacks
const KEY_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const responseKey = (userId, key) => `idem:http:${userId}:${key}`;
const lockKey     = (userId, key) => `idem:http:lock:${userId}:${key}`;

// ─────────────────────────────────────────────
// Middleware factory
// ─────────────────────────────────────────────

/**
 * Express middleware. Mount AFTER `authenticate` so req.user is available.
 *
 * No-op if:
 *   - The Idempotency-Key header is absent (pass-through for reads / no key)
 *   - Redis is unavailable (fail-open — never block legitimate traffic)
 */
export const idempotency = async (req, res, next) => {
  const rawKey = req.headers['idempotency-key'];

  // No header → pass through silently (reads, or clients that don't send the header)
  if (!rawKey) return next();

  // ── Input validation ────────────────────────────────────────────────────
  if (rawKey.length > MAX_KEY_LEN) {
    return next(new AppError(
      `Idempotency-Key must be ≤ ${MAX_KEY_LEN} characters`,
      400,
      'IDEMPOTENCY_KEY_INVALID'
    ));
  }

  if (!KEY_PATTERN.test(rawKey)) {
    return next(new AppError(
      'Idempotency-Key must be a valid UUID v4',
      400,
      'IDEMPOTENCY_KEY_INVALID'
    ));
  }

  // Require authentication — idempotency is always user-scoped
  if (!req.user?.id) {
    return next(new AppError('Authentication required for idempotent requests', 401, 'AUTH_REQUIRED'));
  }

  const userId = req.user.id;
  const rKey   = responseKey(userId, rawKey);
  const lKey   = lockKey(userId, rawKey);

  try {
    // ── Step 1: Check for an existing cached response ─────────────────────
    const cached = await redisClient.get(rKey);
    if (cached) {
      logger.info('IDEMPOTENCY_HTTP_REPLAY', { userId, key: rawKey, path: req.originalUrl });
      const { statusCode, body } = JSON.parse(cached);
      res.set('Idempotency-Replayed', 'true');
      return res.status(statusCode).json(body);
    }

    // ── Step 2: Acquire in-flight lock ────────────────────────────────────
    // NX = only set if key does not exist; prevents two concurrent requests
    // with the same key from both executing
    const locked = await redisClient.set(lKey, '1', 'EX', LOCK_TTL, 'NX');
    if (!locked) {
      logger.warn('IDEMPOTENCY_HTTP_CONFLICT', { userId, key: rawKey, path: req.originalUrl });
      return next(new AppError(
        'A request with this Idempotency-Key is currently being processed. Retry in a moment.',
        409,
        'IDEMPOTENCY_CONFLICT'
      ));
    }

    // ── Step 3: Monkey-patch res.json to capture the response ─────────────
    // We wrap the original res.json so we can observe the status code and body
    // after the route handler runs, then cache them.
    const originalJson = res.json.bind(res);

    res.json = async function idempotencyCapture(body) {
      try {
        // Only cache successful responses — errors are never replayed
        if (res.statusCode >= 200 && res.statusCode < 300) {
          await redisClient.set(
            rKey,
            JSON.stringify({ statusCode: res.statusCode, body }),
            'EX', RESPONSE_TTL
          );
          logger.debug('IDEMPOTENCY_HTTP_STORED', { userId, key: rawKey, statusCode: res.statusCode });
        }
      } catch (err) {
        // Storage failure is non-fatal — log and continue
        logger.warn('IDEMPOTENCY_HTTP_STORE_FAILED', { userId, key: rawKey, error: err.message });
      } finally {
        // Always release the lock, regardless of cache storage success
        await redisClient.del(lKey).catch(() => {});
        // Restore the original function to prevent infinite recursion
        res.json = originalJson;
      }
      return originalJson(body);
    };

    // ── Error path: release lock if the request errors out ────────────────
    res.on('finish', async () => {
      // If the response was an error (non-2xx), release the lock so the client
      // can retry with the same key
      if (res.statusCode >= 400) {
        await redisClient.del(lKey).catch(() => {});
      }
    });

    next();

  } catch (err) {
    // Redis unavailable → fail-open, do NOT block the request
    logger.error('IDEMPOTENCY_MIDDLEWARE_ERROR', { userId, key: rawKey, error: err.message });
    next();
  }
};