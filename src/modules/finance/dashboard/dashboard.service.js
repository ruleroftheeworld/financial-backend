/**
 * dashboard.service.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Financial analytics: aggregated at the SQL/Prisma level — no data is
 * returned to Node.js for arithmetic. Amounts in responses are strings
 * (serialised from Prisma Decimal) to avoid IEEE-754 drift.
 *
 * HARDENING CHANGES:
 *
 *  Step 7 — Cache Consistency:
 *    Previous implementation used `redisClient.keys('dashboard:{userId}:*')`
 *    which is O(N) over the entire keyspace and blocks the Redis event loop.
 *    In production with thousands of users this can cause latency spikes or
 *    Redis timeouts under load.
 *
 *    NEW APPROACH — Cache Generation Counter:
 *      • Each user has a generation counter: `dashboard:gen:{userId}`.
 *      • All cache keys include the current generation:
 *          `dashboard:{userId}:{gen}:{suffix}`
 *      • To invalidate: INCR the counter (O(1)). All old keys are now
 *        unreachable and will expire naturally via their TTL.
 *      • No KEYS, SCAN, or DEL-many needed. Zero blocking.
 *
 *  Step 7 — Cache Fallback:
 *    Cache read failures (Redis unavailable) degrade gracefully — the query
 *    runs against PostgreSQL and the result is returned without caching.
 *    Cache write failures are logged and non-fatal.
 *
 *  SQL Injection Fix:
 *    Previous code used `prisma.raw(...)` inside tagged template literals for
 *    conditional date filters. `prisma.raw()` injects unescaped SQL strings —
 *    this is a SQL injection risk if startDate/endDate are user-controlled.
 *
 *    NEW APPROACH — Prisma.sql conditional fragments:
 *      `Prisma.sql` tagged templates are properly parameterized.
 *      `Prisma.empty` is used as a safe no-op fragment.
 *      All user input is passed as bind parameters, never interpolated.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { Prisma } from '@prisma/client';
import prisma from '../../../shared/config/database.js';
import redisClient from '../../../shared/config/redis.js';
import logger from '../../../shared/utils/logger.js';

const CACHE_TTL_SECONDS  = 300; // 5 minutes
const GEN_TTL_SECONDS    = 86_400; // Generation counter persists 24 h (longer than any cache entry)

// ─────────────────────────────────────────────
// Step 7: Cache Generation helpers
// ─────────────────────────────────────────────

/**
 * Returns the current cache generation for a user.
 * Creates the counter at 0 if it doesn't exist.
 * Falls back to '0' if Redis is unavailable — cache will be a miss,
 * which is safe (the query will run against PG).
 */
const getGeneration = async (userId) => {
  try {
    const gen = await redisClient.get(`dashboard:gen:${userId}`);
    return gen ?? '0';
  } catch {
    return '0'; // Cache degraded → treat as miss
  }
};

/** Builds a generation-scoped cache key. */
const cacheKey = (userId, gen, suffix) => `dashboard:${userId}:${gen}:${suffix}`;

const getFromCache = async (key) => {
  try {
    const raw = await redisClient.get(key);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null; // Cache miss — degrade gracefully
  }
};

const setCache = async (key, data) => {
  try {
    await redisClient.setex(key, CACHE_TTL_SECONDS, JSON.stringify(data));
  } catch (err) {
    logger.warn('DASHBOARD_CACHE_SET_FAILED', { key, error: err.message });
    // Non-fatal — the data is still returned to the caller, just not cached
  }
};

/**
 * Invalidates all cached dashboard data for a user by incrementing their
 * generation counter. This is O(1) — no KEYS/SCAN/DEL-many required.
 *
 * Old keys (with the previous generation number) become unreachable and
 * expire naturally via their CACHE_TTL_SECONDS TTL.
 *
 * Called by transaction.service.js after any mutation.
 */
export const invalidateDashboardCache = async (userId) => {
  try {
    // INCR is atomic — safe under concurrent requests
    await redisClient.incr(`dashboard:gen:${userId}`);
    // Refresh the TTL so the counter doesn't expire while there are active sessions
    await redisClient.expire(`dashboard:gen:${userId}`, GEN_TTL_SECONDS);
    logger.debug('DASHBOARD_CACHE_INVALIDATED', { userId });
  } catch (err) {
    // Non-fatal — next read will be a cache miss and query PG directly
    logger.warn('DASHBOARD_CACHE_INVALIDATION_FAILED', { userId, error: err.message });
  }
};

// ─────────────────────────────────────────────
// SQL Injection Fix: Safe date filter builders
// ─────────────────────────────────────────────

/**
 * Returns a Prisma.sql fragment for a date filter, or Prisma.empty.
 * All values are passed as bind parameters — never interpolated as raw SQL.
 */
const startDateFilter = (startDate) =>
  startDate ? Prisma.sql`AND date >= ${new Date(startDate)}` : Prisma.empty;

const endDateFilter = (endDate) =>
  endDate ? Prisma.sql`AND date <= ${new Date(endDate)}` : Prisma.empty;

// ─────────────────────────────────────────────
// SUMMARY — total income, expense, net balance
// ─────────────────────────────────────────────
export const getSummary = async (userId, { startDate, endDate } = {}) => {
  const gen    = await getGeneration(userId);
  const key    = cacheKey(userId, gen, `summary:${startDate || 'all'}:${endDate || 'all'}`);
  const cached = await getFromCache(key);
  if (cached) return { ...cached, cached: true };

  const dateFilter = buildDateFilter(startDate, endDate);

  // Single-pass aggregation using Prisma groupBy
  const rows = await prisma.transaction.groupBy({
    by:     ['type'],
    where:  { userId, deletedAt: null, ...dateFilter },
    _sum:   { amount: true },
    _count: { id: true },
  });

  let totalIncome  = '0.00';
  let totalExpense = '0.00';
  let incomeCount  = 0;
  let expenseCount = 0;

  for (const row of rows) {
    const sum = row._sum.amount?.toString() || '0';
    if (row.type === 'INCOME') {
      totalIncome = sum;
      incomeCount = row._count.id;
    } else if (row.type === 'EXPENSE') {
      totalExpense = sum;
      expenseCount = row._count.id;
    }
  }

  // Net balance — computed in PostgreSQL using parameterized fragments (no injection risk)
  const netResult = await prisma.$queryRaw`
    SELECT
      COALESCE(SUM(CASE WHEN type = 'INCOME'  THEN amount ELSE 0 END), 0)
      - COALESCE(SUM(CASE WHEN type = 'EXPENSE' THEN amount ELSE 0 END), 0)
      AS net_balance
    FROM transactions
    WHERE "userId"    = ${userId}
      AND "deletedAt" IS NULL
      ${startDateFilter(startDate)}
      ${endDateFilter(endDate)}
  `;

  const netBalance = netResult[0]?.net_balance?.toString() || '0.00';

  const result = {
    totalIncome,
    totalExpense,
    netBalance,
    transactionCounts: {
      income:  incomeCount,
      expense: expenseCount,
      total:   incomeCount + expenseCount,
    },
    period: {
      startDate: startDate || null,
      endDate:   endDate   || null,
    },
  };

  await setCache(key, result);
  return result;
};

// ─────────────────────────────────────────────
// CATEGORY BREAKDOWN
// ─────────────────────────────────────────────
export const getCategoryBreakdown = async (userId, { type, startDate, endDate } = {}) => {
  const gen    = await getGeneration(userId);
  const key    = cacheKey(userId, gen, `categories:${type || 'all'}:${startDate || 'all'}:${endDate || 'all'}`);
  const cached = await getFromCache(key);
  if (cached) return { ...cached, cached: true };

  const where = {
    userId,
    deletedAt: null,
    ...(type && { type }),
    ...buildDateFilter(startDate, endDate),
  };

  const rows = await prisma.transaction.groupBy({
    by:      ['categoryId', 'type'],
    where,
    _sum:    { amount: true },
    _count:  { id: true },
    orderBy: { _sum: { amount: 'desc' } },
  });

  const categoryIds = [...new Set(rows.map((r) => r.categoryId).filter(Boolean))];
  const categories  = categoryIds.length
    ? await prisma.category.findMany({
        where:  { id: { in: categoryIds } },
        select: { id: true, name: true, color: true, icon: true },
      })
    : [];

  const catMap = Object.fromEntries(categories.map((c) => [c.id, c]));

  const breakdown = rows.map((row) => ({
    categoryId:   row.categoryId,
    categoryName: catMap[row.categoryId]?.name  || 'Uncategorized',
    color:        catMap[row.categoryId]?.color  || '#9E9E9E',
    icon:         catMap[row.categoryId]?.icon   || '📁',
    type:         row.type,
    totalAmount:  row._sum.amount?.toString()    || '0.00',
    count:        row._count.id,
  }));

  const result = { breakdown, period: { startDate: startDate || null, endDate: endDate || null } };
  await setCache(key, result);
  return result;
};

// ─────────────────────────────────────────────
// MONTHLY TRENDS — last N months
// ─────────────────────────────────────────────
export const getMonthlyTrends = async (userId, { months = 12 } = {}) => {
  // Step 4: Cap months to prevent giant queries
  const safeMonths = Math.min(60, Math.max(1, parseInt(months) || 12));
  const gen        = await getGeneration(userId);
  const key        = cacheKey(userId, gen, `trends:${safeMonths}`);
  const cached     = await getFromCache(key);
  if (cached) return { ...cached, cached: true };

  // Fully parameterized — no prisma.raw() interpolation
  const rows = await prisma.$queryRaw`
    SELECT
      TO_CHAR(DATE_TRUNC('month', date), 'YYYY-MM') AS month,
      type,
      CAST(SUM(amount) AS TEXT)                     AS total,
      COUNT(*)::int                                  AS count
    FROM transactions
    WHERE "userId"    = ${userId}
      AND "deletedAt" IS NULL
      AND date >= NOW() - (INTERVAL '1 month' * ${safeMonths})
    GROUP BY DATE_TRUNC('month', date), type
    ORDER BY DATE_TRUNC('month', date) ASC
  `;

  // Pivot INCOME / EXPENSE into one row per month
  const monthMap = {};
  for (const row of rows) {
    if (!monthMap[row.month]) {
      monthMap[row.month] = {
        month:        row.month,
        income:       '0.00',
        expense:      '0.00',
        net:          '0.00',
        incomeCount:  0,
        expenseCount: 0,
      };
    }
    if (row.type === 'INCOME') {
      monthMap[row.month].income      = row.total;
      monthMap[row.month].incomeCount = row.count;
    } else {
      monthMap[row.month].expense      = row.total;
      monthMap[row.month].expenseCount = row.count;
    }
  }

  // Net computed in JS from string-decimal — only place we allow float math
  // because this is for display only (chart tooltips), not stored precision.
  const trends = Object.values(monthMap).map((m) => ({
    ...m,
    net: (parseFloat(m.income) - parseFloat(m.expense)).toFixed(2),
  }));

  const result = { trends, months: safeMonths };
  await setCache(key, result);
  return result;
};

// ─────────────────────────────────────────────
// RECENT TRANSACTIONS
// ─────────────────────────────────────────────
export const getRecentTransactions = async (userId, { limit = 10 } = {}) => {
  // Step 4: Hard cap
  const safeLimit = Math.min(50, Math.max(1, parseInt(limit) || 10));

  // Step 5+6: userId + deletedAt enforced at service layer
  const transactions = await prisma.transaction.findMany({
    where:   { userId, deletedAt: null },
    take:    safeLimit,
    orderBy: { date: 'desc' },
    include: {
      category: { select: { id: true, name: true, color: true, icon: true } },
      account:  { select: { id: true, name: true, type: true } },
    },
  });

  return { transactions, count: transactions.length };
};

// ─────────────────────────────────────────────
// Helper — Prisma WHERE date filter
// ─────────────────────────────────────────────
function buildDateFilter(startDate, endDate) {
  if (!startDate && !endDate) return {};
  const date = {};
  if (startDate) date.gte = new Date(startDate);
  if (endDate)   date.lte = new Date(endDate);
  return { date };
}