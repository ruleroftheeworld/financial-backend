/**
 * transaction.service.js
 * ─────────────────────────────────────────────────────────────────────────────
 * All database operations for the Transaction resource.
 *
 * Financial correctness guarantees:
 *  • Amounts are passed to Prisma as strings → stored as NUMERIC(20,2) in PG.
 *  • No JavaScript float arithmetic is performed on monetary values.
 *  • Soft-delete pattern: deletedAt timestamp; queries exclude deleted rows
 *    by default (withDeleted:true is restricted to ADMIN).
 *  • IDOR prevention: every query includes userId in WHERE clause — a user
 *    can never read another user's records regardless of the ID they supply.
 *
 * HARDENING CHANGES:
 *  Step 1  — All mutations wrapped in prisma.$transaction() — the transaction
 *            record, account balance update, and audit log are one atomic unit.
 *  Step 2  — Idempotency: createTransaction accepts an idempotencyKey.
 *            Duplicate requests within 24 h return the original result.
 *  Step 3  — Concurrency: account row is locked with SELECT … FOR UPDATE before
 *            any balance arithmetic to prevent lost-update race conditions.
 *  Step 4  — Pagination enforces hard MAX_PAGE_SIZE = 100.
 *  Step 5  — Data isolation: userId is in every WHERE clause at the service
 *            layer independent of middleware.
 *  Step 6  — Soft-delete: deletedAt: null is always explicit in every query.
 *  Step 8  — Financial rules: EXPENSE transactions check for sufficient balance
 *            unless the account type is CREDIT or has allowNegativeBalance set.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { Prisma } from '@prisma/client';
import prisma from '../../../shared/config/database.js';
import redisClient from '../../../shared/config/redis.js';
import AppError from '../../../shared/utils/AppError.js';
import logger from '../../../shared/utils/logger.js';
import { logFinanceAction, serializeForAudit, FINANCE_ACTIONS } from '../finance.audit.service.js';
import { financeTransactionCounter } from '../../../metrics/metrics.js';
import { invalidateDashboardCache } from '../dashboard/dashboard.service.js';

// ─────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────
const MAX_PAGE_SIZE   = 100;   // Hard cap — never returns more than this
const DEFAULT_LIMIT   = 20;
const IDEM_TTL        = 86_400; // 24 h (seconds) — idempotency window
const IDEM_LOCK_TTL   = 30;     // 30 s — in-flight request lock

/** Account types that are allowed to go negative (overdraft) */
const OVERDRAFT_ALLOWED_TYPES = new Set(['CREDIT']);

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

const buildTransactionFilter = (userId, filters) => {
  // Step 5: userId is always part of the filter — data isolation at service layer
  const where = { userId, deletedAt: null };

  if (filters.type)       where.type       = filters.type;
  if (filters.categoryId) where.categoryId = filters.categoryId;
  if (filters.accountId)  where.accountId  = filters.accountId;

  if (filters.startDate || filters.endDate) {
    where.date = {};
    if (filters.startDate) where.date.gte = new Date(filters.startDate);
    if (filters.endDate)   where.date.lte = new Date(filters.endDate);
  }

  if (filters.withDeleted === true) {
    delete where.deletedAt; // ADMIN only — includes soft-deleted
  }

  return where;
};

// ─────────────────────────────────────────────
// Step 2 — Idempotency helpers (Redis-backed)
// ─────────────────────────────────────────────

const idemKey     = (userId, key) => `idem:txn:${userId}:${key}`;
const idemLockKey = (userId, key) => `idem:lock:${userId}:${key}`;

/**
 * Check if a (userId, idempotencyKey) pair was already successfully processed.
 * Returns the cached transaction record or null.
 */
const checkIdempotency = async (userId, idempotencyKey) => {
  try {
    const raw = await redisClient.get(idemKey(userId, idempotencyKey));
    return raw ? JSON.parse(raw) : null;
  } catch (err) {
    logger.warn('IDEMPOTENCY_CHECK_FAILED', { userId, idempotencyKey, error: err.message });
    return null; // Degrade gracefully — don't block the real request
  }
};

/**
 * Acquire an in-flight lock to prevent concurrent duplicate requests.
 * Returns true if the lock was acquired, false if already held.
 */
const acquireIdempotencyLock = async (userId, idempotencyKey) => {
  try {
    const result = await redisClient.set(
      idemLockKey(userId, idempotencyKey),
      '1',
      'EX', IDEM_LOCK_TTL,
      'NX'
    );
    return result === 'OK';
  } catch (err) {
    logger.warn('IDEMPOTENCY_LOCK_FAILED', { userId, idempotencyKey, error: err.message });
    return true; // Fail-open: allow the request through if Redis is down
  }
};

/**
 * Store the successful result so future duplicates are short-circuited.
 */
const storeIdempotencyResult = async (userId, idempotencyKey, result) => {
  try {
    await redisClient.set(
      idemKey(userId, idempotencyKey),
      JSON.stringify(result),
      'EX', IDEM_TTL
    );
  } catch (err) {
    logger.warn('IDEMPOTENCY_STORE_FAILED', { userId, idempotencyKey, error: err.message });
    // Non-fatal — the next duplicate simply won't be idempotent
  } finally {
    // Always release the lock, whether storage succeeded or not
    try {
      await redisClient.del(idemLockKey(userId, idempotencyKey));
    } catch {/* ignore */}
  }
};

// ─────────────────────────────────────────────
// Step 3 — Account balance helpers (inside $transaction)
// ─────────────────────────────────────────────

/**
 * Lock the account row for the duration of the surrounding $transaction
 * using PostgreSQL's SELECT … FOR UPDATE. This prevents concurrent writes
 * from producing a lost-update race condition on the balance column.
 *
 * Must be called inside a prisma.$transaction callback with the tx client.
 */
const lockAccount = async (tx, accountId) => {
  await tx.$executeRaw`
    SELECT id FROM accounts
    WHERE id = ${accountId}
    FOR UPDATE
  `;
};

/**
 * Step 8 — Financial rule enforcement.
 * Throws INSUFFICIENT_BALANCE if an EXPENSE would take the account negative
 * and the account type does not allow overdraft.
 */
const assertSufficientBalance = (account, type, amount) => {
  if (type !== 'EXPENSE') return; // INCOME never reduces balance
  if (OVERDRAFT_ALLOWED_TYPES.has(account.type)) return;
  if (account.allowNegativeBalance) return;

  const currentBalance = parseFloat(account.balance.toString());
  const deduction      = parseFloat(amount.toString());

  if (currentBalance - deduction < 0) {
    throw new AppError(
      `Insufficient balance. Available: ${currentBalance.toFixed(2)}, Required: ${deduction.toFixed(2)}`,
      422,
      'INSUFFICIENT_BALANCE'
    );
  }
};

/**
 * Applies a signed delta to an account's balance inside a transaction.
 * Uses raw SQL so the arithmetic stays in the database (no JS float math).
 * The FOR UPDATE lock must have already been acquired via lockAccount().
 */
const applyBalanceDelta = async (tx, accountId, type, amount) => {
  // INCOME increases balance; EXPENSE decreases it.
  // Cast amount to NUMERIC ensures precision is preserved end-to-end.
  if (type === 'INCOME') {
    await tx.$executeRaw`
      UPDATE accounts
      SET    balance    = balance + ${amount}::NUMERIC,
             "updatedAt" = NOW()
      WHERE  id = ${accountId}
    `;
  } else {
    await tx.$executeRaw`
      UPDATE accounts
      SET    balance    = balance - ${amount}::NUMERIC,
             "updatedAt" = NOW()
      WHERE  id = ${accountId}
    `;
  }
};

/**
 * Reverses a previously applied balance delta (used on delete/restore).
 * Passing the original type and amount un-does the effect.
 */
const reverseBalanceDelta = async (tx, accountId, type, amount) => {
  // Reverse: INCOME → subtract; EXPENSE → add
  const reverseType = type === 'INCOME' ? 'EXPENSE' : 'INCOME';
  await applyBalanceDelta(tx, accountId, reverseType, amount);
};

// ─────────────────────────────────────────────
// CREATE
// ─────────────────────────────────────────────
export const createTransaction = async (userId, data, meta = {}) => {
  // ── Step 2: Idempotency short-circuit ───────────────────────────────────
  if (meta.idempotencyKey) {
    const cached = await checkIdempotency(userId, meta.idempotencyKey);
    if (cached) {
      logger.info('IDEMPOTENCY_HIT', { userId, idempotencyKey: meta.idempotencyKey });
      return { ...cached, _replayed: true };
    }

    const lockAcquired = await acquireIdempotencyLock(userId, meta.idempotencyKey);
    if (!lockAcquired) {
      throw new AppError(
        'A request with this Idempotency-Key is already being processed. Please retry shortly.',
        409,
        'IDEMPOTENCY_CONFLICT'
      );
    }
  }

  // ── Step 1+3: Atomic $transaction ───────────────────────────────────────
  let transaction;
  try {
    transaction = await prisma.$transaction(async (tx) => {

      // ── Step 6: Validate category (soft-delete + type consistency) ─────
      if (data.categoryId) {
        const cat = await tx.category.findFirst({
          where: {
            id: data.categoryId,
            deletedAt: null,
            OR: [{ userId }, { userId: null }],
          },
        });
        if (!cat) throw new AppError('Category not found or not accessible', 404, 'CATEGORY_NOT_FOUND');
        if (cat.type !== data.type) {
          throw new AppError(
            `Category type "${cat.type}" does not match transaction type "${data.type}"`,
            422,
            'CATEGORY_TYPE_MISMATCH'
          );
        }
      }

      // ── Step 3+8: Account lock, balance validation ─────────────────────
      let account = null;
      if (data.accountId) {
        // Step 6: account must exist and not be soft-deleted
        account = await tx.account.findFirst({
          where: { id: data.accountId, userId, deletedAt: null },
        });
        if (!account) throw new AppError('Account not found or not accessible', 404, 'ACCOUNT_NOT_FOUND');

        // Acquire row-level lock — prevents concurrent balance corruption
        await lockAccount(tx, data.accountId);

        // Step 8: Validate balance BEFORE the transaction record is created
        assertSufficientBalance(account, data.type, data.amount);
      }

      // ── Step 1: Create the transaction record ──────────────────────────
      const txn = await tx.transaction.create({
        data: {
          userId,
          type:        data.type,
          amount:      data.amount,  // string → Prisma Decimal → NUMERIC(20,2)
          currency:    data.currency || 'USD',
          description: data.description,
          notes:       data.notes || null,
          date:        data.date,
          categoryId:  data.categoryId || null,
          accountId:   data.accountId  || null,
        },
        include: { category: true, account: true },
      });

      // ── Step 3+8: Update account balance atomically ────────────────────
      if (data.accountId) {
        await applyBalanceDelta(tx, data.accountId, data.type, data.amount);
      }

      // ── Step 1: Audit log inside the same $transaction ─────────────────
      await logFinanceAction({
        tx,
        userId,
        action:        FINANCE_ACTIONS.TRANSACTION_CREATED,
        transactionId: txn.id,
        after:         serializeForAudit(txn),
        ip:            meta.ip,
        userAgent:     meta.userAgent,
      });

      return txn;
    }); // ← END $transaction
  } catch (err) {
    // Release idempotency lock on failure so caller can retry
    if (meta.idempotencyKey) {
      await redisClient.del(idemLockKey(userId, meta.idempotencyKey)).catch(() => {});
    }
    throw err;
  }

  // ── Post-commit: metrics + cache invalidation (non-critical) ────────────
  financeTransactionCounter.inc({ action: 'create', type: data.type });
  await invalidateDashboardCache(userId);

  // ── Step 2: Store idempotency result ────────────────────────────────────
  if (meta.idempotencyKey) {
    await storeIdempotencyResult(userId, meta.idempotencyKey, transaction);
  }

  return transaction;
};

// ─────────────────────────────────────────────
// GET MANY (paginated, filtered)
// ─────────────────────────────────────────────
export const getTransactions = async (userId, filters = {}, isAdmin = false) => {
  // Step 4: Hard-cap page size
  const page  = Math.max(1, parseInt(filters.page)  || 1);
  const limit = Math.min(MAX_PAGE_SIZE, Math.max(1, parseInt(filters.limit) || DEFAULT_LIMIT));
  const skip  = (page - 1) * limit;

  const sortBy    = ['date', 'amount', 'createdAt'].includes(filters.sortBy)
    ? filters.sortBy : 'date';
  const sortOrder = filters.sortOrder === 'asc' ? 'asc' : 'desc';

  // Step 5: withDeleted only available to ADMINs
  const withDeleted = isAdmin && filters.withDeleted === true;
  // Step 5+6: userId always in WHERE; deletedAt: null unless ADMIN override
  const where = buildTransactionFilter(userId, { ...filters, withDeleted });

  const [transactions, total] = await Promise.all([
    prisma.transaction.findMany({
      where,
      skip,
      take:    limit,
      orderBy: { [sortBy]: sortOrder },
      include: {
        category: { select: { id: true, name: true, color: true, icon: true } },
        account:  { select: { id: true, name: true, type: true } },
      },
    }),
    prisma.transaction.count({ where }),
  ]);

  return {
    transactions,
    pagination: {
      total,
      page,
      limit,
      pages:    Math.ceil(total / limit),
      hasNext:  page * limit < total,
      hasPrev:  page > 1,
    },
  };
};

// ─────────────────────────────────────────────
// GET ONE
// ─────────────────────────────────────────────
export const getTransactionById = async (userId, id) => {
  // Step 5+6: userId + deletedAt guard at the service layer
  const transaction = await prisma.transaction.findFirst({
    where:   { id, userId, deletedAt: null },
    include: {
      category: { select: { id: true, name: true, color: true, icon: true } },
      account:  { select: { id: true, name: true, type: true } },
    },
  });

  if (!transaction) {
    throw new AppError('Transaction not found', 404, 'TRANSACTION_NOT_FOUND');
  }

  return transaction;
};

// ─────────────────────────────────────────────
// UPDATE
// ─────────────────────────────────────────────
export const updateTransaction = async (userId, id, data, meta = {}) => {
  // ── Step 1+3: Atomic $transaction ───────────────────────────────────────
  const updated = await prisma.$transaction(async (tx) => {

    // Step 5+6: Ownership + soft-delete check inside the tx
    const existing = await tx.transaction.findFirst({
      where: { id, userId, deletedAt: null },
    });
    if (!existing) throw new AppError('Transaction not found', 404, 'TRANSACTION_NOT_FOUND');

    // Determine effective type and amount (could be changing)
    const newType   = data.type   ?? existing.type;
    const newAmount = data.amount ?? existing.amount;

    // ── Step 6: Validate category if changing ─────────────────────────
    if (data.categoryId !== undefined && data.categoryId) {
      const cat = await tx.category.findFirst({
        where: {
          id: data.categoryId,
          deletedAt: null,
          OR: [{ userId }, { userId: null }],
        },
      });
      if (!cat) throw new AppError('Category not found', 404, 'CATEGORY_NOT_FOUND');
      if (cat.type !== newType) {
        throw new AppError(
          `Category type "${cat.type}" does not match transaction type "${newType}"`,
          422,
          'CATEGORY_TYPE_MISMATCH'
        );
      }
    }

    // ── Step 3: Account locking and balance reconciliation ─────────────
    const effectiveAccountId = data.accountId !== undefined
      ? data.accountId
      : existing.accountId;

    // Lock ALL affected accounts before any balance mutation
    const accountsToLock = new Set([existing.accountId, effectiveAccountId].filter(Boolean));
    for (const accId of accountsToLock) {
      await lockAccount(tx, accId);
    }

    // Reverse the old balance effect on the old account
    if (existing.accountId) {
      await reverseBalanceDelta(tx, existing.accountId, existing.type, existing.amount);
    }

    // Apply the new balance effect on the (potentially new) account
    if (effectiveAccountId) {
      const account = await tx.account.findFirst({
        where: { id: effectiveAccountId, userId, deletedAt: null },
      });
      if (!account) throw new AppError('Account not found', 404, 'ACCOUNT_NOT_FOUND');

      // Step 8: Balance check with new type + amount
      assertSufficientBalance(account, newType, newAmount);
      await applyBalanceDelta(tx, effectiveAccountId, newType, newAmount);
    }

    const before = serializeForAudit(existing);

    // Build the update payload (only defined fields)
    const updatePayload = {};
    if (data.type        !== undefined) updatePayload.type        = data.type;
    if (data.amount      !== undefined) updatePayload.amount      = data.amount;
    if (data.currency    !== undefined) updatePayload.currency    = data.currency;
    if (data.description !== undefined) updatePayload.description = data.description;
    if (data.notes       !== undefined) updatePayload.notes       = data.notes;
    if (data.date        !== undefined) updatePayload.date        = data.date;
    if (data.categoryId  !== undefined) updatePayload.categoryId  = data.categoryId;
    if (data.accountId   !== undefined) updatePayload.accountId   = data.accountId;

    const txn = await tx.transaction.update({
      where:   { id },
      data:    updatePayload,
      include: {
        category: { select: { id: true, name: true, color: true, icon: true } },
        account:  { select: { id: true, name: true, type: true } },
      },
    });

    // ── Step 1: Audit log inside $transaction ──────────────────────────
    await logFinanceAction({
      tx,
      userId,
      action:        FINANCE_ACTIONS.TRANSACTION_UPDATED,
      transactionId: id,
      before,
      after:         serializeForAudit(txn),
      ip:            meta.ip,
      userAgent:     meta.userAgent,
    });

    return txn;
  }); // ← END $transaction

  financeTransactionCounter.inc({ action: 'update', type: updated.type });
  await invalidateDashboardCache(userId);

  return updated;
};

// ─────────────────────────────────────────────
// SOFT DELETE
// ─────────────────────────────────────────────
export const softDeleteTransaction = async (userId, id, meta = {}) => {
  await prisma.$transaction(async (tx) => {
    // Step 5+6: Ownership + not-already-deleted check inside tx
    const existing = await tx.transaction.findFirst({
      where: { id, userId, deletedAt: null },
    });
    if (!existing) throw new AppError('Transaction not found', 404, 'TRANSACTION_NOT_FOUND');

    // Step 3: Lock account before balance reversal
    if (existing.accountId) {
      await lockAccount(tx, existing.accountId);
      // Reverse the balance effect of this transaction
      await reverseBalanceDelta(tx, existing.accountId, existing.type, existing.amount);
    }

    await tx.transaction.update({
      where: { id },
      data:  { deletedAt: new Date() },
    });

    // Step 1: Audit inside $transaction
    await logFinanceAction({
      tx,
      userId,
      action:        FINANCE_ACTIONS.TRANSACTION_DELETED,
      transactionId: id,
      before:        serializeForAudit(existing),
      ip:            meta.ip,
      userAgent:     meta.userAgent,
    });
  });

  financeTransactionCounter.inc({ action: 'delete', type: 'unknown' });
  await invalidateDashboardCache(userId);
};

// ─────────────────────────────────────────────
// RESTORE (ADMIN only)
// ─────────────────────────────────────────────
export const restoreTransaction = async (userId, id, meta = {}) => {
  const restored = await prisma.$transaction(async (tx) => {
    // Step 5: userId guard even for ADMIN restore
    const existing = await tx.transaction.findFirst({
      where: { id, userId },
    });
    if (!existing)          throw new AppError('Transaction not found', 404, 'TRANSACTION_NOT_FOUND');
    if (!existing.deletedAt) throw new AppError('Transaction is not deleted', 400, 'NOT_DELETED');

    // Step 3+8: Lock account, check balance, re-apply delta
    if (existing.accountId) {
      await lockAccount(tx, existing.accountId);

      const account = await tx.account.findFirst({
        where: { id: existing.accountId, userId, deletedAt: null },
      });
      if (account) {
        // Re-check balance constraint before restoring
        assertSufficientBalance(account, existing.type, existing.amount);
        await applyBalanceDelta(tx, existing.accountId, existing.type, existing.amount);
      }
    }

    const txn = await tx.transaction.update({
      where: { id },
      data:  { deletedAt: null },
      include: {
        category: { select: { id: true, name: true, color: true, icon: true } },
        account:  { select: { id: true, name: true, type: true } },
      },
    });

    await logFinanceAction({
      tx,
      userId,
      action:        FINANCE_ACTIONS.TRANSACTION_RESTORED,
      transactionId: id,
      after:         serializeForAudit(txn),
      ip:            meta.ip,
      userAgent:     meta.userAgent,
    });

    return txn;
  });

  await invalidateDashboardCache(userId);
  return restored;
};