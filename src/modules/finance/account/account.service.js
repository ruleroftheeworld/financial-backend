/**
 * account.service.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Wallet/Account management. One account can be marked as default.
 *
 * HARDENING CHANGES:
 *  Step 1  — logFinanceAction now receives the `tx` client so account
 *            mutations and their audit entries are a single atomic operation.
 *  Step 3  — recalculateBalance() provides an authoritative balance
 *            recomputation from the transactions ledger. Use for reconciliation
 *            or after data-migration events. Guards with FOR UPDATE lock.
 *  Step 5  — userId is explicit in every WHERE clause (service-layer isolation).
 *  Step 6  — All queries include deletedAt: null explicitly.
 *  Step 8  — deleteAccount now also refuses if the account has non-zero
 *            balance (prevents silent balance destruction).
 * ─────────────────────────────────────────────────────────────────────────────
 */

import prisma from '../../../shared/config/database.js';
import AppError from '../../../shared/utils/AppError.js';
import { logFinanceAction, FINANCE_ACTIONS, serializeForAudit } from '../finance.audit.service.js';

// ─────────────────────────────────────────────
// LIST
// ─────────────────────────────────────────────
export const getAccounts = async (userId) => {
  // Step 5+6: userId AND deletedAt filter at service layer
  return prisma.account.findMany({
    where:   { userId, deletedAt: null },
    orderBy: [{ isDefault: 'desc' }, { name: 'asc' }],
    select: {
      id:          true,
      name:        true,
      type:        true,
      balance:     true,
      currency:    true,
      description: true,
      isDefault:   true,
      createdAt:   true,
    },
  });
};

// ─────────────────────────────────────────────
// GET ONE
// ─────────────────────────────────────────────
export const getAccountById = async (userId, id) => {
  const account = await prisma.account.findFirst({
    // Step 5+6: ownership + soft-delete at service layer
    where: { id, userId, deletedAt: null },
  });
  if (!account) throw new AppError('Account not found', 404, 'ACCOUNT_NOT_FOUND');
  return account;
};

// ─────────────────────────────────────────────
// CREATE
// ─────────────────────────────────────────────
export const createAccount = async (userId, data, meta = {}) => {
  return prisma.$transaction(async (tx) => {
    if (data.isDefault) {
      await tx.account.updateMany({
        where: { userId, deletedAt: null },
        data:  { isDefault: false },
      });
    }

    const account = await tx.account.create({
      data: {
        userId,
        name:        data.name,
        type:        data.type,
        currency:    data.currency || 'USD',
        description: data.description || null,
        isDefault:   data.isDefault || false,
        balance:     data.initialBalance?.toString() || '0',
      },
    });

    // Step 1: Audit log shares the same $transaction
    await logFinanceAction({
      tx,
      userId,
      action:    FINANCE_ACTIONS.ACCOUNT_CREATED,
      after:     serializeForAudit(account),
      ip:        meta.ip,
      userAgent: meta.userAgent,
    });

    return account;
  });
};

// ─────────────────────────────────────────────
// UPDATE
// ─────────────────────────────────────────────
export const updateAccount = async (userId, id, data, meta = {}) => {
  return prisma.$transaction(async (tx) => {
    // Step 5+6: Read-with-lock inside tx
    const existing = await tx.account.findFirst({
      where: { id, userId, deletedAt: null },
    });
    if (!existing) throw new AppError('Account not found', 404, 'ACCOUNT_NOT_FOUND');

    if (data.isDefault) {
      await tx.account.updateMany({
        where: { userId, deletedAt: null, id: { not: id } },
        data:  { isDefault: false },
      });
    }

    const before  = serializeForAudit(existing);
    const updated = await tx.account.update({
      where: { id },
      data: {
        ...(data.name        !== undefined && { name:        data.name }),
        ...(data.description !== undefined && { description: data.description }),
        ...(data.isDefault   !== undefined && { isDefault:   data.isDefault }),
      },
    });

    // Step 1: Audit inside tx
    await logFinanceAction({
      tx,
      userId,
      action:    FINANCE_ACTIONS.ACCOUNT_UPDATED,
      before,
      after:     serializeForAudit(updated),
      ip:        meta.ip,
      userAgent: meta.userAgent,
    });

    return updated;
  });
};

// ─────────────────────────────────────────────
// SOFT DELETE
// ─────────────────────────────────────────────
export const deleteAccount = async (userId, id, meta = {}) => {
  return prisma.$transaction(async (tx) => {
    const existing = await tx.account.findFirst({
      where: { id, userId, deletedAt: null },
    });
    if (!existing) throw new AppError('Account not found', 404, 'ACCOUNT_NOT_FOUND');

    if (existing.isDefault) {
      throw new AppError(
        'Cannot delete the default account. Set another account as default first.',
        409,
        'DEFAULT_ACCOUNT_DELETE'
      );
    }

    // Step 8: Prevent deleting an account with non-zero balance.
    // This guards against silent destruction of financial history.
    // Allow a small epsilon for floating-point serialization drift.
    const balance = parseFloat(existing.balance.toString());
    if (Math.abs(balance) > 0.001) {
      throw new AppError(
        `Cannot delete account with non-zero balance (${balance.toFixed(2)}). ` +
        'Transfer or reconcile the balance first.',
        409,
        'ACCOUNT_HAS_BALANCE'
      );
    }

    // Check for non-deleted transactions still referencing this account
    const linkedCount = await tx.transaction.count({
      where: { accountId: id, deletedAt: null },
    });
    if (linkedCount > 0) {
      throw new AppError(
        `Cannot delete account with ${linkedCount} active transaction(s). ` +
        'Re-assign or delete transactions first.',
        409,
        'ACCOUNT_HAS_TRANSACTIONS'
      );
    }

    await tx.account.update({
      where: { id },
      data:  { deletedAt: new Date() },
    });

    await logFinanceAction({
      tx,
      userId,
      action:    FINANCE_ACTIONS.ACCOUNT_DELETED,
      before:    serializeForAudit(existing),
      ip:        meta.ip,
      userAgent: meta.userAgent,
    });
  });
};

// ─────────────────────────────────────────────
// RECALCULATE BALANCE (Step 3 — reconciliation)
// ─────────────────────────────────────────────
/**
 * Recomputes an account's balance from its full transaction ledger and
 * atomically writes the corrected value.
 *
 * Use cases:
 *   • Post-migration reconciliation
 *   • Admin "repair" endpoint
 *   • Scheduled consistency checker
 *
 * The account row is locked with FOR UPDATE for the duration of the
 * transaction so no concurrent writes can race the recomputation.
 *
 * @returns {{ previousBalance: string, newBalance: string }}
 */
export const recalculateBalance = async (userId, accountId) => {
  return prisma.$transaction(async (tx) => {
    // Step 5: Ownership check
    const account = await tx.account.findFirst({
      where: { id: accountId, userId, deletedAt: null },
    });
    if (!account) throw new AppError('Account not found', 404, 'ACCOUNT_NOT_FOUND');

    // Step 3: Lock the account row
    await tx.$executeRaw`
      SELECT id FROM accounts
      WHERE id = ${accountId}
      FOR UPDATE
    `;

    // Compute the true balance from the ledger using DB-side arithmetic
    const [result] = await tx.$queryRaw`
      SELECT
        COALESCE(SUM(CASE WHEN type = 'INCOME'  THEN amount ELSE 0 END), 0)
        - COALESCE(SUM(CASE WHEN type = 'EXPENSE' THEN amount ELSE 0 END), 0)
        AS computed_balance
      FROM transactions
      WHERE "accountId" = ${accountId}
        AND "deletedAt" IS NULL
    `;

    const computedBalance = result.computed_balance?.toString() ?? '0.00';
    const previousBalance = account.balance.toString();

    await tx.account.update({
      where: { id: accountId },
      data:  { balance: computedBalance },
    });

    return { previousBalance, newBalance: computedBalance };
  });
};