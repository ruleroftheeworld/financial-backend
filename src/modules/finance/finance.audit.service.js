/**
 * finance.audit.service.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Immutable audit trail for all financial mutations.
 *
 * Every CREATE / UPDATE / DELETE on a Transaction is recorded here with
 * a before/after JSON snapshot so the full change history is reconstructable.
 * This table is append-only — rows are never updated or deleted.
 *
 * HARDENING (Step 1 — Transactional Integrity):
 *   • All functions now accept an optional `tx` parameter (Prisma interactive
 *     transaction client). When `tx` is provided the audit write shares the
 *     same database transaction as the financial operation — if either side
 *     rolls back, both roll back. This eliminates the silent-audit-failure
 *     class of bugs where money moved but the trail was never written.
 *   • When `tx` is NOT provided (stand-alone calls) it falls back to the
 *     global `prisma` client — fully backward-compatible.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import prisma from '../../shared/config/database.js';
import logger from '../../shared/utils/logger.js';

// ─────────────────────────────────────────────
// Action constants — single source of truth
// ─────────────────────────────────────────────
export const FINANCE_ACTIONS = Object.freeze({
  TRANSACTION_CREATED:  'TRANSACTION_CREATED',
  TRANSACTION_UPDATED:  'TRANSACTION_UPDATED',
  TRANSACTION_DELETED:  'TRANSACTION_DELETED',
  TRANSACTION_RESTORED: 'TRANSACTION_RESTORED',
  ACCOUNT_CREATED:      'ACCOUNT_CREATED',
  ACCOUNT_UPDATED:      'ACCOUNT_UPDATED',
  ACCOUNT_DELETED:      'ACCOUNT_DELETED',
  CATEGORY_CREATED:     'CATEGORY_CREATED',
  CATEGORY_UPDATED:     'CATEGORY_UPDATED',
  CATEGORY_DELETED:     'CATEGORY_DELETED',
});

/**
 * Log a financial audit entry.
 *
 * @param {object}  opts
 * @param {object}  [opts.tx]             - Prisma transaction client (interactive tx).
 *                                          When supplied, the audit write is atomic
 *                                          with the surrounding financial operation.
 *                                          When omitted, uses the global prisma client.
 * @param {string}  opts.userId           - The acting user's ID
 * @param {string}  opts.action           - One of FINANCE_ACTIONS
 * @param {string}  [opts.transactionId]  - Related transaction (if applicable)
 * @param {object}  [opts.before]         - Snapshot before mutation
 * @param {object}  [opts.after]          - Snapshot after mutation
 * @param {string}  [opts.ip]             - Client IP address
 * @param {string}  [opts.userAgent]      - Client user-agent
 */
export const logFinanceAction = async ({
  tx,             // ← NEW: optional Prisma tx client
  userId,
  action,
  transactionId = null,
  before = null,
  after = null,
  ip = null,
  userAgent = null,
}) => {
  // Use the transaction client when inside a $transaction, otherwise fall back
  // to the global prisma instance. This makes the function work in both contexts
  // without callers needing to branch.
  const db = tx ?? prisma;

  try {
    await db.financeAuditLog.create({
      data: {
        userId,
        action,
        transactionId,
        before: before ? JSON.parse(JSON.stringify(before)) : undefined,
        after:  after  ? JSON.parse(JSON.stringify(after))  : undefined,
        ip,
        userAgent,
      },
    });
  } catch (err) {
    if (tx) {
      // ⚠️ Inside a $transaction — re-throw so the financial operation rolls back.
      // You MUST have an audit trail for every financial mutation.
      logger.error('FINANCE_AUDIT_LOG_FAILED_INSIDE_TX', {
        userId,
        action,
        transactionId,
        error: err.message,
      });
      throw err;
    }

    // Outside a $transaction — log and swallow (legacy stand-alone path).
    // This preserves backward-compatibility for non-financial callers
    // (e.g. account/category services that have their own $transaction wrappers).
    logger.error('FINANCE_AUDIT_LOG_FAILED', {
      userId,
      action,
      transactionId,
      error: err.message,
    });
  }
};

/**
 * Serialize a Prisma Decimal/Date record so it can safely be stored as JSON.
 * Prisma Decimal objects are not plain numbers — .toString() gives exact string.
 */
export const serializeForAudit = (record) => {
  if (!record) return null;
  return JSON.parse(
    JSON.stringify(record, (key, value) => {
      // Prisma Decimal → string (prevents float serialization)
      if (value !== null && typeof value === 'object' && typeof value.toFixed === 'function') {
        return value.toString();
      }
      return value;
    })
  );
};