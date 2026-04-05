/**
 * transaction.routes.js
 *
 * HARDENING (Step 2 — Idempotency):
 *   • POST / now includes the `idempotency` middleware BEFORE validation.
 *     If the Idempotency-Key has been seen before, the middleware replays
 *     the original response without touching the service or database.
 *   • The Idempotency-Key is forwarded via res.locals so the controller
 *     can pass it to the service for the service-layer duplicate check
 *     (belt-and-suspenders: both HTTP-level and DB-level idempotency).
 */

import { Router } from 'express';
import { authorizeRoles } from '../../../shared/middleware/authorizeRoles.js';
import { validate } from '../../../shared/middleware/validate.js';
import { idempotency } from '../../../shared/middleware/idempotency.js';
import {
  createTransactionRules,
  updateTransactionRules,
  listTransactionRules,
  transactionIdParamRule,
} from './transaction.validation.js';
import * as ctrl from './transaction.controller.js';

const router = Router();

/**
 * @swagger
 * tags:
 *   name: Transactions
 *   description: Financial transaction management
 */

/**
 * @swagger
 * /finance/transactions:
 *   post:
 *     summary: Create a new transaction
 *     description: |
 *       Creates a financial transaction and atomically updates the linked
 *       account balance. Supports idempotent submission via the
 *       `Idempotency-Key` header (UUID v4). Duplicate requests within 24 h
 *       with the same key return the original response without side effects.
 *     tags: [Transactions]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: header
 *         name: Idempotency-Key
 *         required: false
 *         schema:
 *           type: string
 *           format: uuid
 *         description: |
 *           UUID v4 unique to this request. Repeat the same key to safely
 *           retry without creating duplicate transactions.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/CreateTransactionInput'
 *           example:
 *             type: "EXPENSE"
 *             amount: "49.99"
 *             description: "Grocery shopping"
 *             date: "2026-04-02T10:00:00Z"
 *             categoryId: "uuid-here"
 *             currency: "USD"
 *     responses:
 *       201:
 *         description: Transaction created
 *         headers:
 *           Idempotency-Replayed:
 *             schema:
 *               type: string
 *             description: Present with value 'true' when the response was replayed from cache
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/TransactionResponse'
 *       409:
 *         description: Idempotency conflict (same key already in-flight) or insufficient balance
 *       422:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/Unauthorized'
 */
router.post(
  '/',
  authorizeRoles('USER', 'ADMIN'),
  idempotency,              // Step 2: HTTP-level idempotency (must run after authenticate)
  createTransactionRules,
  validate,
  ctrl.createTransaction
);

/**
 * @swagger
 * /finance/transactions:
 *   get:
 *     summary: List transactions (paginated + filtered)
 *     tags: [Transactions]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema: { type: integer, default: 1 }
 *       - in: query
 *         name: limit
 *         schema: { type: integer, default: 20, maximum: 100 }
 *         description: Maximum 100. Larger values are silently capped.
 *       - in: query
 *         name: type
 *         schema: { type: string, enum: [INCOME, EXPENSE] }
 *       - in: query
 *         name: categoryId
 *         schema: { type: string, format: uuid }
 *       - in: query
 *         name: accountId
 *         schema: { type: string, format: uuid }
 *       - in: query
 *         name: startDate
 *         schema: { type: string, format: date-time }
 *       - in: query
 *         name: endDate
 *         schema: { type: string, format: date-time }
 *       - in: query
 *         name: sortBy
 *         schema: { type: string, enum: [date, amount, createdAt] }
 *       - in: query
 *         name: sortOrder
 *         schema: { type: string, enum: [asc, desc] }
 *     responses:
 *       200:
 *         description: Paginated transaction list
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/PaginatedTransactions'
 */
router.get(
  '/',
  listTransactionRules,
  validate,
  ctrl.listTransactions
);

/**
 * @swagger
 * /finance/transactions/{id}:
 *   get:
 *     summary: Get a single transaction by ID
 *     tags: [Transactions]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string, format: uuid }
 *     responses:
 *       200:
 *         description: Transaction found
 *       404:
 *         $ref: '#/components/responses/NotFound'
 */
router.get(
  '/:id',
  transactionIdParamRule,
  validate,
  ctrl.getTransaction
);

/**
 * @swagger
 * /finance/transactions/{id}:
 *   patch:
 *     summary: Update a transaction
 *     description: |
 *       Updates a transaction and atomically reconciles the account balance:
 *       the old balance effect is reversed and the new one applied in a
 *       single database transaction.
 *     tags: [Transactions]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string, format: uuid }
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/UpdateTransactionInput'
 *     responses:
 *       200:
 *         description: Transaction updated
 *       404:
 *         $ref: '#/components/responses/NotFound'
 */
router.patch(
  '/:id',
  authorizeRoles('USER', 'ADMIN'),
  transactionIdParamRule,
  updateTransactionRules,
  validate,
  ctrl.updateTransaction
);
/**
 * @swagger
 * /finance/transactions/{id}:
 *   delete:
 *     summary: Soft-delete a transaction
 *     description: |
 *       Soft-deletes the transaction (sets deletedAt) and atomically
 *       reverses its effect on the linked account balance.
 *     tags: [Transactions]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string, format: uuid }
 *     responses:
 *       200:
 *         description: Transaction deleted (soft)
 *       404:
 *         $ref: '#/components/responses/NotFound'
 */
router.delete(
  '/:id',
  authorizeRoles('USER', 'ADMIN'),
  transactionIdParamRule,
  validate,
  ctrl.deleteTransaction
);

/**
 * @swagger
 * /finance/transactions/{id}/restore:
 *   post:
 *     summary: Restore a soft-deleted transaction (ADMIN only)
 *     description: |
 *       Restores a soft-deleted transaction and re-applies its balance
 *       effect on the linked account atomically.
 *     tags: [Transactions]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string, format: uuid }
 *     responses:
 *       200:
 *         description: Transaction restored
 *       403:
 *         $ref: '#/components/responses/Forbidden'
 */
router.post(
  '/:id/restore',
  authorizeRoles('ADMIN'),
  transactionIdParamRule,
  validate,
  ctrl.restoreTransaction
);

export default router;