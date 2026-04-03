/**
 * transaction.controller.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Thin controller — validates request shape, delegates to service, formats
 * the response. No business logic lives here.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import * as txService from './transaction.service.js';
import { successResponse } from '../../../shared/utils/response.js';
import { extractClientInfo } from '../../../shared/utils/clientInfo.js';

// ─────────────────────────────────────────────
// POST /api/v1/finance/transactions
// ─────────────────────────────────────────────
export const createTransaction = async (req, res, next) => {
  try {
    const meta = extractClientInfo(req);
    const transaction = await txService.createTransaction(req.user.id, req.body, meta);
    return successResponse(res, { transaction }, 'Transaction created', 201);
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// GET /api/v1/finance/transactions
// ─────────────────────────────────────────────
export const listTransactions = async (req, res, next) => {
  try {
    const isAdmin = req.user.role === 'ADMIN';
    const result  = await txService.getTransactions(req.user.id, req.query, isAdmin);
    return successResponse(res, result, 'Transactions retrieved');
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// GET /api/v1/finance/transactions/:id
// ─────────────────────────────────────────────
export const getTransaction = async (req, res, next) => {
  try {
    const transaction = await txService.getTransactionById(req.user.id, req.params.id);
    return successResponse(res, { transaction }, 'Transaction retrieved');
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// PATCH /api/v1/finance/transactions/:id
// ─────────────────────────────────────────────
export const updateTransaction = async (req, res, next) => {
  try {
    const meta        = extractClientInfo(req);
    const transaction = await txService.updateTransaction(req.user.id, req.params.id, req.body, meta);
    return successResponse(res, { transaction }, 'Transaction updated');
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// DELETE /api/v1/finance/transactions/:id
// ─────────────────────────────────────────────
export const deleteTransaction = async (req, res, next) => {
  try {
    const meta = extractClientInfo(req);
    await txService.softDeleteTransaction(req.user.id, req.params.id, meta);
    return successResponse(res, null, 'Transaction deleted');
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// POST /api/v1/finance/transactions/:id/restore  (ADMIN only)
// ─────────────────────────────────────────────
export const restoreTransaction = async (req, res, next) => {
  try {
    const meta        = extractClientInfo(req);
    const transaction = await txService.restoreTransaction(req.user.id, req.params.id, meta);
    return successResponse(res, { transaction }, 'Transaction restored');
  } catch (err) {
    next(err);
  }
};
