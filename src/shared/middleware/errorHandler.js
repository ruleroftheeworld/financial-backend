/**
 * errorHandler.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Centralized error handler.
 *
 * HARDENING (Step 9 — Error Standardization):
 *   All error responses now use a consistent envelope:
 *
 *     {
 *       "error": {
 *         "code":      "TRANSACTION_NOT_FOUND",
 *         "message":   "Transaction not found",
 *         "details":   {},          ← validation errors, field-level info
 *         "requestId": "uuid"       ← for log correlation
 *       }
 *     }
 *
 *   This is a clean break from the previous `{ success, code, message }` shape.
 *   Benefits:
 *     • `error` key makes it unambiguous that this is an error response.
 *     • `requestId` enables instant log correlation without digging through
 *       logs by timestamp.
 *     • `details` is a stable, structured slot for validation errors or
 *       domain-specific supplementary data — no more ad-hoc field additions.
 *     • Clients can reliably check `if (body.error)` with no ambiguity.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import logger from '../utils/logger.js';
import AppError from '../utils/AppError.js';
import { extractClientInfo } from '../utils/clientInfo.js';
import { app as appConfig } from '../config/index.js';

// ───────────────────────────────────────────────────────────
// Prisma error normalizer
// ───────────────────────────────────────────────────────────
const handlePrismaError = (err) => {
  switch (err.code) {
    case 'P2002':
      return new AppError(
        `A record with this ${err.meta?.target?.join(', ')} already exists`,
        409,
        'DUPLICATE_ENTRY'
      );
    case 'P2025':
      return new AppError('Record not found', 404, 'NOT_FOUND');
    case 'P2003':
      return new AppError('Related record not found', 400, 'FOREIGN_KEY_ERROR');
    case 'P2034':
      // Transaction conflict / serialization failure — safe to retry
      return new AppError(
        'Transaction conflict due to concurrent update. Please retry.',
        409,
        'TRANSACTION_CONFLICT'
      );
    default:
      return new AppError('Database operation failed', 500, 'DB_ERROR');
  }
};

// ───────────────────────────────────────────────────────────
// Build the standardized error response body
// ───────────────────────────────────────────────────────────

/**
 * Constructs the error envelope.
 *
 * @param {AppError}  error       - Normalized AppError instance
 * @param {object}    req         - Express request (for requestId)
 * @param {boolean}   isProduction
 * @param {Error}     originalErr - Raw error (for stack in dev)
 */
const buildErrorResponse = (error, req, isProduction, originalErr) => {
  const response = {
    error: {
      code:      error.code || 'INTERNAL_ERROR',
      message:   error.isOperational || !isProduction
        ? error.message
        : 'An unexpected error occurred',
      details:   error.errors || {},        // Validation errors, field-level info
      requestId: req.id || null,            // UUID injected in app.js
    },
  };

  // Include stack trace in non-production environments for developer ergonomics
  if (!isProduction && originalErr?.stack) {
    response.error._debug = {
      stack: originalErr.stack,
    };
  }

  return response;
};

// ───────────────────────────────────────────────────────────
// Main Error Handler Middleware
// ───────────────────────────────────────────────────────────
export const errorHandler = (err, req, res, next) => {
  let error = err;

  // ── 1. Normalize known error types ────────────────────────────────────────

  if (err.constructor?.name === 'PrismaClientKnownRequestError') {
    error = handlePrismaError(err);
  } else if (err.constructor?.name === 'PrismaClientValidationError') {
    error = new AppError('Invalid data provided to database operation', 400, 'DB_VALIDATION_ERROR');
  } else if (err.name === 'JsonWebTokenError') {
    error = new AppError('Invalid token', 401, 'TOKEN_INVALID');
  } else if (err.name === 'TokenExpiredError') {
    error = new AppError('Token has expired', 401, 'TOKEN_EXPIRED');
  } else if (!(error instanceof AppError)) {
    // Unknown error — hide internal details in production
    error = new AppError(
      err.message || 'Internal Server Error',
      500,
      'INTERNAL_ERROR'
    );
  }

  const statusCode   = error.statusCode || 500;
  const isProduction = appConfig.isProduction;

  // ── 2. Structured logging ─────────────────────────────────────────────────
  const logMeta = {
    requestId: req.id || null,
    path:      req.originalUrl,
    method:    req.method,
    ip:        extractClientInfo(req).ip,
    userId:    req.user?.id || null,
    code:      error.code,
  };

  if (statusCode >= 500) {
    logger.error('SERVER_ERROR', {
      ...logMeta,
      message: err.message,
      stack:   err.stack,
    });
  } else {
    logger.warn('CLIENT_ERROR', {
      ...logMeta,
      message: error.message,
    });
  }

  // ── 3. Send standardized response ─────────────────────────────────────────
  res.status(statusCode).json(buildErrorResponse(error, req, isProduction, err));
};

// ───────────────────────────────────────────────────────────
// 404 Handler
// ───────────────────────────────────────────────────────────
export const notFoundHandler = (req, res, next) => {
  next(
    new AppError(
      `Route ${req.method} ${req.originalUrl} not found`,
      404,
      'NOT_FOUND'
    )
  );
};