/**
 * transaction.validation.js
 * ─────────────────────────────────────────────────────────────────────────────
 * express-validator rule sets for the Transaction resource.
 *
 * Financial validation principles:
 *  • Amounts are validated as strings matching a decimal pattern before being
 *    handed to Prisma (which maps them to PostgreSQL NUMERIC(20,2)).
 *  • Dates are normalized to UTC ISO-8601 strings.
 *  • No float coercion — amounts travel as strings end-to-end.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { body, query, param } from 'express-validator';

// ─────────────────────────────────────────────
// Reusable helpers
// ─────────────────────────────────────────────

const VALID_AMOUNT_REGEX = /^\d{1,9}(\.\d{1,2})?$/;
const MAX_AMOUNT = 999999999.99;

const amountRule = (field = 'amount') =>
  body(field)
    .notEmpty().withMessage(`${field} is required`)
    .isString().withMessage(`${field} must be a string`)
    .matches(VALID_AMOUNT_REGEX)
    .withMessage(`${field} must be a positive number with up to 2 decimal places (e.g. "1500.00")`)
    .custom((v) => {
      const n = parseFloat(v);
      if (n <= 0) throw new Error(`${field} must be greater than zero`);
      if (n > MAX_AMOUNT) throw new Error(`${field} must not exceed ${MAX_AMOUNT}`);
      return true;
    });

const currencyRule = (field = 'currency') =>
  body(field)
    .optional()
    .isISO4217().withMessage(`${field} must be a valid ISO 4217 currency code (e.g. USD)`);

// ─────────────────────────────────────────────
// CREATE rules
// ─────────────────────────────────────────────
export const createTransactionRules = [
  body('type')
    .notEmpty().withMessage('type is required')
    .isIn(['INCOME', 'EXPENSE']).withMessage('type must be INCOME or EXPENSE'),

  amountRule('amount'),
  currencyRule('currency'),

  body('description')
    .trim()
    .notEmpty().withMessage('description is required')
    .isLength({ min: 1, max: 255 }).withMessage('description must be 1–255 characters')
    .escape(),

  body('notes')
    .optional({ nullable: true })
    .isLength({ max: 1000 }).withMessage('notes must be at most 1000 characters')
    .trim()
    .escape(),

  body('date')
    .notEmpty().withMessage('date is required')
    .isISO8601().withMessage('date must be a valid ISO 8601 date-time')
    .toDate(),

  body('categoryId')
    .optional({ nullable: true })
    .isUUID().withMessage('categoryId must be a valid UUID'),

  body('accountId')
    .optional({ nullable: true })
    .isUUID().withMessage('accountId must be a valid UUID'),
];

// ─────────────────────────────────────────────
// UPDATE rules (all fields optional)
// ─────────────────────────────────────────────
export const updateTransactionRules = [
  body('type')
    .optional()
    .isIn(['INCOME', 'EXPENSE']).withMessage('type must be INCOME or EXPENSE'),

  body('amount')
    .optional()
    .isString().withMessage('amount must be a string')
    .matches(VALID_AMOUNT_REGEX)
    .withMessage('amount must be a positive number with up to 2 decimal places')
    .custom((v) => parseFloat(v) > 0)
    .withMessage('amount must be greater than zero'),

  currencyRule('currency'),

  body('description')
    .optional()
    .trim()
    .isLength({ min: 1, max: 255 }).withMessage('description must be 1–255 characters')
    .escape(),

  body('notes')
    .optional({ nullable: true })
    .isLength({ max: 1000 }).withMessage('notes must be at most 1000 characters')
    .trim()
    .escape(),

  body('date')
    .optional()
    .isISO8601().withMessage('date must be a valid ISO 8601 date-time')
    .toDate(),

  body('categoryId')
    .optional({ nullable: true })
    .isUUID().withMessage('categoryId must be a valid UUID'),

  body('accountId')
    .optional({ nullable: true })
    .isUUID().withMessage('accountId must be a valid UUID'),
];

// ─────────────────────────────────────────────
// LIST / FILTER query rules
// ─────────────────────────────────────────────
export const listTransactionRules = [
  query('page')
    .optional()
    .isInt({ min: 1 }).withMessage('page must be a positive integer')
    .toInt(),

  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 }).withMessage('limit must be between 1 and 100')
    .toInt(),

  query('type')
    .optional()
    .isIn(['INCOME', 'EXPENSE']).withMessage('type must be INCOME or EXPENSE'),

  query('categoryId')
    .optional()
    .isUUID().withMessage('categoryId must be a valid UUID'),

  query('accountId')
    .optional()
    .isUUID().withMessage('accountId must be a valid UUID'),

  query('startDate')
    .optional()
    .isISO8601().withMessage('startDate must be a valid ISO 8601 date')
    .toDate(),

  query('endDate')
    .optional()
    .isISO8601().withMessage('endDate must be a valid ISO 8601 date')
    .toDate(),

  query('sortBy')
    .optional()
    .isIn(['date', 'amount', 'createdAt']).withMessage('sortBy must be date, amount, or createdAt'),

  query('sortOrder')
    .optional()
    .isIn(['asc', 'desc']).withMessage('sortOrder must be asc or desc'),

  query('withDeleted')
    .optional()
    .isBoolean().withMessage('withDeleted must be a boolean'),
];

// ─────────────────────────────────────────────
// ID param rule (reused)
// ─────────────────────────────────────────────
export const transactionIdParamRule = [
  param('id')
    .notEmpty().withMessage('Transaction ID is required')
    .isUUID().withMessage('Transaction ID must be a valid UUID'),
];
