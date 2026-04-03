import { body, param } from 'express-validator';

const ACCOUNT_TYPES = ['CHECKING', 'SAVINGS', 'CREDIT', 'INVESTMENT', 'WALLET'];

export const createAccountRules = [
  body('name')
    .trim()
    .notEmpty().withMessage('name is required')
    .isLength({ min: 1, max: 100 }).withMessage('name must be 1–100 characters')
    .escape(),

  body('type')
    .notEmpty().withMessage('type is required')
    .isIn(ACCOUNT_TYPES).withMessage(`type must be one of: ${ACCOUNT_TYPES.join(', ')}`),

  body('currency')
    .optional()
    .isISO4217().withMessage('currency must be a valid ISO 4217 code'),

  body('description')
    .optional({ nullable: true })
    .isLength({ max: 255 }).withMessage('description must be at most 255 characters')
    .trim()
    .escape(),

  body('isDefault')
    .optional()
    .isBoolean().withMessage('isDefault must be a boolean'),
];

export const updateAccountRules = [
  body('name')
    .optional()
    .trim()
    .isLength({ min: 1, max: 100 }).withMessage('name must be 1–100 characters')
    .escape(),

  body('description')
    .optional({ nullable: true })
    .isLength({ max: 255 }).withMessage('description must be at most 255 characters')
    .trim()
    .escape(),

  body('isDefault')
    .optional()
    .isBoolean().withMessage('isDefault must be a boolean'),
];

export const accountIdParamRule = [
  param('id')
    .notEmpty().withMessage('Account ID is required')
    .isUUID().withMessage('Account ID must be a valid UUID'),
];
