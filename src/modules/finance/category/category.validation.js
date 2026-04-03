import { body, param } from 'express-validator';

export const createCategoryRules = [
  body('name')
    .trim()
    .notEmpty().withMessage('name is required')
    .isLength({ min: 1, max: 50 }).withMessage('name must be 1–50 characters')
    .escape(),

  body('type')
    .notEmpty().withMessage('type is required')
    .isIn(['INCOME', 'EXPENSE']).withMessage('type must be INCOME or EXPENSE'),

  body('color')
    .optional({ nullable: true })
    .matches(/^#[0-9A-Fa-f]{6}$/).withMessage('color must be a hex color (e.g. #FF5733)'),

  body('icon')
    .optional({ nullable: true })
    .isLength({ max: 10 }).withMessage('icon must be at most 10 characters'),
];

export const updateCategoryRules = [
  body('name')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 }).withMessage('name must be 1–50 characters')
    .escape(),

  body('color')
    .optional({ nullable: true })
    .matches(/^#[0-9A-Fa-f]{6}$/).withMessage('color must be a hex color'),

  body('icon')
    .optional({ nullable: true })
    .isLength({ max: 10 }).withMessage('icon must be at most 10 characters'),
];

export const categoryIdParamRule = [
  param('id')
    .notEmpty().withMessage('Category ID is required')
    .isUUID().withMessage('Category ID must be a valid UUID'),
];
