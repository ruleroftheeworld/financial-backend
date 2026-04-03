/**
 * @swagger
 * tags:
 *   name: Categories
 *   description: Transaction category management
 */

import { Router } from 'express';
import { validate } from '../../../shared/middleware/validate.js';
import { createCategoryRules, updateCategoryRules, categoryIdParamRule } from './category.validation.js';
import * as ctrl from './category.controller.js';

const router = Router();

/**
 * @swagger
 * /finance/categories:
 *   get:
 *     summary: List categories (own + system defaults)
 *     tags: [Categories]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: type
 *         schema: { type: string, enum: [INCOME, EXPENSE] }
 *     responses:
 *       200:
 *         description: List of categories
 */
router.get('/', ctrl.listCategories);

/**
 * @swagger
 * /finance/categories/{id}:
 *   get:
 *     summary: Get a single category
 *     tags: [Categories]
 *     security:
 *       - bearerAuth: []
 */
router.get('/:id', categoryIdParamRule, validate, ctrl.getCategory);

/**
 * @swagger
 * /finance/categories:
 *   post:
 *     summary: Create a custom category
 *     tags: [Categories]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/CreateCategoryInput'
 *           example:
 *             name: "Side Hustle"
 *             type: "INCOME"
 *             color: "#4CAF50"
 *             icon: "💻"
 *     responses:
 *       201:
 *         description: Category created
 */
router.post('/', createCategoryRules, validate, ctrl.createCategory);

/**
 * @swagger
 * /finance/categories/{id}:
 *   patch:
 *     summary: Update a custom category (own only)
 *     tags: [Categories]
 *     security:
 *       - bearerAuth: []
 */
router.patch('/:id', categoryIdParamRule, updateCategoryRules, validate, ctrl.updateCategory);

/**
 * @swagger
 * /finance/categories/{id}:
 *   delete:
 *     summary: Delete a custom category (own only, must have no active transactions)
 *     tags: [Categories]
 *     security:
 *       - bearerAuth: []
 */
router.delete('/:id', categoryIdParamRule, validate, ctrl.deleteCategory);

export default router;
