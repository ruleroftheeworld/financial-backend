/**
 * @swagger
 * tags:
 *   name: Dashboard
 *   description: Financial analytics and reporting
 */

import { Router } from 'express';
import * as ctrl from './dashboard.controller.js';

const router = Router();

/**
 * @swagger
 * /finance/dashboard/summary:
 *   get:
 *     summary: Total income, expenses, net balance
 *     tags: [Dashboard]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: startDate
 *         schema: { type: string, format: date-time }
 *         description: Filter from this date
 *       - in: query
 *         name: endDate
 *         schema: { type: string, format: date-time }
 *         description: Filter to this date
 *     responses:
 *       200:
 *         description: Summary statistics
 *         content:
 *           application/json:
 *             example:
 *               success: true
 *               data:
 *                 totalIncome: "8500.00"
 *                 totalExpense: "3200.50"
 *                 netBalance: "5299.50"
 *                 transactionCounts:
 *                   income: 5
 *                   expense: 12
 *                   total: 17
 *                 cached: false
 */
router.get('/summary',            ctrl.getSummary);

/**
 * @swagger
 * /finance/dashboard/category-breakdown:
 *   get:
 *     summary: Spending/income grouped by category
 *     tags: [Dashboard]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: type
 *         schema: { type: string, enum: [INCOME, EXPENSE] }
 */
router.get('/category-breakdown', ctrl.getCategoryBreakdown);

/**
 * @swagger
 * /finance/dashboard/monthly-trends:
 *   get:
 *     summary: Month-by-month income and expense for the last N months
 *     tags: [Dashboard]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: months
 *         schema: { type: integer, default: 12, maximum: 24 }
 */
router.get('/monthly-trends',     ctrl.getMonthlyTrends);

/**
 * @swagger
 * /finance/dashboard/recent:
 *   get:
 *     summary: Most recent transactions
 *     tags: [Dashboard]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema: { type: integer, default: 10, maximum: 50 }
 */
router.get('/recent',             ctrl.getRecentTransactions);

export default router;
