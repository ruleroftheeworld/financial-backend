import * as svc from './dashboard.service.js';
import { successResponse } from '../../../shared/utils/response.js';

/**
 * GET /api/v1/finance/dashboard/summary
 * Query params: startDate?, endDate?
 */
export const getSummary = async (req, res, next) => {
  try {
    const { startDate, endDate } = req.query;
    const data = await svc.getSummary(req.user.id, { startDate, endDate });
    return successResponse(res, data, 'Dashboard summary retrieved');
  } catch (err) { next(err); }
};

/**
 * GET /api/v1/finance/dashboard/category-breakdown
 * Query params: type?, startDate?, endDate?
 */
export const getCategoryBreakdown = async (req, res, next) => {
  try {
    const { type, startDate, endDate } = req.query;
    const data = await svc.getCategoryBreakdown(req.user.id, { type, startDate, endDate });
    return successResponse(res, data, 'Category breakdown retrieved');
  } catch (err) { next(err); }
};

/**
 * GET /api/v1/finance/dashboard/monthly-trends
 * Query params: months? (default 12, max 24)
 */
export const getMonthlyTrends = async (req, res, next) => {
  try {
    const months = Math.min(24, Math.max(1, parseInt(req.query.months) || 12));
    const data   = await svc.getMonthlyTrends(req.user.id, { months });
    return successResponse(res, data, 'Monthly trends retrieved');
  } catch (err) { next(err); }
};

/**
 * GET /api/v1/finance/dashboard/recent
 * Query params: limit? (default 10, max 50)
 */
export const getRecentTransactions = async (req, res, next) => {
  try {
    const { limit } = req.query;
    const data = await svc.getRecentTransactions(req.user.id, { limit });
    return successResponse(res, data, 'Recent transactions retrieved');
  } catch (err) { next(err); }
};
