import * as svc from './category.service.js';
import { successResponse } from '../../../shared/utils/response.js';
import { extractClientInfo } from '../../../shared/utils/clientInfo.js';

export const listCategories = async (req, res, next) => {
  try {
    const categories = await svc.getCategories(req.user.id, req.query);
    return successResponse(res, { categories }, 'Categories retrieved');
  } catch (err) { next(err); }
};

export const getCategory = async (req, res, next) => {
  try {
    const category = await svc.getCategoryById(req.user.id, req.params.id);
    return successResponse(res, { category }, 'Category retrieved');
  } catch (err) { next(err); }
};

export const createCategory = async (req, res, next) => {
  try {
    const meta     = extractClientInfo(req);
    const category = await svc.createCategory(req.user.id, req.body, meta);
    return successResponse(res, { category }, 'Category created', 201);
  } catch (err) { next(err); }
};

export const updateCategory = async (req, res, next) => {
  try {
    const meta     = extractClientInfo(req);
    const category = await svc.updateCategory(req.user.id, req.params.id, req.body, meta);
    return successResponse(res, { category }, 'Category updated');
  } catch (err) { next(err); }
};

export const deleteCategory = async (req, res, next) => {
  try {
    const meta = extractClientInfo(req);
    await svc.deleteCategory(req.user.id, req.params.id, meta);
    return successResponse(res, null, 'Category deleted');
  } catch (err) { next(err); }
};
