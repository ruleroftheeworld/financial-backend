/**
 * category.service.js
 * ─────────────────────────────────────────────────────────────────────────────
 * A user can manage their own custom categories.
 * System categories (userId = null, isDefault = true) are visible to everyone
 * but cannot be modified or deleted by regular users.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import prisma from '../../../shared/config/database.js';
import AppError from '../../../shared/utils/AppError.js';
import { logFinanceAction, FINANCE_ACTIONS } from '../finance.audit.service.js';

// ─────────────────────────────────────────────
// LIST — returns system defaults + user's own categories
// ─────────────────────────────────────────────
export const getCategories = async (userId, filters = {}) => {
  const where = {
    deletedAt: null,
    OR: [
      { userId },       // user's own categories
      { userId: null }, // system defaults
    ],
  };

  if (filters.type) where.type = filters.type;

  const categories = await prisma.category.findMany({
    where,
    orderBy: [{ isDefault: 'desc' }, { name: 'asc' }],
    select: {
      id:        true,
      name:      true,
      type:      true,
      color:     true,
      icon:      true,
      isDefault: true,
      userId:    true,
    },
  });

  return categories;
};

// ─────────────────────────────────────────────
// GET ONE
// ─────────────────────────────────────────────
export const getCategoryById = async (userId, id) => {
  const category = await prisma.category.findFirst({
    where: {
      id,
      deletedAt: null,
      OR: [{ userId }, { userId: null }],
    },
  });
  if (!category) throw new AppError('Category not found', 404, 'CATEGORY_NOT_FOUND');
  return category;
};

// ─────────────────────────────────────────────
// CREATE
// ─────────────────────────────────────────────
export const createCategory = async (userId, data, meta = {}) => {
  const category = await prisma.category.create({
    data: {
      userId,
      name:      data.name,
      type:      data.type,
      color:     data.color || null,
      icon:      data.icon  || null,
      isDefault: false,
    },
  });

  await logFinanceAction({
    userId,
    action:    FINANCE_ACTIONS.CATEGORY_CREATED,
    after:     category,
    ip:        meta.ip,
    userAgent: meta.userAgent,
  });

  return category;
};

// ─────────────────────────────────────────────
// UPDATE — only own categories
// ─────────────────────────────────────────────
export const updateCategory = async (userId, id, data, meta = {}) => {
  const existing = await prisma.category.findFirst({
    where: { id, userId, deletedAt: null },
  });
  if (!existing) throw new AppError('Category not found or not modifiable', 404, 'CATEGORY_NOT_FOUND');

  const updated = await prisma.category.update({
    where: { id },
    data: {
      ...(data.name  !== undefined && { name:  data.name }),
      ...(data.color !== undefined && { color: data.color }),
      ...(data.icon  !== undefined && { icon:  data.icon }),
    },
  });

  await logFinanceAction({
    userId,
    action:    FINANCE_ACTIONS.CATEGORY_UPDATED,
    before:    existing,
    after:     updated,
    ip:        meta.ip,
    userAgent: meta.userAgent,
  });

  return updated;
};

// ─────────────────────────────────────────────
// SOFT DELETE — only own categories
// ─────────────────────────────────────────────
export const deleteCategory = async (userId, id, meta = {}) => {
  const existing = await prisma.category.findFirst({
    where: { id, userId, deletedAt: null },
  });
  if (!existing) throw new AppError('Category not found or not modifiable', 404, 'CATEGORY_NOT_FOUND');

  // Prevent deleting a category that still has active transactions
  const txCount = await prisma.transaction.count({
    where: { categoryId: id, deletedAt: null },
  });
  if (txCount > 0) {
    throw new AppError(
      `Cannot delete category with ${txCount} active transaction(s). Re-assign transactions first.`,
      409,
      'CATEGORY_IN_USE'
    );
  }

  await prisma.category.update({
    where: { id },
    data:  { deletedAt: new Date() },
  });

  await logFinanceAction({
    userId,
    action:    FINANCE_ACTIONS.CATEGORY_DELETED,
    before:    existing,
    ip:        meta.ip,
    userAgent: meta.userAgent,
  });
};
