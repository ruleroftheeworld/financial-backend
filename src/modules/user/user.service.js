import prisma from '../../shared/config/database.js';
import AppError from '../../shared/utils/AppError.js';
import logger from '../../shared/utils/logger.js';
import { logSecurityEvent } from '../auth/audit.service.js';

// Allowed roles (prevent invalid role injection)
const ALLOWED_ROLES = ['USER', 'ADMIN', 'SECURITY_ANALYST'];

// ───────────────────────────────────────────────────────────
// GET ALL USERS (PAGINATED)
// ───────────────────────────────────────────────────────────
export const getAllUsers = async ({ page = 1, limit = 20, role } = {}) => {
  // 🔐 Sanitize inputs
  page = Math.max(1, parseInt(page));
  limit = Math.min(100, Math.max(1, parseInt(limit))); // cap to prevent abuse

  const skip = (page - 1) * limit;

  if (role && !ALLOWED_ROLES.includes(role)) {
    throw new AppError('Invalid role filter', 400, 'VALIDATION_ERROR');
  }

  const where = role ? { role } : {};

  const [users, total] = await Promise.all([
    prisma.user.findMany({
      where,
      skip,
      take: limit,
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        createdAt: true,
      },
      orderBy: { createdAt: 'desc' },
    }),
    prisma.user.count({ where }),
  ]);

  return {
    users,
    pagination: {
      total,
      page,
      limit,
      pages: Math.ceil(total / limit),
    },
  };
};

// ───────────────────────────────────────────────────────────
// GET USER BY ID
// ───────────────────────────────────────────────────────────
export const getUserById = async (id) => {
  if (!id) {
    throw new AppError('Invalid user ID', 400, 'INVALID_ID');
  }

  const user = await prisma.user.findUnique({
    where: { id },
    select: {
      id: true,
      name: true,
      email: true,
      role: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  if (!user) {
    throw new AppError('User not found', 404, 'NOT_FOUND');
  }

  return user;
};

// ───────────────────────────────────────────────────────────
// UPDATE USER ROLE
// ───────────────────────────────────────────────────────────
export const updateUserRole = async (id, role, currentUser) => {
  if (!id || !role) {
    throw new AppError('Invalid input', 400, 'INVALID_INPUT');
  }

  // 🔐 Validate role
  if (!ALLOWED_ROLES.includes(role)) {
    throw new AppError('Invalid role', 400, 'INVALID_ROLE');
  }

  const user = await prisma.user.findUnique({ where: { id } });

  if (!user) {
    throw new AppError('User not found', 404, 'NOT_FOUND');
  }

  // 🔥 CRITICAL: Prevent self role change (privilege abuse)
  if (currentUser.id === id) {
    await logSecurityEvent({
      userId: currentUser.id,
      action: 'ROLE_CHANGE_SELF_DENIED',
      status: 'FAILURE',
      ip: null,
      userAgent: null,
      metadata: { targetUserId: id, attemptedRole: role },
    });
    throw new AppError('You cannot change your own role', 403, 'FORBIDDEN');
  }

  const previousRole = user.role;

  const updatedUser = await prisma.user.update({
    where: { id },
    data: { role },
    select: { id: true, name: true, email: true, role: true },
  });

  // 📋 AUDIT: Persistent audit trail for role changes
  await logSecurityEvent({
    userId: currentUser.id,
    action: 'USER_ROLE_CHANGED',
    status: 'SUCCESS',
    ip: null,
    userAgent: null,
    metadata: { targetUserId: id, previousRole, newRole: role },
  });

  logger.warn('ROLE_UPDATED', {
    targetUserId: id,
    previousRole,
    newRole: role,
    performedBy: currentUser.id,
  });

  return updatedUser;
};

// ───────────────────────────────────────────────────────────
// DELETE USER
// ───────────────────────────────────────────────────────────
export const deleteUser = async (id, currentUser) => {
  if (!id) {
    throw new AppError('Invalid user ID', 400, 'INVALID_ID');
  }

  const user = await prisma.user.findUnique({ where: { id } });

  if (!user) {
    throw new AppError('User not found', 404, 'NOT_FOUND');
  }

  // 🔥 CRITICAL: Prevent self-delete
  if (currentUser.id === id) {
    await logSecurityEvent({
      userId: currentUser.id,
      action: 'USER_DELETE_SELF_DENIED',
      status: 'FAILURE',
      ip: null,
      userAgent: null,
      metadata: { targetUserId: id },
    });
    throw new AppError('You cannot delete your own account', 403, 'FORBIDDEN');
  }

  const deletedEmail = user.email;
  const deletedRole = user.role;

  await prisma.user.delete({ where: { id } });

  // 📋 AUDIT: Persistent audit trail for user deletion
  await logSecurityEvent({
    userId: currentUser.id,
    action: 'USER_DELETED',
    status: 'SUCCESS',
    ip: null,
    userAgent: null,
    metadata: { deletedUserId: id, deletedEmail, deletedRole },
  });

  logger.warn('USER_DELETED', {
    deletedUserId: id,
    deletedEmail,
    performedBy: currentUser.id,
  });

  return { success: true };
};
