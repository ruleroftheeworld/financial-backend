import * as userService from './user.service.js';
import { successResponse } from '../../shared/utils/response.js';


// ─────────────────────────────────────────────
// GET ALL USERS
// ─────────────────────────────────────────────
export const getAllUsers = async (req, res, next) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page)  || 1);
    const limit = Math.min(Math.max(1, parseInt(req.query.limit) || 20), 100);
    const role  = req.query.role;

    const result = await userService.getAllUsers({ page, limit, role });

    return successResponse(res, result, 'Users retrieved');

  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// GET USER BY ID
// ─────────────────────────────────────────────
export const getUserById = async (req, res, next) => {
  try {
    const user = await userService.getUserById(req.params.id);

    return successResponse(res, { user }, 'User retrieved');

  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// UPDATE USER ROLE
// ─────────────────────────────────────────────
export const updateUserRole = async (req, res, next) => {
  try {
    const { role } = req.body;

    const user = await userService.updateUserRole(
      req.params.id,
      role,
      req.user   // 🔐 passed for service-layer security checks
    );

    return successResponse(res, { user }, 'User role updated');

  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// DELETE USER
// ─────────────────────────────────────────────
export const deleteUser = async (req, res, next) => {
  try {
    const targetUserId = req.params.id;

    await userService.deleteUser(targetUserId, req.user);

    return successResponse(res, {}, 'User deleted');

  } catch (err) {
    next(err);
  }
};
