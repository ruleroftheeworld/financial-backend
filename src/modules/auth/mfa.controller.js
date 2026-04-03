import * as mfaService from './mfa.service.js';
import { successResponse } from '../../shared/utils/response.js';

export const setupMfa = async (req, res, next) => {
  try {
    const result = await mfaService.setupMfa(req.user.id);
    return successResponse(res, result, 'MFA setup initiated');
  } catch (err) {
    next(err);
  }
};

export const verifyMfa = async (req, res, next) => {
  try {
    const { code } = req.body;
    await mfaService.verifyMfa(req.user.id, code);
    return successResponse(res, {}, 'MFA successfully enabled');
  } catch (err) {
    next(err);
  }
};
