import * as svc from './account.service.js';
import { successResponse } from '../../../shared/utils/response.js';
import { extractClientInfo } from '../../../shared/utils/clientInfo.js';

export const listAccounts = async (req, res, next) => {
  try {
    const accounts = await svc.getAccounts(req.user.id);
    return successResponse(res, { accounts }, 'Accounts retrieved');
  } catch (err) { next(err); }
};

export const getAccount = async (req, res, next) => {
  try {
    const account = await svc.getAccountById(req.user.id, req.params.id);
    return successResponse(res, { account }, 'Account retrieved');
  } catch (err) { next(err); }
};

export const createAccount = async (req, res, next) => {
  try {
    const meta    = extractClientInfo(req);
    const account = await svc.createAccount(req.user.id, req.body, meta);
    return successResponse(res, { account }, 'Account created', 201);
  } catch (err) { next(err); }
};

export const updateAccount = async (req, res, next) => {
  try {
    const meta    = extractClientInfo(req);
    const account = await svc.updateAccount(req.user.id, req.params.id, req.body, meta);
    return successResponse(res, { account }, 'Account updated');
  } catch (err) { next(err); }
};

export const deleteAccount = async (req, res, next) => {
  try {
    const meta = extractClientInfo(req);
    await svc.deleteAccount(req.user.id, req.params.id, meta);
    return successResponse(res, null, 'Account deleted');
  } catch (err) { next(err); }
};
