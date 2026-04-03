/**
 * @swagger
 * tags:
 *   name: Accounts
 *   description: Financial account / wallet management
 */

import { Router } from 'express';
import { validate } from '../../../shared/middleware/validate.js';
import { createAccountRules, updateAccountRules, accountIdParamRule } from './account.validation.js';
import * as ctrl from './account.controller.js';

const router = Router();

router.get('/', ctrl.listAccounts);
router.get('/:id', accountIdParamRule, validate, ctrl.getAccount);
router.post('/', createAccountRules, validate, ctrl.createAccount);
router.patch('/:id', accountIdParamRule, updateAccountRules, validate, ctrl.updateAccount);
router.delete('/:id', accountIdParamRule, validate, ctrl.deleteAccount);

export default router;
