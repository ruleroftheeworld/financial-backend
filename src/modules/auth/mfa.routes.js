import { Router } from 'express';
import * as mfaController from './mfa.controller.js';
import { authenticate } from '../../shared/middleware/authenticate.js';

const router = Router();
router.use(authenticate);

router.post('/setup', mfaController.setupMfa);
router.post('/verify', mfaController.verifyMfa);

export default router;
