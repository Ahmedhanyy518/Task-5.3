import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { getSettings, updateRecoveryEmail } from '../controllers/settingController.js';

const router = Router();

// Reading and writing both require a logged-in user. The write is additionally
// covered by the app-wide anti-CSRF guard (app.js -> middleware/csrf.js): it must
// carry a valid `x-csrf-token` header matching the csrf cookie, which a forged
// cross-site form cannot supply, so a CSRF attempt is rejected with 403.
router.get('/', requireAuth, getSettings);
router.post('/recovery-email', requireAuth, updateRecoveryEmail);

export default router;
