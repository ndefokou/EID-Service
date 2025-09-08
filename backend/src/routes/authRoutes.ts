import { Router } from 'express';
import * as authController from '../controllers/authController';
import { authenticateJWT } from '../middleware/authMiddleware';

const router = Router();

router.post('/logout', authenticateJWT, authController.logout); // Requires authentication
router.post('/refresh-token', authController.refreshToken); // To get a new access token using refresh token

// Protected route example
router.get('/profile', authenticateJWT, authController.getProfile);

export default router;