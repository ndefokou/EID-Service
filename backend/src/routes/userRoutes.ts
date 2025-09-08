import { Router } from 'express';
import * as userController from '../controllers/userController';
import { authenticateJWT } from '../middleware/authMiddleware';

const router = Router();

// Get user profile (already defined in authController for now, but can be expanded here)
router.get('/profile', authenticateJWT, userController.getUserProfile);

// Update user profile
router.put('/profile', authenticateJWT, userController.updateUserProfile);

// Delete user account
router.delete('/account', authenticateJWT, userController.deleteUserAccount);

export default router;