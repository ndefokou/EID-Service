import { Request, Response, NextFunction } from 'express';
import { JwtPayload } from 'jsonwebtoken'; // Import JwtPayload
import { User, IUser } from '../models/User';
import { logger } from '../../utils/logger';

// Get user profile
export const getUserProfile = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = (req.user as JwtPayload)?.id; // Explicitly cast req.user to JwtPayload
    if (!userId) {
      return res.status(401).json({ message: 'User not authenticated.' });
    }

    const user = await User.findById(userId).select('-password -refreshToken'); // Exclude sensitive info

    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    res.status(200).json({ user });
  } catch (error: any) {
    logger.error(`Error fetching user profile: ${error.message}`);
    next(error);
  }
};

// Update user profile
export const updateUserProfile = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = (req.user as JwtPayload)?.id; // Explicitly cast req.user to JwtPayload
    if (!userId) {
      return res.status(401).json({ message: 'User not authenticated.' });
    }

    const { username, email, eIdAttributes } = req.body;
    const updates: Partial<IUser> = {};

    if (username) updates.username = username;
    if (email) updates.email = email;
    if (eIdAttributes) updates.eIdAttributes = eIdAttributes;

    const updatedUser = await User.findByIdAndUpdate(userId, { $set: updates }, { new: true }).select('-password -refreshToken');

    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found.' });
    }

    logger.info(`User ${updatedUser.username} profile updated.`);
    res.status(200).json({ message: 'Profile updated successfully.', user: updatedUser });
  } catch (error: any) {
    logger.error(`Error updating user profile: ${error.message}`);
    next(error);
  }
};

// Delete user account
export const deleteUserAccount = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = (req.user as JwtPayload)?.id; // Explicitly cast req.user to JwtPayload
    if (!userId) {
      return res.status(401).json({ message: 'User not authenticated.' });
    }

    const deletedUser = await User.findByIdAndDelete(userId);

    if (!deletedUser) {
      return res.status(404).json({ message: 'User not found.' });
    }

    logger.info(`User ${deletedUser.username} account deleted.`);
    res.status(200).json({ message: 'Account deleted successfully.' });
  } catch (error: any) {
    logger.error(`Error deleting user account: ${error.message}`);
    next(error);
  }
};