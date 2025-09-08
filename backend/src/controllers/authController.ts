import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import jwt, { Secret, JwtPayload, SignOptions } from 'jsonwebtoken'; // Added JwtPayload, SignOptions
import { User, IUser } from '../models/User';
import { logger } from '@root/utils/logger'; // Adjusted path to use alias
import { JWT_CONFIG } from '@root/config/jwt'; // Adjusted path to use alias

// Register a new user

// Login a user

// Logout a user
export const logout = async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Assuming user is available from authenticateJWT middleware
    const user = (req as any).user;
    if (user) {
      const dbUser = await User.findById(user.id);
      if (dbUser) {
        dbUser.refreshToken = undefined;
        await dbUser.save();
        logger.info(`User ${dbUser.username} logged out.`);
      }
    }
    res.status(200).json({ message: 'Logged out successfully.' });
  } catch (error: any) {
    logger.error(`Error during user logout: ${error.message}`);
    next(error);
  }
};

// Refresh JWT token
export const refreshToken = async (req: Request, res: Response, next: NextFunction) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ message: 'Refresh token is required.' });
  }

  try {
    const user = await User.findOne({ refreshToken });
    if (!user) {
      return res.status(403).json({ message: 'Invalid refresh token.' });
    }

    jwt.verify(refreshToken, JWT_CONFIG.REFRESH_SECRET, (err: jwt.VerifyErrors | null, decodedUser: string | JwtPayload | undefined) => {
      if (err) {
        logger.warn('Refresh token verification failed:', err.message);
        return res.status(403).json({ message: 'Invalid refresh token.' });
      }

      // Ensure decodedUser is a JwtPayload and has an 'id' property
      if (typeof decodedUser === 'string' || !decodedUser || !('id' in decodedUser)) {
        return res.status(403).json({ message: 'Invalid token payload.' });
      }

      // Check if the decoded user ID matches the user found by refresh token
      if (user._id.toString() !== decodedUser.id) {
        return res.status(403).json({ message: 'Invalid refresh token.' });
      }

      const newAccessTokenSignOptions: SignOptions = { expiresIn: JWT_CONFIG.EXPIRATION_TIME as any };
      const newAccessToken = jwt.sign({ id: user._id.toString(), username: user.username }, JWT_CONFIG.SECRET, newAccessTokenSignOptions);
      logger.info(`New access token issued for user ${user.username}.`);
      res.status(200).json({ accessToken: newAccessToken });
    });
  } catch (error: any) {
    logger.error(`Error during token refresh: ${error.message}`);
    next(error);
  }
};

// Get user profile (example protected route)
export const getProfile = async (req: Request, res: Response, next: NextFunction) => {
  try {
    // User object is attached by authenticateJWT middleware
    const userId = (req as any).user.id;
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