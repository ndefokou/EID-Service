import { User, IUser } from '@root/src/models/User';
import { logger } from '@root/utils/logger';
import bcrypt from 'bcryptjs';
import jwt, { Secret, SignOptions } from 'jsonwebtoken';
import { JWT_CONFIG } from '@root/config/jwt';
import { v4 as uuidv4 } from 'uuid'; // For generating unique IDs for the one-time token

export class AuthService {
  /**
   * Registers a new user with the provided credentials.
   * @param username The user's chosen username.
   * @param email The user's email address.
   * @param password The user's chosen password.
   * @returns The newly created user document.
   * @throws Error if the username or email already exists, or other registration failure.
   */
  public async registerUser(username: string, email: string, password: string): Promise<IUser> {
    logger.debug(`Attempting to register new user: ${username} with email: ${email}`);

    let user = await User.findOne({ email });
    if (user) {
      logger.warn(`Registration failed: User with email ${email} already exists.`);
      throw new Error('User with that email already exists.');
    }

    user = await User.findOne({ username });
    if (user) {
      logger.warn(`Registration failed: User with username ${username} already exists.`);
      throw new Error('User with that username already exists.');
    }

    user = new User({
      username,
      email,
      password,
    });

    await user.save();
    logger.info(`New user registered: ${user.username} (${user._id})`);
    return user;
  }

  /**
   * Authenticates a user and generates JWT and refresh tokens.
   * @param username The user's username.
   * @param password The user's password.
   * @returns An object containing the access token, refresh token, and user details.
   * @throws Error if authentication fails (invalid credentials).
   */
  public async loginUser(username: string, password: string): Promise<{ token: string; refreshToken: string; user: { id: string; username: string; email: string; }; }> {
    logger.debug(`Attempting to log in user: ${username}`);

    const user: IUser | null = await User.findOne({ username });
    if (!user) {
      logger.warn(`Login failed for ${username}: Invalid credentials.`);
      throw new Error('Invalid credentials.');
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      logger.warn(`Login failed for ${username}: Invalid credentials (password mismatch).`);
      throw new Error('Invalid credentials.');
    }

    // Now 'user' is guaranteed to be IUser
    const token = jwt.sign({ id: user._id.toString(), username: user.username }, JWT_CONFIG.SECRET as Secret, { expiresIn: JWT_CONFIG.EXPIRATION_TIME as any });
    const refreshToken = jwt.sign({ id: user._id.toString(), username: user.username }, JWT_CONFIG.REFRESH_SECRET as Secret, { expiresIn: JWT_CONFIG.REFRESH_EXPIRATION_TIME as any });

    user.refreshToken = refreshToken;
    await user.save();

    logger.info(`User ${user.username} logged in successfully.`);
    return {
      token,
      refreshToken,
      user: { id: user._id.toString(), username: user.username, email: user.email },
    };
  }

  /**
   * Refreshes an expired access token using a valid refresh token.
   * @param oldRefreshToken The refresh token provided by the client.
   * @returns A new access token.
   * @throws Error if the refresh token is invalid or expired.
   */
  public async refreshAccessToken(oldRefreshToken: string): Promise<string> {
    logger.debug('Attempting to refresh access token.');

    const user: IUser | null = await User.findOne({ refreshToken: oldRefreshToken });
    if (!user) {
      logger.warn('Token refresh failed: Invalid refresh token - user not found.');
      throw new Error('Invalid refresh token.');
    }

    return new Promise((resolve, reject) => {
      jwt.verify(oldRefreshToken, JWT_CONFIG.REFRESH_SECRET, (err, decodedUser) => {
        if (err) {
          logger.warn('Refresh token verification failed:', err.message);
          return reject(new Error('Invalid refresh token.'));
        }

        if (typeof decodedUser === 'string' || !decodedUser || !('id' in decodedUser)) {
          logger.warn('Refresh token verification failed: Invalid token payload.');
          return reject(new Error('Invalid token payload.'));
        }

        if (user._id.toString() !== decodedUser.id) {
          logger.warn(`Refresh token verification failed: Decoded user ID (${decodedUser.id}) does not match stored user ID (${user._id.toString()}).`);
          return reject(new Error('Invalid refresh token.'));
        }

        const newAccessToken = jwt.sign({ id: user._id.toString(), username: user.username }, JWT_CONFIG.SECRET as Secret, { expiresIn: JWT_CONFIG.EXPIRATION_TIME as any });
        logger.info(`New access token issued for user ${user.username}.`);
        resolve(newAccessToken);
      });
    });
  }

  /**
   * Logs out a user by clearing their refresh token.
   * @param userId The ID of the user to log out.
   * @throws Error if the user is not found.
   */
  public async logoutUser(userId: string): Promise<void> {
    logger.debug(`Attempting to log out user: ${userId}`);
    const user = await User.findById(userId);
    if (user) {
      user.refreshToken = undefined;
      await user.save();
      logger.info(`User ${user.username} (${user._id}) logged out.`);
    } else {
      logger.warn(`Logout failed: User with ID ${userId} not found.`);
      throw new Error('User not found.');
    }
  }

  /**
   * Retrieves a user's profile by ID.
   * @param userId The ID of the user to retrieve.
   * @returns The user's profile, excluding sensitive information.
   * @throws Error if the user is not found.
   */
  public async getUserProfile(userId: string): Promise<IUser> {
    logger.debug(`Attempting to fetch profile for user ID: ${userId}`);
    const user = await User.findById(userId).select('-password -refreshToken'); // Exclude sensitive info

    if (!user) {
      logger.warn(`User profile fetch failed: User with ID ${userId} not found.`);
      throw new Error('User not found.');
    }
    logger.info(`User profile fetched for ID: ${userId}`);
    return user;
  }

  /**
   * Generates a short-lived, one-time token for frontend redirection and immediate exchange.
   * This token should be used once by the frontend to request user session data securely.
   * It has a very short expiration to minimize exposure risk.
   * @param userId The ID of the user for whom the token is generated.
   * @returns A short-lived JWT token.
   * @throws Error if token generation fails.
   */
  public generateOneTimeFrontendToken(userId: string): string {
    logger.debug(`Generating one-time frontend token for user ID: ${userId}`);
    try {
      // Use a very short expiration time (e.g., 60 seconds)
      const expiresIn: SignOptions['expiresIn'] = '60s';
      const token = jwt.sign(
        { id: userId, type: 'frontend_redirect' },
        JWT_CONFIG.SECRET as Secret,
        { expiresIn, jwtid: uuidv4() } // jwtid for unique token identification
      );
      logger.info(`One-time frontend token generated for user ID: ${userId}`);
      return token;
    } catch (error) {
      logger.error(`Failed to generate one-time frontend token for user ID ${userId}:`, error);
      throw new Error('Failed to generate one-time frontend token.');
    }
  }
}