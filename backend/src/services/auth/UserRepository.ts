import { User, IUser } from '@root/src/models/User';
import { logger } from '@root/utils/logger';

export class UserRepository {
  /**
   * Finds a user by their ID.
   * @param id The user's ID.
   * @returns The user document or null if not found.
   */
  public async findById(id: string): Promise<IUser | null> {
    logger.debug(`Fetching user by ID: ${id}`);
    return User.findById(id);
  }

  /**
   * Finds a user by their username.
   * @param username The user's username.
   * @returns The user document or null if not found.
   */
  public async findByUsername(username: string): Promise<IUser | null> {
    logger.debug(`Fetching user by username: ${username}`);
    return User.findOne({ username });
  }

  /**
   * Finds a user by their email.
   * @param email The user's email.
   * @returns The user document or null if not found.
   */
  public async findByEmail(email: string): Promise<IUser | null> {
    logger.debug(`Fetching user by email: ${email}`);
    return User.findOne({ email });
  }

  /**
   * Finds a user by their refresh token.
   * @param refreshToken The refresh token.
   * @returns The user document or null if not found.
   */
  public async findByRefreshToken(refreshToken: string): Promise<IUser | null> {
    logger.debug('Fetching user by refresh token.');
    return User.findOne({ refreshToken });
  }

  /**
   * Creates a new user.
   * @param userData The user data to create the user.
   * @returns The newly created user document.
   */
  public async createUser(userData: Partial<IUser>): Promise<IUser> {
    logger.debug(`Creating new user with username: ${userData.username}`);
    const user = new User(userData);
    await user.save();
    return user;
  }

  /**
   * Updates a user's document.
   * @param user The user document to update.
   * @returns The updated user document.
   */
  public async save(user: IUser): Promise<IUser> {
    logger.debug(`Saving user document for ID: ${user._id}`);
    await user.save();
    return user;
  }
}