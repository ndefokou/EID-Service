import { v4 as uuidv4 } from 'uuid';
import { EidSession, IEidSession } from '@root/src/models/EidSession';
import { logger } from '@root/utils/logger';
import { UpdateQuery } from 'mongoose';
import validator from 'validator';
import { EID_CONFIG } from '@root/config/eid';

/**
 * Custom error class for session management failures
 */
export class SessionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SessionError';
  }
}

/**
 * Manages eID authentication sessions with Mongoose.
 * Handles session creation, retrieval, updates, expiration, and cleanup.
 */
export class SessionManager {
  private readonly SESSION_TIMEOUT_MS: number = EID_CONFIG.SESSION_TIMEOUT || 30 * 60 * 1000; // Default: 30 minutes
  private readonly MAX_RETRIES: number = EID_CONFIG.MAX_RETRIES || 3;
  private readonly RETRY_DELAY_MS: number = EID_CONFIG.RETRY_DELAY || 1000;

  constructor() {
    try {
      // Ensure MongoDB indexes for performance
      this.ensureIndexes();
      logger.info('SessionManager initialized', {
        sessionTimeoutMs: this.SESSION_TIMEOUT_MS,
        maxRetries: this.MAX_RETRIES,
        retryDelayMs: this.RETRY_DELAY_MS,
      });
    } catch (error) {
      const errorMessage = `Failed to initialize SessionManager: ${(error as Error).message}`;
      logger.error(errorMessage);
      throw new SessionError(errorMessage);
    }
  }

  /**
   * Ensures MongoDB indexes for efficient session queries and cleanup.
   * @private
   */
  private async ensureIndexes(): Promise<void> {
    try {
      await EidSession.collection.createIndexes([
        { key: { sessionId: 1 }, unique: true },
        { key: { createdAt: 1 }, expireAfterSeconds: this.SESSION_TIMEOUT_MS / 1000 }
      ]);
      logger.debug('MongoDB indexes ensured for EidSession');
    } catch (error) {
      logger.error(`Failed to create MongoDB indexes: ${(error as Error).message}`);
      throw new SessionError(`Failed to create indexes: ${(error as Error).message}`);
    }
  }

  /**
   * Creates a new eID session in the database.
   * @param userId The ID of the user initiating the session (nullable).
   * @param clientRedirectUrl The redirect URL for the frontend.
   * @param requestedAttributes List of attributes requested (optional).
   * @param loaRequested Requested Level of Assurance (optional).
   * @param eidTypeRequested Requested eID types (optional).
   * @param transactionAttestationRequest Transaction attestation data (optional).
   * @param ageVerificationRequested Flag for age verification (optional).
   * @param communityIdRequested Community ID for verification (optional).
   * @param eCardServerAddress eID server address override (optional).
   * @returns The created IEidSession document.
   * @throws SessionError on validation or database failure.
   */
  public async createSession(
    userId: string | null,
    clientRedirectUrl: string,
    requestedAttributes: string[] = [],
    loaRequested?: string,
    eidTypeRequested?: string[],
    transactionAttestationRequest?: object,
    ageVerificationRequested?: boolean,
    communityIdRequested?: string,
    eCardServerAddress?: string,
    initialStatus?: IEidSession['status'] // Add optional initialStatus parameter
  ): Promise<IEidSession> {
    const sessionId = uuidv4();
    const requestId = `create_${sessionId}`;
    logger.debug(`Creating new eID session`, { requestId, sessionId });

    // Validate inputs
    if (userId && !validator.isUUID(userId)) {
      logger.warn('Invalid userId format', { requestId });
      throw new SessionError('Invalid userId format');
    }
    if (requestedAttributes.some(attr => !validator.isAlphanumeric(attr, 'en-US', { ignore: '_' }))) {
      logger.warn('Invalid requested attributes', { requestId });
      throw new SessionError('Invalid requested attributes');
    }
    if (loaRequested && !['Low', 'Substantial', 'High'].includes(loaRequested)) {
      logger.warn('Invalid LoA requested', { requestId });
      throw new SessionError('Invalid Level of Assurance');
    }
    if (eidTypeRequested && eidTypeRequested.some(type => !validator.isAlphanumeric(type))) {
      logger.warn('Invalid eID types', { requestId });
      throw new SessionError('Invalid eID types');
    }
    if (communityIdRequested && !validator.isAlphanumeric(communityIdRequested)) {
      logger.warn('Invalid communityIdRequested', { requestId });
      throw new SessionError('Invalid community ID');
    }

    const newSession = new EidSession({
      sessionId,
      userId,
      status: initialStatus || 'INITIATED', // Use initialStatus or default to 'INITIATED'
      nonce: uuidv4(),
      clientRedirectUrl,
      requestedAttributes,
      loaRequested,
      eidTypeRequested,
      transactionAttestationRequest,
      ageVerificationRequested,
      communityIdRequested,
      eCardServerAddress: eCardServerAddress || EID_CONFIG.DEFAULT_ECARD_SERVER_ADDRESS,
      createdAt: new Date(),
      updatedAt: new Date(),
      expiresAt: new Date(Date.now() + this.SESSION_TIMEOUT_MS),
    });

    for (let attempt = 1; attempt <= this.MAX_RETRIES; attempt++) {
      try {
        const savedSession = await newSession.save();
        logger.info(`New eID session created`, { requestId, sessionId });
        return savedSession;
      } catch (error) {
        logger.warn(`Session creation attempt ${attempt} failed`, { requestId, error: (error as Error).message });
        if (attempt === this.MAX_RETRIES) {
          logger.error(`Failed to create session after ${this.MAX_RETRIES} attempts`, { requestId });
          throw new SessionError(`Failed to create session: ${(error as Error).message}`);
        }
        await new Promise(resolve => setTimeout(resolve, this.RETRY_DELAY_MS));
      }
    }

    throw new SessionError('Failed to create session after maximum retries');
  }

  /**
   * Retrieves an eID session by its ID.
   * @param sessionId The session ID.
   * @returns The IEidSession document or null if not found.
   * @throws SessionError on database failure.
   */
  public async getSession(sessionId: string): Promise<IEidSession | null> {
    const requestId = `get_${sessionId}`;
    logger.debug(`Retrieving eID session`, { requestId, sessionId });

    if (!validator.isUUID(sessionId)) {
      logger.warn('Invalid sessionId format', { requestId });
      throw new SessionError('Invalid session ID format');
    }

    for (let attempt = 1; attempt <= this.MAX_RETRIES; attempt++) {
      try {
        const session = await EidSession.findOne({ sessionId });
        if (session) {
          // Check if session is expired
          if (session.expiresAt && session.expiresAt < new Date()) {
            logger.warn(`Session expired`, { requestId, sessionId });
            await this.deleteSession(sessionId);
            return null;
          }
          logger.debug(`Retrieved eID session`, { requestId, sessionId });
          return session;
        }
        logger.warn(`eID session not found`, { requestId, sessionId });
        return null;
      } catch (error) {
        logger.warn(`Session retrieval attempt ${attempt} failed`, { requestId, error: (error as Error).message });
        if (attempt === this.MAX_RETRIES) {
          logger.error(`Failed to retrieve session after ${this.MAX_RETRIES} attempts`, { requestId });
          throw new SessionError(`Failed to retrieve session: ${(error as Error).message}`);
        }
        await new Promise(resolve => setTimeout(resolve, this.RETRY_DELAY_MS));
      }
    }

    throw new SessionError('Failed to retrieve session after maximum retries');
  }

  /**
   * Updates the status of an eID session.
   * @param sessionId The session ID.
   * @param newStatus The new status.
   * @param statusDetail Optional status detail message.
   * @returns The updated IEidSession document or null if not found.
   * @throws SessionError on validation or database failure.
   */
  public async updateSessionStatus(
    sessionId: string,
    newStatus: string,
    statusDetail?: string
  ): Promise<IEidSession | null> {
    const requestId = `status_${sessionId}_${Date.now()}`;
    logger.debug(`Updating eID session status`, { requestId, sessionId, newStatus });

    if (!validator.isUUID(sessionId)) {
      logger.warn('Invalid sessionId format', { requestId });
      throw new SessionError('Invalid session ID format');
    }
    if (!['INITIATED', 'PENDING', 'COMPLETED', 'FAILED', 'CANCELLED'].includes(newStatus)) {
      logger.warn('Invalid status', { requestId, newStatus });
      throw new SessionError('Invalid session status');
    }
    if (statusDetail && !validator.isAscii(statusDetail)) {
      logger.warn('Invalid statusDetail format', { requestId });
      throw new SessionError('Invalid status detail format');
    }

    for (let attempt = 1; attempt <= this.MAX_RETRIES; attempt++) {
      try {
        const updatedSession = await EidSession.findOneAndUpdate(
          { sessionId },
          { $set: { status: newStatus, statusDetail, updatedAt: new Date(), expiresAt: new Date(Date.now() + this.SESSION_TIMEOUT_MS) } },
          { new: true }
        );
        if (updatedSession) {
          logger.info(`Updated eID session status`, { requestId, sessionId, newStatus });
          return updatedSession;
        }
        logger.warn(`eID session not found for status update`, { requestId, sessionId });
        return null;
      } catch (error) {
        logger.warn(`Status update attempt ${attempt} failed`, { requestId, error: (error as Error).message });
        if (attempt === this.MAX_RETRIES) {
          logger.error(`Failed to update session status after ${this.MAX_RETRIES} attempts`, { requestId });
          throw new SessionError(`Failed to update session status: ${(error as Error).message}`);
        }
        await new Promise(resolve => setTimeout(resolve, this.RETRY_DELAY_MS));
      }
    }

    throw new SessionError('Failed to update session status after maximum retries');
  }

  /**
   * Updates the attributes of an eID session.
   * @param sessionId The session ID.
   * @param attributes The new attributes to store.
   * @returns The updated IEidSession document or null if not found.
   * @throws SessionError on validation or database failure.
   */
  public async updateSessionAttributes(sessionId: string, attributes: object): Promise<IEidSession | null> {
    const requestId = `attrs_${sessionId}_${Date.now()}`;
    logger.debug(`Updating eID session attributes`, { requestId, sessionId });

    if (!validator.isUUID(sessionId)) {
      logger.warn('Invalid sessionId format', { requestId });
      throw new SessionError('Invalid session ID format');
    }
    if (!attributes || typeof attributes !== 'object' || Object.keys(attributes).length === 0) {
      logger.warn('Invalid or empty attributes', { requestId });
      throw new SessionError('Invalid or empty attributes');
    }
    for (const key of Object.keys(attributes)) {
      if (!validator.isAlphanumeric(key, 'en-US', { ignore: '_' })) {
        logger.warn(`Invalid attribute key: ${key}`, { requestId });
        throw new SessionError(`Invalid attribute key: ${key}`);
      }
    }

    for (let attempt = 1; attempt <= this.MAX_RETRIES; attempt++) {
      try {
        const updatedSession = await EidSession.findOneAndUpdate(
          { sessionId },
          { $set: { attributes: { ...attributes }, updatedAt: new Date(), expiresAt: new Date(Date.now() + this.SESSION_TIMEOUT_MS) } },
          { new: true }
        );
        if (updatedSession) {
          logger.info(`Updated eID session attributes`, { requestId, sessionId, attributeKeys: Object.keys(attributes) });
          return updatedSession;
        }
        logger.warn(`eID session not found for attributes update`, { requestId, sessionId });
        return null;
      } catch (error) {
        logger.warn(`Attributes update attempt ${attempt} failed`, { requestId, error: (error as Error).message });
        if (attempt === this.MAX_RETRIES) {
          logger.error(`Failed to update session attributes after ${this.MAX_RETRIES} attempts`, { requestId });
          throw new SessionError(`Failed to update session attributes: ${(error as Error).message}`);
        }
        await new Promise(resolve => setTimeout(resolve, this.RETRY_DELAY_MS));
      }
    }

    throw new SessionError('Failed to update session attributes after maximum retries');
  }

  /**
   * Updates multiple fields of an eID session.
   * @param sessionId The session ID.
   * @param updates The fields to update.
   * @returns The updated IEidSession document or null if not found.
   * @throws SessionError on validation or database failure.
   */
  public async updateSession(sessionId: string, updates: UpdateQuery<IEidSession>): Promise<IEidSession | null> {
    const requestId = `update_${sessionId}_${Date.now()}`;
    logger.debug(`Updating eID session`, { requestId, sessionId });

    if (!validator.isUUID(sessionId)) {
      logger.warn('Invalid sessionId format', { requestId });
      throw new SessionError('Invalid session ID format');
    }
    if (!updates || Object.keys(updates).length === 0) {
      logger.warn('Empty updates provided', { requestId });
      throw new SessionError('Empty updates provided');
    }

    const updatePayload: UpdateQuery<IEidSession> = {
      ...updates,
      $set: {
        ...(updates.$set || {}),
        updatedAt: new Date(),
        expiresAt: new Date(Date.now() + this.SESSION_TIMEOUT_MS),
      },
    };

    for (let attempt = 1; attempt <= this.MAX_RETRIES; attempt++) {
      try {
        const updatedSession = await EidSession.findOneAndUpdate(
          { sessionId },
          updatePayload,
          { new: true }
        );
        if (updatedSession) {
          logger.info(`Updated eID session`, { requestId, sessionId, updatedFields: Object.keys(updates.$set || {}) });
          return updatedSession;
        }
        logger.warn(`eID session not found for update`, { requestId, sessionId });
        return null;
      } catch (error) {
        logger.warn(`Session update attempt ${attempt} failed`, { requestId, error: (error as Error).message });
        if (attempt === this.MAX_RETRIES) {
          logger.error(`Failed to update session after ${this.MAX_RETRIES} attempts`, { requestId });
          throw new SessionError(`Failed to update session: ${(error as Error).message}`);
        }
        await new Promise(resolve => setTimeout(resolve, this.RETRY_DELAY_MS));
      }
    }

    throw new SessionError('Failed to update session after maximum retries');
  }

  /**
   * Deletes an eID session by its ID.
   * @param sessionId The session ID.
   * @returns True if deleted, false if not found.
   * @throws SessionError on database failure.
   */
  public async deleteSession(sessionId: string): Promise<boolean> {
    const requestId = `delete_${sessionId}_${Date.now()}`;
    logger.debug(`Deleting eID session`, { requestId, sessionId });

    if (!validator.isUUID(sessionId)) {
      logger.warn('Invalid sessionId format', { requestId });
      throw new SessionError('Invalid session ID format');
    }

    for (let attempt = 1; attempt <= this.MAX_RETRIES; attempt++) {
      try {
        const result = await EidSession.deleteOne({ sessionId });
        if (result.deletedCount > 0) {
          logger.info(`Deleted eID session`, { requestId, sessionId });
          return true;
        }
        logger.warn(`eID session not found for deletion`, { requestId, sessionId });
        return false;
      } catch (error) {
        logger.warn(`Session deletion attempt ${attempt} failed`, { requestId, error: (error as Error).message });
        if (attempt === this.MAX_RETRIES) {
          logger.error(`Failed to delete session after ${this.MAX_RETRIES} attempts`, { requestId });
          throw new SessionError(`Failed to delete session: ${(error as Error).message}`);
        }
        await new Promise(resolve => setTimeout(resolve, this.RETRY_DELAY_MS));
      }
    }

    throw new SessionError('Failed to delete session after maximum retries');
  }

  /**
   * Cleans up expired sessions from the database.
   * @returns The number of sessions deleted.
   * @throws SessionError on database failure.
   */
  public async cleanupExpiredSessions(): Promise<number> {
    const requestId = `cleanup_${Date.now()}`;
    logger.debug(`Cleaning up expired eID sessions`, { requestId });

    for (let attempt = 1; attempt <= this.MAX_RETRIES; attempt++) {
      try {
        const result = await EidSession.deleteMany({ expiresAt: { $lte: new Date() } });
        logger.info(`Cleaned up ${result.deletedCount} expired eID sessions`, { requestId });
        return result.deletedCount;
      } catch (error) {
        logger.warn(`Cleanup attempt ${attempt} failed`, { requestId, error: (error as Error).message });
        if (attempt === this.MAX_RETRIES) {
          logger.error(`Failed to clean up sessions after ${this.MAX_RETRIES} attempts`, { requestId });
          throw new SessionError(`Failed to clean up sessions: ${(error as Error).message}`);
        }
        await new Promise(resolve => setTimeout(resolve, this.RETRY_DELAY_MS));
      }
    }

    throw new SessionError('Failed to clean up sessions after maximum retries');
  }
}