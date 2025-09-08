import axios, { AxiosError } from 'axios';
import validator from 'validator';
import { API_ENDPOINTS } from '../config/api';
import logger from '../utils/logger';

/**
 * Interface for authentication response
 */
interface AuthResponse {
  user: {
    id: string;
    username: string;
    email: string;
  };
  token: string;
  refreshToken?: string;
}

/**
 * Interface for password reset request
 */

/**
 * Interface for password reset confirmation
 */

/**
 * Configuration for API requests
 */
const AUTH_CONFIG = {
  TIMEOUT_MS: 10000,
  MAX_RETRIES: 3,
  RETRY_DELAY_MS: 1000,
};

/**
 * Custom error class for authentication failures
 */
export class AuthError extends Error {
  constructor(message: string, public readonly statusCode?: number) {
    super(message);
    this.name = 'AuthError';
  }
}

/**
 * Performs a login request to the backend
 * @param username The user's username
 * @param password The user's password
 * @returns AuthResponse containing user data and token
 * @throws AuthError on validation or API failure
 */

/**
 * Refreshes an authentication token using a refresh token
 * @returns AuthResponse containing new user data and token
 * @throws AuthError on validation or API failure
 */
export const refreshToken = async (): Promise<AuthResponse> => {
  const requestId = `refresh_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  logger.info(`Initiating token refresh request`, { requestId });

  const refreshToken = localStorage.getItem('refreshToken');
  if (!refreshToken) {
    logger.warn('No refresh token found', { requestId });
    throw new AuthError('No refresh token available');
  }

  for (let attempt = 1; attempt <= AUTH_CONFIG.MAX_RETRIES; attempt++) {
    try {
      const response = await axios.post<AuthResponse>(
        API_ENDPOINTS.AUTH.REFRESH_TOKEN,
        { refreshToken },
        {
          timeout: AUTH_CONFIG.TIMEOUT_MS,
          headers: { 'Content-Type': 'application/json' },
        }
      );

      const { token, refreshToken: newRefreshToken, user } = response.data;
      if (!token || !user?.id || !user?.username || !user?.email) {
        logger.error('Invalid refresh token response format', { requestId });
        throw new AuthError('Invalid refresh token response format', 500);
      }

      // Update stored tokens
      try {
        localStorage.setItem('authToken', token);
        if (newRefreshToken) {
          localStorage.setItem('refreshToken', newRefreshToken);
        }
      } catch (error) {
        logger.warn(`Failed to store tokens: ${(error as Error).message}`, { requestId });
      }

      logger.info(`Token refresh successful`, { requestId, userId: user.id });
      return response.data;
    } catch (error) {
      const errorMessage = error instanceof AxiosError
        ? error.response
          ? `${error.response.data.message || 'Token refresh failed'} (HTTP ${error.response.status})`
          : error.code === 'ECONNABORTED'
          ? `Request timed out after ${AUTH_CONFIG.TIMEOUT_MS}ms`
          : `Network error: ${error.message}`
        : `Unexpected error: ${(error as Error).message}`;

      logger.warn(`Token refresh attempt ${attempt} failed`, { requestId, error: errorMessage });

      if (
        attempt < AUTH_CONFIG.MAX_RETRIES &&
        error instanceof AxiosError &&
        (error.code === 'ECONNABORTED' || error.response?.status === 429)
      ) {
        await new Promise(resolve => setTimeout(resolve, AUTH_CONFIG.RETRY_DELAY_MS));
        continue;
      }

      logger.error(`Token refresh failed after ${AUTH_CONFIG.MAX_RETRIES} attempts`, { requestId });
      localStorage.removeItem('refreshToken');
      throw new AuthError(errorMessage, error instanceof AxiosError ? error.response?.status : undefined);
    }
  }

  throw new AuthError('Token refresh failed after maximum retries');
};

/**
 * Initiates a password reset request
 * @param email The user's email
 * @returns True if the request was successful
 * @throws AuthError on validation or API failure
 */
export const requestPasswordReset = async (email: string): Promise<boolean> => {
  const requestId = `pw_reset_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  logger.info(`Initiating password reset request`, { requestId, email });

  // Input validation
  if (!validator.isEmail(email)) {
    logger.warn('Invalid email format', { requestId });
    throw new AuthError('Invalid email format');
  }

  for (let attempt = 1; attempt <= AUTH_CONFIG.MAX_RETRIES; attempt++) {
    try {
      await axios.post(
        API_ENDPOINTS.AUTH.PASSWORD_RESET_REQUEST,
        { email },
        {
          timeout: AUTH_CONFIG.TIMEOUT_MS,
          headers: { 'Content-Type': 'application/json' },
        }
      );

      logger.info(`Password reset request successful`, { requestId, email });
      return true;
    } catch (error) {
      const errorMessage = error instanceof AxiosError
        ? error.response
          ? `${error.response.data.message || 'Password reset request failed'} (HTTP ${error.response.status})`
          : error.code === 'ECONNABORTED'
          ? `Request timed out after ${AUTH_CONFIG.TIMEOUT_MS}ms`
          : `Network error: ${error.message}`
        : `Unexpected error: ${(error as Error).message}`;

      logger.warn(`Password reset request attempt ${attempt} failed`, { requestId, error: errorMessage });

      if (
        attempt < AUTH_CONFIG.MAX_RETRIES &&
        error instanceof AxiosError &&
        (error.code === 'ECONNABORTED' || error.response?.status === 429)
      ) {
        await new Promise(resolve => setTimeout(resolve, AUTH_CONFIG.RETRY_DELAY_MS));
        continue;
      }

      logger.error(`Password reset request failed after ${AUTH_CONFIG.MAX_RETRIES} attempts`, { requestId });
      throw new AuthError(errorMessage, error instanceof AxiosError ? error.response?.status : undefined);
    }
  }

  throw new AuthError('Password reset request failed after maximum retries');
};

/**
 * Confirms a password reset with a token
 * @param token The reset token
 * @param newPassword The new password
 * @returns True if the password was reset successfully
 * @throws AuthError on validation or API failure
 */
export const confirmPasswordReset = async (token: string, newPassword: string): Promise<boolean> => {
  const requestId = `pw_confirm_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  logger.info(`Initiating password reset confirmation`, { requestId });

  // Input validation
  if (!token || !validator.isAlphanumeric(token, 'en-US', { ignore: '-_' })) {
    logger.warn('Invalid reset token format', { requestId });
    throw new AuthError('Invalid reset token format');
  }
  if (!newPassword || newPassword.length < 8) {
    logger.warn('Invalid new password length', { requestId });
    throw new AuthError('New password must be at least 8 characters');
  }

  for (let attempt = 1; attempt <= AUTH_CONFIG.MAX_RETRIES; attempt++) {
    try {
      await axios.post(
        API_ENDPOINTS.AUTH.PASSWORD_RESET_CONFIRM,
        { token, newPassword },
        {
          timeout: AUTH_CONFIG.TIMEOUT_MS,
          headers: { 'Content-Type': 'application/json' },
        }
      );

      logger.info(`Password reset confirmation successful`, { requestId });
      return true;
    } catch (error) {
      const errorMessage = error instanceof AxiosError
        ? error.response
          ? `${error.response.data.message || 'Password reset confirmation failed'} (HTTP ${error.response.status})`
          : error.code === 'ECONNABORTED'
          ? `Request timed out after ${AUTH_CONFIG.TIMEOUT_MS}ms`
          : `Network error: ${error.message}`
        : `Unexpected error: ${(error as Error).message}`;

      logger.warn(`Password reset confirmation attempt ${attempt} failed`, { requestId, error: errorMessage });

      if (
        attempt < AUTH_CONFIG.MAX_RETRIES &&
        error instanceof AxiosError &&
        (error.code === 'ECONNABORTED' || error.response?.status === 429)
      ) {
        await new Promise(resolve => setTimeout(resolve, AUTH_CONFIG.RETRY_DELAY_MS));
        continue;
      }

      logger.error(`Password reset confirmation failed after ${AUTH_CONFIG.MAX_RETRIES} attempts`, { requestId });
      throw new AuthError(errorMessage, error instanceof AxiosError ? error.response?.status : undefined);
    }
  }

  throw new AuthError('Password reset confirmation failed after maximum retries');
};