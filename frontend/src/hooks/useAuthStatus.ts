import { useState, useEffect, useCallback } from 'react';
import axios, { AxiosError } from 'axios';
import { useAuth } from '../contexts/AuthContext';

/**
 * Interface for authentication status
 */
interface AuthStatus {
  isAuthenticated: boolean;
  user: { id: string; username: string; email?: string } | null;
  isLoading: boolean;
  error: string | null;
}

/**
 * Configuration for API requests
 */
const AUTH_CONFIG = {
  API_URL: process.env.REACT_APP_AUTH_API_URL || '/api/auth/validate',
  MAX_RETRIES: 3,
  RETRY_DELAY_MS: 1000,
  TIMEOUT_MS: 5000,
};

/**
 * Custom error class for authentication errors
 */
class AuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthError';
  }
}

/**
 * Hook to manage authentication status with real API validation
 * @returns Authentication status including user data, loading state, and errors
 */
export const useAuthStatus = (): AuthStatus => {
  const { isAuthenticated, user, setAuth } = useAuth();
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  /**
   * Validates authentication token via API
   */
  const validateAuthToken = useCallback(async (attempt = 1): Promise<void> => {
    try {
      const token = localStorage.getItem('authToken');
      if (!token) {
        setError('No authentication token found');
        setIsLoading(false);
        setAuth({ isAuthenticated: false, user: null });
        return;
      }

      const response = await axios.get(AUTH_CONFIG.API_URL, {
        headers: { Authorization: `Bearer ${token}` },
        timeout: AUTH_CONFIG.TIMEOUT_MS,
      });

      const { isValid, user } = response.data;
      if (isValid && user) {
        setAuth({ isAuthenticated: true, user });
        setError(null);
      } else {
        localStorage.removeItem('authToken');
        setAuth({ isAuthenticated: false, user: null });
        setError('Invalid authentication token');
      }
    } catch (error) {
      if (error instanceof AxiosError && attempt < AUTH_CONFIG.MAX_RETRIES) {
        if (error.code === 'ECONNABORTED' || error.response?.status === 429) {
          await new Promise(resolve => setTimeout(resolve, AUTH_CONFIG.RETRY_DELAY_MS));
          return validateAuthToken(attempt + 1);
        }
      }
      const errorMessage = error instanceof Error ? error.message : 'Unknown authentication error';
      setError(errorMessage);
      setAuth({ isAuthenticated: false, user: null });
      localStorage.removeItem('authToken');
    } finally {
      setIsLoading(false);
    }
  }, [setAuth]);

  useEffect(() => {
    let isMounted = true;

    const checkAuth = async () => {
      if (!isMounted) return;

      try {
        await validateAuthToken();
      } catch (error) {
        if (isMounted) {
          const errorMessage = error instanceof Error ? error.message : 'Failed to validate authentication';
          setError(errorMessage);
          setIsLoading(false);
        }
      }
    };

    checkAuth();

    return () => {
      isMounted = false;
    };
  }, [validateAuthToken]);

  return {
    isAuthenticated,
    user,
    isLoading,
    error,
  };
};