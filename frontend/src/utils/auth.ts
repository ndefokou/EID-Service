/**
 * @file Utility functions for authentication-related tasks.
 */

import { AuthResponse } from '../types/auth';

/**
 * Stores authentication data (user info and token) in local storage.
 * In a production environment, tokens should ideally be stored in HttpOnly cookies
 * to enhance security against XSS attacks. For client-side access (as in this example),
 * localStorage is used for simplicity.
 *
 * @param {AuthResponse} authData - The authentication response containing user data and token.
 */
export const storeAuthData = (authData: AuthResponse): void => {
  localStorage.setItem('authToken', authData.token);
  localStorage.setItem('userData', JSON.stringify(authData.user));
};

/**
 * Retrieves the authentication token from local storage.
 * @returns {string | null} The authentication token, or null if not found.
 */
export const getAuthToken = (): string | null => {
  return localStorage.getItem('authToken');
};

/**
 * Retrieves user data from local storage.
 * @returns {any | null} The parsed user data, or null if not found or parsing fails.
 */
export const getUserData = (): any | null => {
  const userDataString = localStorage.getItem('userData');
  if (userDataString) {
    try {
      return JSON.parse(userDataString);
    } catch (error) {
      console.error('Error parsing user data from localStorage:', error);
      return null;
    }
  }
  return null;
};

/**
 * Removes all authentication data from local storage.
 */
export const clearAuthData = (): void => {
  localStorage.removeItem('authToken');
  localStorage.removeItem('userData');
};

/**
 * Checks if a user is currently authenticated based on the presence of a token.
 * @returns {boolean} True if authenticated, false otherwise.
 */
export const isAuthenticated = (): boolean => {
  return !!getAuthToken();
};