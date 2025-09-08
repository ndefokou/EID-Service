/**
 * @file Contains type definitions for authentication-related data.
 */

/**
 * Interface representing a user in the application.
 */
export interface User {
  id: string;
  username: string;
  email: string;
  // Add other user profile fields as needed, e.g.,
  // firstName?: string;
  // lastName?: string;
  // roles: string[];
}

/**
 * Interface for the response received after a successful login or registration.
 */
export interface AuthResponse {
  user: User;
  token: string;
}