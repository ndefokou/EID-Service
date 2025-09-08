/**
 * @file Utility functions for input validation.
 */

/**
 * Validates an email address format.
 * @param {string} email - The email address to validate.
 * @returns {boolean} True if the email is valid, false otherwise.
 */
export const isValidEmail = (email: string): boolean => {
  // A simple regex for email validation.
  // For stricter validation, consider more comprehensive regex or a library.
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

/**
 * Validates a password based on common security requirements.
 * At least 8 characters, one uppercase, one lowercase, one number, one special character.
 * @param {string} password - The password to validate.
 * @returns {boolean} True if the password is valid, false otherwise.
 */
export const isValidPassword = (password: string): boolean => {
  // Minimum 8 characters
  // At least one uppercase letter
  // At least one lowercase letter
  // At least one number
  // At least one special character
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return passwordRegex.test(password);
};

/**
 * Checks if a string is empty or contains only whitespace.
 * @param {string | null | undefined} value - The string to check.
 * @returns {boolean} True if the string is empty or whitespace only, false otherwise.
 */
export const isEmpty = (value: string | null | undefined): boolean => {
  return value === null || value === undefined || value.trim() === '';
};