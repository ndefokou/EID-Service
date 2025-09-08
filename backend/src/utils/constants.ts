/**
 * General Constants for the eID Backend Service
 */

// API Versioning
export const API_VERSION = 'v1';

// Regular Expressions
export const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
export const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/;
// At least 8 characters, one uppercase, one lowercase, one number, one special character

// EID-related Constants
export const EID_MAX_SESSION_DURATION_MS = 10 * 60 * 1000; // 10 minutes for eID session
export const CRL_CACHE_TTL_MS = 4 * 60 * 60 * 1000; // 4 hours for CRL cache

// Common Status Messages
export const AUTH_SUCCESS_MESSAGE = 'Authentication successful.';
export const AUTH_FAILURE_MESSAGE = 'Authentication failed: Invalid credentials.';
export const REGISTRATION_SUCCESS_MESSAGE = 'User registered successfully.';
export const SERVER_ERROR_MESSAGE = 'An unexpected server error occurred.';
export const NOT_FOUND_MESSAGE = 'Resource not found.';
export const UNAUTHORIZED_MESSAGE = 'Unauthorized: Access token is missing or invalid.';
export const FORBIDDEN_MESSAGE = 'Forbidden: You do not have permission to access this resource.';
export const REFRESH_TOKEN_INVALID_MESSAGE = 'Invalid refresh token.';
export const REFRESH_TOKEN_EXPIRED_MESSAGE = 'Refresh token expired. Please log in again.';

// Environment Variables Default Values
export const DEFAULT_PORT = 3000;
export const DEFAULT_NODE_ENV = 'development';

// Security Headers (Helmet defaults are often sufficient, but these can be customized)
export const SECURITY_HEADERS = {
  // Example: 'default-src': ["'self'"], 'frame-ancestors': ["'none'"]
};

// CORS Whitelist (should be dynamically loaded from config or environment)
export const CORS_WHITELIST: string[] = []; // Populate from config/cors.ts

// OCSP Constants
export const OCSP_REQUEST_TIMEOUT_MS = 5000; // 5 seconds timeout for OCSP requests