/**
 * Custom Error Class for Application-specific errors.
 * Extends the built-in Error class to add a statusCode property,
 * useful for HTTP responses.
 */
export class ApplicationError extends Error {
  public statusCode: number;
  public isOperational: boolean; // Indicates if this is an error the app expects to handle

  constructor(message: string, statusCode: number = 500, isOperational: boolean = true) {
    super(message);
    this.name = this.constructor.name; // Set the name of the error class
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    Error.captureStackTrace(this, this.constructor); // Capture stack trace
  }
}

/**
 * Specific Error for Bad Request (400).
 */
export class BadRequestError extends ApplicationError {
  constructor(message: string = 'Bad Request') {
    super(message, 400);
  }
}

/**
 * Specific Error for Unauthorized Access (401).
 */
export class UnauthorizedError extends ApplicationError {
  constructor(message: string = 'Unauthorized') {
    super(message, 401);
  }
}

/**
 * Specific Error for Forbidden Access (403).
 */
export class ForbiddenError extends ApplicationError {
  constructor(message: string = 'Forbidden') {
    super(message, 403);
  }
}

/**
 * Specific Error for Resource Not Found (404).
 */
export class NotFoundError extends ApplicationError {
  constructor(message: string = 'Not Found') {
    super(message, 404);
  }
}

/**
 * Specific Error for Conflict (409) - e.g., duplicate resource.
 */
export class ConflictError extends ApplicationError {
  constructor(message: string = 'Conflict') {
    super(message, 409);
  }
}

/**
 * Specific Error for EID-related protocol or server errors.
 */
export class EidProtocolError extends ApplicationError {
  constructor(message: string = 'eID Protocol Error', originalError?: Error) {
    super(message, 500); // eID protocol errors are often internal server errors
    if (originalError) {
      this.stack = originalError.stack; // Preserve original error stack
    }
  }
}

/**
 * Specific Error for Database related errors.
 */
export class DatabaseError extends ApplicationError {
  constructor(message: string = 'Database Error', originalError?: Error) {
    super(message, 500, false); // Database errors are typically not operational
    if (originalError) {
      this.stack = originalError.stack;
    }
  }
}

/**
 * Handles uncaught exceptions by logging them and exiting the process.
 * Should be used for critical, unexpected errors that indicate a bug.
 * @param error The uncaught exception.
 * @param logger The logger instance to use.
 */
export function handleCriticalError(error: Error, logger: any): void {
  logger.error('CRITICAL UNCAUGHT EXCEPTION:', error.message, error.stack);
  // In a production environment, you might want to send this to an error tracking service
  // and gracefully shut down the application after a delay.
  process.exit(1); // Exit with a failure code
}