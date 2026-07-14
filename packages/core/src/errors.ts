/**
 * EVP Error Handling
 *
 * Custom error class for EVP-specific errors with spec-compliant error codes.
 */

import type { EVPErrorCode } from './types.js';

/**
 * EVP-specific error class
 *
 * Use this class to throw and handle EVP protocol errors.
 * The error can be serialized to JSON for HTTP error responses.
 *
 * @example
 * ```typescript
 * throw new EVPError('invalid_token', 'Token signature verification failed');
 * ```
 */
export class EVPError extends Error {
  /** Error code as defined by the EVP specification */
  readonly code: EVPErrorCode;

  /** Optional human-readable description */
  readonly description?: string;

  constructor(code: EVPErrorCode, description?: string) {
    const message = description ? `${code}: ${description}` : code;
    super(message);

    this.name = 'EVPError';
    this.code = code;
    if (description !== undefined) {
      this.description = description;
    }

    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, EVPError);
    }
  }

  /**
   * Convert error to JSON format suitable for HTTP responses
   *
   * @example
   * ```typescript
   * // Express.js error handler
   * if (error instanceof EVPError) {
   *   res.status(getStatusForCode(error.code)).json(error.toJSON());
   * }
   * ```
   */
  toJSON(): { error: EVPErrorCode; error_description?: string } {
    const json: { error: EVPErrorCode; error_description?: string } = {
      error: this.code,
    };

    if (this.description) {
      json.error_description = this.description;
    }

    return json;
  }

  /**
   * Get the appropriate HTTP status code for this error
   */
  getHttpStatus(): number {
    switch (this.code) {
      case 'authentication_required':
        return 401;
      case 'invalid_request':
      case 'invalid_token':
      case 'invalid_signature':
      case 'private_email_not_supported':
      case 'invalid_directed_email':
        return 400;
      case 'server_error':
        return 500;
      default:
        return 400;
    }
  }
}

/**
 * Type guard to check if an error is an EVPError
 */
export function isEVPError(error: unknown): error is EVPError {
  return error instanceof EVPError;
}

/** Return a safe message for values thrown by JavaScript or third-party code. */
export function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Create an EVPError from an unknown error
 *
 * Useful for wrapping unexpected errors in a consistent format.
 */
export function toEVPError(error: unknown): EVPError {
  if (isEVPError(error)) {
    return error;
  }

  if (error instanceof Error) {
    return new EVPError('server_error', getErrorMessage(error));
  }

  return new EVPError('server_error', getErrorMessage(error));
}
