/**
 * EVP Issuer Middleware Helpers
 *
 * Provides framework-agnostic middleware for handling EVP issuance requests.
 */

import { isEVPError } from '@aspect-evp/core';
import type { EmailVerificationIssuer } from './issuer.js';

/**
 * Function to verify if a user owns an email address
 */
export type VerifyUserOwnsEmail = (cookie: string, email: string) => Promise<boolean>;

/**
 * Issuance response for successful token generation
 */
export interface IssuanceSuccessResponse {
  issuance_token: string;
}

/**
 * Error response for failed issuance
 */
export interface IssuanceErrorResponse {
  error: string;
  error_description?: string;
}

/**
 * Result from handling an issuance request
 */
export interface HandleIssuanceResult {
  status: number;
  body: IssuanceSuccessResponse | IssuanceErrorResponse;
  headers?: Record<string, string>;
}

/**
 * Issuer middleware interface
 */
export interface IssuerMiddleware {
  handleIssuance(request: Request): Promise<HandleIssuanceResult>;
}

// Helper to create error result
function errorResult(
  status: number,
  error: string,
  description?: string,
  headers?: Record<string, string>
): HandleIssuanceResult {
  const body: IssuanceErrorResponse = { error };
  if (description) {
    body.error_description = description;
  }
  const result: HandleIssuanceResult = { status, body };
  if (headers) {
    result.headers = headers;
  }
  return result;
}

// Validate HTTP method
function validateMethod(request: Request): HandleIssuanceResult | null {
  if (request.method !== 'POST') {
    return errorResult(405, 'invalid_request', 'Method must be POST', { Allow: 'POST' });
  }
  return null;
}

// Validate Content-Type header
function validateContentType(request: Request): HandleIssuanceResult | null {
  const contentType = request.headers.get('Content-Type');
  if (!contentType?.includes('application/x-www-form-urlencoded')) {
    return errorResult(
      415,
      'invalid_request',
      'Content-Type must be application/x-www-form-urlencoded'
    );
  }
  return null;
}

// Validate Sec-Fetch-Dest header
function validateSecFetchDest(request: Request): HandleIssuanceResult | null {
  const secFetchDest = request.headers.get('Sec-Fetch-Dest');
  if (secFetchDest !== 'email-verification') {
    return errorResult(400, 'invalid_request', 'Missing or invalid Sec-Fetch-Dest header');
  }
  return null;
}

/**
 * Create middleware for handling EVP issuance requests
 *
 * @param issuer - The EmailVerificationIssuer instance
 * @param verifyUserOwnsEmail - Function to verify user owns the email
 * @returns Middleware with handleIssuance method
 *
 * @example
 * ```typescript
 * const middleware = createIssuerMiddleware(issuer, async (cookie, email) => {
 *   const user = await getUserFromSession(cookie);
 *   return user?.emails.includes(email) ?? false;
 * });
 * ```
 */
export function createIssuerMiddleware(
  issuer: EmailVerificationIssuer,
  verifyUserOwnsEmail: VerifyUserOwnsEmail
): IssuerMiddleware {
  return {
    async handleIssuance(request: Request): Promise<HandleIssuanceResult> {
      try {
        // Validate request
        const methodError = validateMethod(request);
        if (methodError) return methodError;

        const contentTypeError = validateContentType(request);
        if (contentTypeError) return contentTypeError;

        const secFetchError = validateSecFetchDest(request);
        if (secFetchError) return secFetchError;

        // Parse request body
        const formData = await request.formData();
        const requestToken = formData.get('request_token');

        if (!requestToken || typeof requestToken !== 'string') {
          return errorResult(400, 'invalid_request', 'Missing request_token parameter');
        }

        // Verify the request token
        const { payload, browserPublicKey } = await issuer.verifyRequestToken(requestToken);

        // Check if user owns this email
        const cookie = request.headers.get('Cookie') ?? '';
        const ownsEmail = await verifyUserOwnsEmail(cookie, payload.email);

        if (!ownsEmail) {
          return errorResult(
            401,
            'authentication_required',
            'User must be authenticated and control the email'
          );
        }

        // Issue the token
        const issuanceToken = await issuer.issueToken(payload.email, browserPublicKey);

        return {
          status: 200,
          body: { issuance_token: issuanceToken },
        };
      } catch (error) {
        if (isEVPError(error)) {
          return {
            status: error.getHttpStatus(),
            body: error.toJSON(),
          };
        }

        console.error('EVP issuance error:', error);
        return errorResult(500, 'server_error', 'Internal server error');
      }
    },
  };
}

/**
 * Convert HandleIssuanceResult to a Web API Response
 */
export function toResponse(result: HandleIssuanceResult): Response {
  const headers = new Headers({
    'Content-Type': 'application/json',
    ...result.headers,
  });

  return new Response(JSON.stringify(result.body), {
    status: result.status,
    headers,
  });
}
