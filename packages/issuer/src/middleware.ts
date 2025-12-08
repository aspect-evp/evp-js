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

/** Create error result */
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

/** Create success result */
function successResult(issuanceToken: string): HandleIssuanceResult {
  return {
    status: 200,
    body: { issuance_token: issuanceToken },
  };
}

/** Validate HTTP method */
function validateMethod(request: Request): HandleIssuanceResult | null {
  if (request.method !== 'POST') {
    return errorResult(405, 'invalid_request', 'Method must be POST', { Allow: 'POST' });
  }
  return null;
}

/** Validate Content-Type header */
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

/** Validate Sec-Fetch-Dest header */
function validateSecFetchDest(request: Request): HandleIssuanceResult | null {
  const secFetchDest = request.headers.get('Sec-Fetch-Dest');
  if (secFetchDest !== 'email-verification') {
    return errorResult(400, 'invalid_request', 'Missing or invalid Sec-Fetch-Dest header');
  }
  return null;
}

/** Validate all request headers and method */
function validateRequest(request: Request): HandleIssuanceResult | null {
  return validateMethod(request) || validateContentType(request) || validateSecFetchDest(request);
}

/** Extract request token from form data */
async function extractRequestToken(request: Request): Promise<string | HandleIssuanceResult> {
  const formData = await request.formData();
  const requestToken = formData.get('request_token');

  if (!requestToken || typeof requestToken !== 'string') {
    return errorResult(400, 'invalid_request', 'Missing request_token parameter');
  }

  return requestToken;
}

/** Verify user owns the email address */
async function verifyEmailOwnership(
  request: Request,
  email: string,
  verifyUserOwnsEmail: VerifyUserOwnsEmail
): Promise<HandleIssuanceResult | null> {
  const cookie = request.headers.get('Cookie') ?? '';
  const ownsEmail = await verifyUserOwnsEmail(cookie, email);

  if (!ownsEmail) {
    return errorResult(
      401,
      'authentication_required',
      'User must be authenticated and control the email'
    );
  }

  return null;
}

/** Handle error and convert to result */
function handleError(error: unknown): HandleIssuanceResult {
  if (isEVPError(error)) {
    return {
      status: error.getHttpStatus(),
      body: error.toJSON(),
    };
  }

  console.error('EVP issuance error:', error);
  return errorResult(500, 'server_error', 'Internal server error');
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
        // Validate request headers and method
        const validationError = validateRequest(request);
        if (validationError) return validationError;

        // Extract request token
        const tokenResult = await extractRequestToken(request);
        if (typeof tokenResult !== 'string') return tokenResult;
        const requestToken = tokenResult;

        // Verify the request token
        const { payload, browserPublicKey } = await issuer.verifyRequestToken(requestToken);

        // Check if user owns this email
        const ownershipError = await verifyEmailOwnership(
          request,
          payload.email,
          verifyUserOwnsEmail
        );
        if (ownershipError) return ownershipError;

        // Issue the token
        const issuanceToken = await issuer.issueToken(payload.email, browserPublicKey);
        return successResult(issuanceToken);
      } catch (error) {
        return handleError(error);
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
