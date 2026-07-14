/** Framework-agnostic handlers for the EVP issuance endpoint. */

import {
  EVPError,
  type IssuanceRequest,
  isEVPError,
  isValidEmail,
  verifyHttpMessageSignature,
  type WebAuthnChallenge,
  type WebAuthnResponse,
} from '@aspect-evp/core';
import type { EmailVerificationIssuer } from './issuer.js';

export type VerifyUserOwnsEmail = (cookie: string, email: string) => Promise<boolean>;
export type CreatePrivateEmail = (email: string) => Promise<string>;
export type VerifyDirectedEmail = (email: string, directedEmail: string) => Promise<boolean>;
export type CreateWebAuthnChallenge = (email: string) => Promise<WebAuthnChallenge>;
export type VerifyWebAuthnResponse = (
  email: string,
  response: WebAuthnResponse,
  cookie: string
) => Promise<boolean>;

export interface IssuerMiddlewareOptions {
  createPrivateEmail?: CreatePrivateEmail;
  verifyDirectedEmail?: VerifyDirectedEmail;
  createWebAuthnChallenge?: CreateWebAuthnChallenge;
  verifyWebAuthnResponse?: VerifyWebAuthnResponse;
  clockTolerance?: number;
}

export interface IssuanceSuccessResponse {
  issuance_token: string;
}

export interface IssuanceErrorResponse {
  error: string;
  error_description?: string;
}

export interface WebAuthnChallengeResponse {
  webauthn_challenge: WebAuthnChallenge;
}

export interface HandleIssuanceResult {
  status: number;
  body: IssuanceSuccessResponse | IssuanceErrorResponse | WebAuthnChallengeResponse;
  headers?: Record<string, string>;
}

export interface IssuerMiddleware {
  handleIssuance(request: Request): Promise<HandleIssuanceResult>;
}

function errorResult(
  status: number,
  error: string,
  description: string,
  headers?: Record<string, string>
): HandleIssuanceResult {
  const body: IssuanceErrorResponse = { error, error_description: description };
  const result: HandleIssuanceResult = { status, body };
  if (headers) result.headers = headers;
  return result;
}

function validateEnvelope(request: Request): HandleIssuanceResult | null {
  if (request.method !== 'POST') {
    return errorResult(405, 'invalid_request', 'Method must be POST', { Allow: 'POST' });
  }
  const contentType = request.headers.get('Content-Type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (contentType !== 'application/json') {
    return errorResult(415, 'invalid_request', 'Content-Type must be application/json');
  }
  if (request.headers.get('Sec-Fetch-Dest') !== 'email-verification') {
    return errorResult(400, 'invalid_request', 'Missing or invalid Sec-Fetch-Dest header');
  }
  return null;
}

async function parseBody(request: Request): Promise<IssuanceRequest> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    throw new EVPError('invalid_request', 'Invalid or malformed request body');
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new EVPError('invalid_request', 'Invalid or malformed request body');
  }
  const candidate = body as Record<string, unknown> & {
    email?: unknown;
    private_email?: unknown;
    directed_email?: unknown;
  };
  if (typeof candidate.email !== 'string' || !isValidEmail(candidate.email)) {
    throw new EVPError('invalid_request', 'A syntactically valid email is required');
  }
  if (candidate.private_email !== undefined && typeof candidate.private_email !== 'boolean') {
    throw new EVPError('invalid_request', 'private_email must be a boolean');
  }
  if (candidate.directed_email !== undefined && typeof candidate.directed_email !== 'string') {
    throw new EVPError('invalid_request', 'directed_email must be a string');
  }
  if (candidate.private_email && candidate.directed_email !== undefined) {
    throw new EVPError(
      'invalid_request',
      'private_email and directed_email are mutually exclusive'
    );
  }
  return candidate as unknown as IssuanceRequest;
}

async function authenticate(
  request: Request,
  body: IssuanceRequest,
  verifyUserOwnsEmail: VerifyUserOwnsEmail,
  options: IssuerMiddlewareOptions
): Promise<HandleIssuanceResult | null> {
  const cookie = request.headers.get('Cookie') ?? '';
  if (await verifyUserOwnsEmail(cookie, body.email)) return null;

  if (body.webauthn_response && options.verifyWebAuthnResponse) {
    if (await options.verifyWebAuthnResponse(body.email, body.webauthn_response, cookie))
      return null;
  } else if (!body.webauthn_response && options.createWebAuthnChallenge) {
    return {
      status: 401,
      body: { webauthn_challenge: await options.createWebAuthnChallenge(body.email) },
    };
  }

  return errorResult(
    401,
    'authentication_required',
    'User must be authenticated and have control of the requested email address'
  );
}

async function selectIssuedEmail(
  body: IssuanceRequest,
  options: IssuerMiddlewareOptions
): Promise<{ email: string; isPrivateEmail: boolean }> {
  if (body.private_email) {
    if (!options.createPrivateEmail) {
      throw new EVPError(
        'private_email_not_supported',
        'This issuer does not support private email addresses'
      );
    }
    const email = await options.createPrivateEmail(body.email);
    if (!isValidEmail(email)) {
      throw new EVPError('server_error', 'Private email callback returned an invalid email');
    }
    return { email, isPrivateEmail: true };
  }

  if (body.directed_email !== undefined) {
    if (!options.verifyDirectedEmail) {
      throw new EVPError(
        'private_email_not_supported',
        'This issuer does not support private email addresses'
      );
    }
    if (
      !isValidEmail(body.directed_email) ||
      !(await options.verifyDirectedEmail(body.email, body.directed_email))
    ) {
      throw new EVPError(
        'invalid_directed_email',
        'The directed_email is invalid or not linked to this email address'
      );
    }
    return { email: body.directed_email, isPrivateEmail: true };
  }

  return { email: body.email, isPrivateEmail: false };
}

function handleError(error: unknown): HandleIssuanceResult {
  if (isEVPError(error)) return { status: error.getHttpStatus(), body: error.toJSON() };
  console.error('EVP issuance error:', error);
  return errorResult(500, 'server_error', 'Temporary server error, please try again later');
}

/** Create the current-draft EVP issuance middleware. */
export function createIssuerMiddleware(
  issuer: EmailVerificationIssuer,
  verifyUserOwnsEmail: VerifyUserOwnsEmail,
  options: IssuerMiddlewareOptions = {}
): IssuerMiddleware {
  return {
    async handleIssuance(request: Request): Promise<HandleIssuanceResult> {
      try {
        const envelopeError = validateEnvelope(request);
        if (envelopeError) return envelopeError;

        const { publicKey } = await verifyHttpMessageSignature(request, options.clockTolerance);
        const body = await parseBody(request);
        const authenticationResult = await authenticate(
          request,
          body,
          verifyUserOwnsEmail,
          options
        );
        if (authenticationResult) return authenticationResult;

        const issued = await selectIssuedEmail(body, options);
        const issuanceToken = await issuer.issueToken(issued.email, publicKey, {
          isPrivateEmail: issued.isPrivateEmail,
        });
        return { status: 200, body: { issuance_token: issuanceToken } };
      } catch (error) {
        return handleError(error);
      }
    },
  };
}

export function toResponse(result: HandleIssuanceResult): Response {
  const headers = new Headers({ 'Content-Type': 'application/json', ...result.headers });
  return new Response(JSON.stringify(result.body), { status: result.status, headers });
}
