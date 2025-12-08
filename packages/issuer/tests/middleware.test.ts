import { getCurrentTimestamp } from '@evp/core';
import { SignJWT, importJWK } from 'jose';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { EmailVerificationIssuer } from '../src/issuer.js';
import { generateKeyPair } from '../src/keys.js';
import { createIssuerMiddleware, toResponse } from '../src/middleware.js';

describe('createIssuerMiddleware', () => {
  let issuer: EmailVerificationIssuer;
  let issuerKeyPair: { privateKey: JsonWebKey; publicKey: JsonWebKey };
  let browserKeyPair: { privateKey: JsonWebKey; publicKey: JsonWebKey };

  beforeAll(async () => {
    issuerKeyPair = await generateKeyPair('EdDSA');
    browserKeyPair = await generateKeyPair('EdDSA');

    issuer = new EmailVerificationIssuer({
      issuer: 'mail.example.com',
      privateKey: issuerKeyPair.privateKey,
      kid: 'test-key',
    });
  });

  async function createValidRequestToken(): Promise<string> {
    const browserPrivateKey = await importJWK(browserKeyPair.privateKey, 'EdDSA');
    return await new SignJWT({
      aud: 'mail.example.com',
      iat: getCurrentTimestamp(),
      email: 'user@example.com',
    })
      .setProtectedHeader({
        alg: 'EdDSA',
        typ: 'JWT',
        jwk: browserKeyPair.publicKey,
      })
      .sign(browserPrivateKey);
  }

  it('should reject non-POST requests', async () => {
    const middleware = createIssuerMiddleware(issuer, async () => true);

    const result = await middleware.handleIssuance(
      new Request('http://localhost/issuance', { method: 'GET' })
    );

    expect(result.status).toBe(405);
    expect(result.body).toHaveProperty('error', 'invalid_request');
    expect(result.headers).toHaveProperty('Allow', 'POST');
  });

  it('should reject wrong Content-Type', async () => {
    const middleware = createIssuerMiddleware(issuer, async () => true);

    const result = await middleware.handleIssuance(
      new Request('http://localhost/issuance', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      })
    );

    expect(result.status).toBe(415);
    expect(result.body).toHaveProperty('error', 'invalid_request');
  });

  it('should reject missing Sec-Fetch-Dest header', async () => {
    const middleware = createIssuerMiddleware(issuer, async () => true);

    const result = await middleware.handleIssuance(
      new Request('http://localhost/issuance', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'request_token=test',
      })
    );

    expect(result.status).toBe(400);
    expect(result.body).toHaveProperty('error', 'invalid_request');
    expect((result.body as { error_description?: string }).error_description).toContain(
      'Sec-Fetch-Dest'
    );
  });

  it('should reject missing request_token', async () => {
    const middleware = createIssuerMiddleware(issuer, async () => true);

    const result = await middleware.handleIssuance(
      new Request('http://localhost/issuance', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Sec-Fetch-Dest': 'email-verification',
        },
        body: '',
      })
    );

    expect(result.status).toBe(400);
    expect(result.body).toHaveProperty('error', 'invalid_request');
    expect((result.body as { error_description?: string }).error_description).toContain(
      'request_token'
    );
  });

  it('should reject if user does not own email', async () => {
    const middleware = createIssuerMiddleware(issuer, async () => false);
    const requestToken = await createValidRequestToken();

    const result = await middleware.handleIssuance(
      new Request('http://localhost/issuance', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Sec-Fetch-Dest': 'email-verification',
        },
        body: `request_token=${encodeURIComponent(requestToken)}`,
      })
    );

    expect(result.status).toBe(401);
    expect(result.body).toHaveProperty('error', 'authentication_required');
  });

  it('should issue token for valid request', async () => {
    const middleware = createIssuerMiddleware(issuer, async () => true);
    const requestToken = await createValidRequestToken();

    const result = await middleware.handleIssuance(
      new Request('http://localhost/issuance', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Sec-Fetch-Dest': 'email-verification',
        },
        body: `request_token=${encodeURIComponent(requestToken)}`,
      })
    );

    expect(result.status).toBe(200);
    expect(result.body).toHaveProperty('issuance_token');
    expect((result.body as { issuance_token: string }).issuance_token).toMatch(/~$/);
  });

  it('should pass cookie to verifyUserOwnsEmail', async () => {
    const verifyFn = vi.fn(async () => true);
    const middleware = createIssuerMiddleware(issuer, verifyFn);
    const requestToken = await createValidRequestToken();

    await middleware.handleIssuance(
      new Request('http://localhost/issuance', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Sec-Fetch-Dest': 'email-verification',
          Cookie: 'session=abc123',
        },
        body: `request_token=${encodeURIComponent(requestToken)}`,
      })
    );

    expect(verifyFn).toHaveBeenCalledWith('session=abc123', 'user@example.com');
  });
});

describe('toResponse', () => {
  it('should convert success result to Response', () => {
    const result = {
      status: 200,
      body: { issuance_token: 'token123~' },
    };

    const response = toResponse(result);

    expect(response.status).toBe(200);
    expect(response.headers.get('Content-Type')).toBe('application/json');
  });

  it('should convert error result to Response', () => {
    const result = {
      status: 400,
      body: { error: 'invalid_request', error_description: 'Missing field' },
    };

    const response = toResponse(result);

    expect(response.status).toBe(400);
  });

  it('should include custom headers', () => {
    const result = {
      status: 405,
      body: { error: 'invalid_request' },
      headers: { Allow: 'POST' },
    };

    const response = toResponse(result);

    expect(response.headers.get('Allow')).toBe('POST');
  });
});
