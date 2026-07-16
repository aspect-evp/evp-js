import { createSignedIssuanceRequest, decodeJWTPayload } from '@aspect-evp/core';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { EmailVerificationIssuer } from '../src/issuer.js';
import { generateKeyPair } from '../src/keys.js';
import { createIssuerMiddleware, toResponse } from '../src/middleware.js';

describe('createIssuerMiddleware', () => {
  let issuer: EmailVerificationIssuer;
  let browserPrivateKey: JsonWebKey;

  beforeAll(async () => {
    const issuerKeyPair = await generateKeyPair('EdDSA');
    const browserKeyPair = await generateKeyPair('EdDSA');
    browserPrivateKey = browserKeyPair.privateKey;
    issuer = new EmailVerificationIssuer({
      issuer: 'mail.example.com',
      privateKey: issuerKeyPair.privateKey,
      kid: 'test-key',
      privateEmailSupported: true,
      webauthnSupported: true,
    });
  });

  function signedRequest(
    body: Record<string, unknown> = { email: 'user@example.com' },
    cookie?: string
  ): Promise<Request> {
    return createSignedIssuanceRequest(
      'https://mail.example.com/email-verification/issuance',
      body,
      browserPrivateKey,
      cookie ? { cookie } : {}
    );
  }

  it('rejects non-POST requests', async () => {
    const middleware = createIssuerMiddleware(issuer, async () => true);
    const result = await middleware.handleIssuance(
      new Request('https://mail.example.com/issuance', { method: 'GET' })
    );
    expect(result.status).toBe(405);
    expect(result.headers).toHaveProperty('Allow', 'POST');
  });

  it('rejects the deprecated form request format', async () => {
    const middleware = createIssuerMiddleware(issuer, async () => true);
    const result = await middleware.handleIssuance(
      new Request('https://mail.example.com/issuance', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'request_token=deprecated',
      })
    );
    expect(result.status).toBe(415);
  });

  it('rejects missing Sec-Fetch-Dest', async () => {
    const middleware = createIssuerMiddleware(issuer, async () => true);
    const result = await middleware.handleIssuance(
      new Request('https://mail.example.com/issuance', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      })
    );
    expect(result.status).toBe(400);
    expect(result.body).toHaveProperty('error', 'invalid_request');
  });

  it.each([
    'emailverification',
    'document',
  ])('rejects the value %s because draft-00 requires email-verification', async (destination) => {
    const middleware = createIssuerMiddleware(issuer, async () => true);
    const request = await signedRequest();
    const headers = new Headers(request.headers);
    headers.set('Sec-Fetch-Dest', destination);
    const result = await middleware.handleIssuance(new Request(request, { headers }));
    expect(result).toMatchObject({
      status: 400,
      body: { error: 'invalid_request' },
    });
  });

  it('rejects missing HTTP Message Signature', async () => {
    const middleware = createIssuerMiddleware(issuer, async () => true);
    const result = await middleware.handleIssuance(
      new Request('https://mail.example.com/issuance', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Sec-Fetch-Dest': 'email-verification',
        },
        body: JSON.stringify({ email: 'user@example.com' }),
      })
    );
    expect(result.body).toHaveProperty('error', 'invalid_signature');
  });

  it('rejects malformed request bodies', async () => {
    const middleware = createIssuerMiddleware(issuer, async () => true);
    const result = await middleware.handleIssuance(await signedRequest({ email: 'invalid' }));
    expect(result.body).toHaveProperty('error', 'invalid_request');
  });

  it('rejects invalid JSON and non-object JSON bodies', async () => {
    const middleware = createIssuerMiddleware(issuer, async () => true);
    const valid = await signedRequest();
    const requestWithBody = async (body: string) =>
      new Request(valid.url, {
        method: valid.method,
        headers: valid.headers,
        body,
      });

    for (const body of ['{', 'null', '[]', '"email"']) {
      const result = await middleware.handleIssuance(await requestWithBody(body));
      expect(result.body).toHaveProperty('error', 'invalid_request');
    }
  });

  it.each([
    [{ email: 'user@example.com', private_email: 'yes' }, 'private_email must be a boolean'],
    [{ email: 'user@example.com', directed_email: true }, 'directed_email must be a string'],
    [
      { email: 'user@example.com', private_email: true, directed_email: 'relay@private.example' },
      'mutually exclusive',
    ],
  ] as const)('rejects an invalid issuance option', async (body, message) => {
    const middleware = createIssuerMiddleware(issuer, async () => true);
    const result = await middleware.handleIssuance(await signedRequest({ ...body }));
    expect(result.body).toHaveProperty('error_description', expect.stringContaining(message));
  });

  it('returns a uniform authentication error', async () => {
    const middleware = createIssuerMiddleware(issuer, async () => false);
    const result = await middleware.handleIssuance(await signedRequest());
    expect(result.status).toBe(401);
    expect(result.body).toHaveProperty('error', 'authentication_required');
  });

  it('issues an evt+jwt token for a valid signed request', async () => {
    const verifyFn = vi.fn(async () => true);
    const middleware = createIssuerMiddleware(issuer, verifyFn);
    const result = await middleware.handleIssuance(
      await signedRequest({ email: 'user@example.com' }, 'session=abc123')
    );
    expect(result.status).toBe(200);
    expect(verifyFn).toHaveBeenCalledWith('session=abc123', 'user@example.com');
    const token = (result.body as { issuance_token: string }).issuance_token;
    expect(token).toMatch(/~$/);
    const header = decodeJWTPayload<{ typ: string }>(token.split('.')[0] ?? '');
    expect(header.typ).toBe('evt+jwt');
  });

  it('issues and marks a new private email', async () => {
    const middleware = createIssuerMiddleware(issuer, async () => true, {
      createPrivateEmail: async () => 'relay@private.example',
    });
    const result = await middleware.handleIssuance(
      await signedRequest({ email: 'user@example.com', private_email: true })
    );
    const token = (result.body as { issuance_token: string }).issuance_token;
    const payload = decodeJWTPayload<{ email: string; is_private_email: boolean }>(
      token.split('.')[1] ?? ''
    );
    expect(payload).toMatchObject({ email: 'relay@private.example', is_private_email: true });
  });

  it('rejects unsupported private email requests', async () => {
    const middleware = createIssuerMiddleware(issuer, async () => true);
    const result = await middleware.handleIssuance(
      await signedRequest({ email: 'user@example.com', private_email: true })
    );
    expect(result.body).toHaveProperty('error', 'private_email_not_supported');
  });

  it('rejects an invalid private email returned by the callback', async () => {
    const middleware = createIssuerMiddleware(issuer, async () => true, {
      createPrivateEmail: async () => 'not-an-email',
    });
    const result = await middleware.handleIssuance(
      await signedRequest({ email: 'user@example.com', private_email: true })
    );
    expect(result).toMatchObject({ status: 500 });
    expect(result.body).toHaveProperty('error', 'server_error');
  });

  it('rejects directed email when the capability is not configured', async () => {
    const middleware = createIssuerMiddleware(issuer, async () => true);
    const result = await middleware.handleIssuance(
      await signedRequest({
        email: 'user@example.com',
        directed_email: 'relay@private.example',
      })
    );
    expect(result.body).toHaveProperty('error', 'private_email_not_supported');
  });

  it('short-circuits an invalid directed email before invoking its callback', async () => {
    const verifyDirectedEmail = vi.fn(async () => true);
    const middleware = createIssuerMiddleware(issuer, async () => true, {
      verifyDirectedEmail,
    });
    const result = await middleware.handleIssuance(
      await signedRequest({ email: 'user@example.com', directed_email: 'invalid' })
    );
    expect(result.body).toHaveProperty('error', 'invalid_directed_email');
    expect(verifyDirectedEmail).not.toHaveBeenCalled();
  });

  it('issues a verified directed email', async () => {
    const middleware = createIssuerMiddleware(issuer, async () => true, {
      verifyDirectedEmail: async () => true,
    });
    const result = await middleware.handleIssuance(
      await signedRequest({
        email: 'user@example.com',
        directed_email: 'relay@private.example',
      })
    );
    expect(result.status).toBe(200);
  });

  it('rejects an unlinked directed email', async () => {
    const middleware = createIssuerMiddleware(issuer, async () => true, {
      verifyDirectedEmail: async () => false,
    });
    const result = await middleware.handleIssuance(
      await signedRequest({
        email: 'user@example.com',
        directed_email: 'other@private.example',
      })
    );
    expect(result.body).toHaveProperty('error', 'invalid_directed_email');
  });

  it('returns a WebAuthn challenge when cookie authentication fails', async () => {
    const middleware = createIssuerMiddleware(issuer, async () => false, {
      createWebAuthnChallenge: async () => ({ challenge: 'challenge', rpId: 'mail.example.com' }),
    });
    const result = await middleware.handleIssuance(await signedRequest());
    expect(result.status).toBe(401);
    expect(result.body).toHaveProperty('webauthn_challenge');
  });

  it('accepts a verified WebAuthn assertion', async () => {
    const verifyWebAuthnResponse = vi.fn(async () => true);
    const middleware = createIssuerMiddleware(issuer, async () => false, {
      verifyWebAuthnResponse,
    });
    const webauthn_response = {
      id: 'id',
      rawId: 'id',
      response: { authenticatorData: 'a', clientDataJSON: 'b', signature: 'c' },
      type: 'public-key',
    };
    const result = await middleware.handleIssuance(
      await signedRequest({ email: 'user@example.com', webauthn_response })
    );
    expect(result.status).toBe(200);
    expect(verifyWebAuthnResponse).toHaveBeenCalled();
  });

  it('rejects a WebAuthn assertion when verification fails or is unavailable', async () => {
    const webauthn_response = {
      id: 'id',
      rawId: 'id',
      response: { authenticatorData: 'a', clientDataJSON: 'b', signature: 'c' },
      type: 'public-key',
    };
    for (const options of [{ verifyWebAuthnResponse: async () => false }, {}]) {
      const middleware = createIssuerMiddleware(issuer, async () => false, options);
      const result = await middleware.handleIssuance(
        await signedRequest({ email: 'user@example.com', webauthn_response })
      );
      expect(result.body).toHaveProperty('error', 'authentication_required');
    }
  });

  it('normalizes unexpected issuer failures without leaking details', async () => {
    const failingIssuer = {
      issueToken: vi.fn(async () => {
        throw new Error('database password should not leak');
      }),
    } as unknown as EmailVerificationIssuer;
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const middleware = createIssuerMiddleware(failingIssuer, async () => true);
    const result = await middleware.handleIssuance(await signedRequest());
    expect(result).toMatchObject({
      status: 500,
      body: {
        error: 'server_error',
        error_description: 'Temporary server error, please try again later',
      },
    });
    expect(JSON.stringify(result.body)).not.toContain('database password');
    consoleError.mockRestore();
  });
});

describe('toResponse', () => {
  it('converts results and preserves custom headers', () => {
    const response = toResponse({
      status: 405,
      body: { error: 'invalid_request' },
      headers: { Allow: 'POST' },
    });
    expect(response.status).toBe(405);
    expect(response.headers.get('Content-Type')).toBe('application/json');
    expect(response.headers.get('Allow')).toBe('POST');
  });
});
