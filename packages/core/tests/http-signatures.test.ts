import { exportJWK, generateKeyPair } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { createSignedIssuanceRequest, verifyHttpMessageSignature } from '../src/http-signatures.js';
import { getCurrentTimestamp } from '../src/utils.js';

describe('EVP HTTP Message Signatures', () => {
  let privateKey: JsonWebKey;

  beforeAll(async () => {
    const pair = await generateKeyPair('EdDSA', { extractable: true });
    privateKey = await exportJWK(pair.privateKey);
  });

  async function withHeaders(
    request: Request,
    changes: Record<string, string | null>
  ): Promise<Request> {
    const headers = new Headers(request.headers);
    for (const [name, value] of Object.entries(changes)) {
      if (value === null) headers.delete(name);
      else headers.set(name, value);
    }
    return new Request(request.url, {
      method: request.method,
      headers,
      body: await request.text(),
    });
  }

  it('signs and verifies the required draft profile', async () => {
    const request = await createSignedIssuanceRequest(
      'https://issuer.example/email-verification/issuance',
      { email: 'user@example.com' },
      privateKey
    );
    const result = await verifyHttpMessageSignature(request);
    expect(result.algorithm).toBe('EdDSA');
    expect(result.coveredComponents).toEqual(['@method', '@authority', '@path', 'signature-key']);
  });

  it('binds cookies when they are present', async () => {
    const request = await createSignedIssuanceRequest(
      'https://issuer.example/email-verification/issuance',
      { email: 'user@example.com' },
      privateKey,
      { cookie: 'session=abc' }
    );
    const result = await verifyHttpMessageSignature(request);
    expect(result.coveredComponents).toContain('cookie');
  });

  it.each([
    'ES256',
    'ES384',
    'RS256',
  ] as const)('round-trips the %s HTTP signature profile', async (algorithm) => {
    const pair = await generateKeyPair(algorithm, { extractable: true });
    const key = await exportJWK(pair.privateKey);
    const request = await createSignedIssuanceRequest(
      'https://issuer.example/email-verification/issuance',
      { email: 'user@example.com' },
      key
    );
    await expect(verifyHttpMessageSignature(request)).resolves.toMatchObject({ algorithm });
  });

  it('rejects a request replayed against another path', async () => {
    const request = await createSignedIssuanceRequest(
      'https://issuer.example/email-verification/issuance',
      { email: 'user@example.com' },
      privateKey
    );
    const replay = new Request('https://issuer.example/other', request);
    await expect(verifyHttpMessageSignature(replay)).rejects.toThrow(
      'HTTP Message Signature verification failed'
    );
  });

  it('rejects stale signatures', async () => {
    const request = await createSignedIssuanceRequest(
      'https://issuer.example/email-verification/issuance',
      { email: 'user@example.com' },
      privateKey,
      { created: getCurrentTimestamp() - 61 }
    );
    await expect(verifyHttpMessageSignature(request)).rejects.toThrow('timestamp');
  });

  it('rejects cookie injection when cookie was not covered', async () => {
    const request = await createSignedIssuanceRequest(
      'https://issuer.example/email-verification/issuance',
      { email: 'user@example.com' },
      privateKey
    );
    const headers = new Headers(request.headers);
    headers.set('Cookie', 'session=attacker');
    const injected = new Request(request.url, {
      method: request.method,
      headers,
      body: await request.text(),
    });
    await expect(verifyHttpMessageSignature(injected)).rejects.toThrow('Cookie coverage');
  });

  it('supports an origin path and caller-supplied headers', async () => {
    const request = await createSignedIssuanceRequest(
      'https://issuer.example',
      { email: 'user@example.com' },
      privateKey,
      { headers: { 'X-Request-ID': 'request-1' } }
    );
    await expect(verifyHttpMessageSignature(request)).resolves.toMatchObject({
      algorithm: 'EdDSA',
    });
    expect(request.headers.get('X-Request-ID')).toBe('request-1');
  });

  it('rejects unsupported signing keys', async () => {
    await expect(
      createSignedIssuanceRequest('https://issuer.example/issuance', {}, {
        kty: 'oct',
        k: 'c2VjcmV0',
      } as JsonWebKey)
    ).rejects.toThrow('Unsupported HTTP signature key');
  });

  it.each([
    ['Signature-Input', 'not-a-signature-input', 'Malformed Signature-Input'],
    ['Signature', 'sig=not-wrapped', 'Malformed Signature header'],
    ['Signature', 'sig=:A:', 'Malformed signature bytes'],
    ['Signature-Key', 'not-a-key', 'Malformed Signature-Key header'],
    ['Signature-Key', 'sig=hwk; bad', 'Malformed Signature-Key parameter'],
    ['Signature-Key', 'sig=hwk; crv="Ed25519"', 'Signature-Key is missing kty'],
    ['Signature-Key', 'sig=hwk; kty="oct"', 'Unsupported HTTP signature key'],
  ] as const)('rejects malformed %s values', async (header, value, message) => {
    const request = await createSignedIssuanceRequest(
      'https://issuer.example/issuance',
      {},
      privateKey
    );
    await expect(
      verifyHttpMessageSignature(await withHeaders(request, { [header]: value }))
    ).rejects.toThrow(message);
  });

  it('rejects requests missing any signature header', async () => {
    const request = await createSignedIssuanceRequest(
      'https://issuer.example/issuance',
      {},
      privateKey
    );
    await expect(
      verifyHttpMessageSignature(await withHeaders(request, { Signature: null }))
    ).rejects.toThrow('Missing HTTP Message Signature headers');
  });

  it('requires every profile component to be covered', async () => {
    const request = await createSignedIssuanceRequest(
      'https://issuer.example/issuance',
      {},
      privateKey
    );
    const created = getCurrentTimestamp();
    const signatureInput = `sig=("@method" "@authority" "signature-key");created=${created}`;
    await expect(
      verifyHttpMessageSignature(await withHeaders(request, { 'Signature-Input': signatureInput }))
    ).rejects.toThrow('Signature does not cover @path');
  });

  it('rejects a covered component that is absent from the request', async () => {
    const request = await createSignedIssuanceRequest(
      'https://issuer.example/issuance',
      {},
      privateKey
    );
    const created = getCurrentTimestamp();
    const signatureInput = `sig=("@method" "@authority" "@path" "x-missing" "signature-key");created=${created}`;
    await expect(
      verifyHttpMessageSignature(await withHeaders(request, { 'Signature-Input': signatureInput }))
    ).rejects.toThrow('Covered component is missing: x-missing');
  });
});
