import { EVPError, getCurrentTimestamp, sha256 } from '@evp/core';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { EmailVerificationVerifier } from '../src/verifier.js';

describe('EmailVerificationVerifier', () => {
  let issuerKeyPair: CryptoKeyPair;
  let browserKeyPair: CryptoKeyPair;
  let issuerPublicJwk: JsonWebKey;
  let browserPublicJwk: JsonWebKey;

  beforeAll(async () => {
    issuerKeyPair = await generateKeyPair('EdDSA');
    browserKeyPair = await generateKeyPair('EdDSA');

    issuerPublicJwk = await exportJWK(issuerKeyPair.publicKey);
    browserPublicJwk = await exportJWK(browserKeyPair.publicKey);
  });

  describe('constructor', () => {
    it('should create verifier with valid config', () => {
      const verifier = new EmailVerificationVerifier({
        rpOrigin: 'https://myapp.example.com',
      });
      expect(verifier).toBeInstanceOf(EmailVerificationVerifier);
    });

    it('should throw for missing rpOrigin', () => {
      expect(
        () =>
          new EmailVerificationVerifier({
            rpOrigin: '',
          })
      ).toThrow(EVPError);
    });

    it('should throw for invalid rpOrigin with path', () => {
      expect(
        () =>
          new EmailVerificationVerifier({
            rpOrigin: 'https://myapp.example.com/path',
          })
      ).toThrow('Invalid RP origin');
    });

    it('should throw for rpOrigin with trailing slash', () => {
      expect(
        () =>
          new EmailVerificationVerifier({
            rpOrigin: 'https://myapp.example.com/',
          })
      ).toThrow('Invalid RP origin');
    });

    it('should accept custom dnsResolver', () => {
      const customResolver = vi.fn(async () => 'issuer.example.com');
      const verifier = new EmailVerificationVerifier({
        rpOrigin: 'https://myapp.example.com',
        dnsResolver: customResolver,
      });
      expect(verifier).toBeInstanceOf(EmailVerificationVerifier);
    });
  });

  describe('verify', () => {
    it('should reject empty token', async () => {
      const verifier = new EmailVerificationVerifier({
        rpOrigin: 'https://myapp.example.com',
      });

      await expect(verifier.verify('', 'nonce')).rejects.toThrow('Token is required');
    });

    it('should reject empty nonce', async () => {
      const verifier = new EmailVerificationVerifier({
        rpOrigin: 'https://myapp.example.com',
      });

      await expect(verifier.verify('token~', '')).rejects.toThrow('Expected nonce is required');
    });

    it('should reject token without KB-JWT', async () => {
      const verifier = new EmailVerificationVerifier({
        rpOrigin: 'https://myapp.example.com',
      });

      // Create a valid SD-JWT but without KB-JWT
      const sdJwt = await new SignJWT({
        iss: 'issuer.example.com',
        email: 'user@example.com',
        email_verified: true,
        iat: getCurrentTimestamp(),
        cnf: { jwk: browserPublicJwk },
      })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'evp+sd-jwt', kid: 'key-1' })
        .sign(issuerKeyPair.privateKey);

      await expect(verifier.verify(`${sdJwt}~`, 'nonce')).rejects.toThrow(
        'must include Key Binding JWT'
      );
    });
  });

  describe('full verification flow', () => {
    async function createTestToken(
      options: {
        issuer?: string;
        email?: string;
        rpOrigin?: string;
        nonce?: string;
        sdJwtIat?: number;
        kbJwtIat?: number;
        emailVerified?: boolean;
        sdJwtType?: string;
        kbJwtType?: string;
        wrongSdHash?: boolean;
      } = {}
    ): Promise<string> {
      const {
        issuer = 'issuer.example.com',
        email = 'user@example.com',
        rpOrigin = 'https://myapp.example.com',
        nonce = 'test-nonce',
        sdJwtIat = getCurrentTimestamp(),
        kbJwtIat = getCurrentTimestamp(),
        emailVerified = true,
        sdJwtType = 'evp+sd-jwt',
        kbJwtType = 'kb+jwt',
        wrongSdHash = false,
      } = options;

      // Create SD-JWT
      const sdJwt = await new SignJWT({
        iss: issuer,
        email,
        email_verified: emailVerified,
        iat: sdJwtIat,
        cnf: { jwk: browserPublicJwk },
      })
        .setProtectedHeader({ alg: 'EdDSA', typ: sdJwtType as 'evp+sd-jwt', kid: 'key-1' })
        .sign(issuerKeyPair.privateKey);

      // Calculate sd_hash
      const sdHash = wrongSdHash ? 'wrong-hash' : await sha256(sdJwt);

      // Create KB-JWT
      const kbJwt = await new SignJWT({
        aud: rpOrigin,
        nonce,
        iat: kbJwtIat,
        sd_hash: sdHash,
      })
        .setProtectedHeader({ alg: 'EdDSA', typ: kbJwtType as 'kb+jwt' })
        .sign(browserKeyPair.privateKey);

      return `${sdJwt}~${kbJwt}`;
    }

    it('should verify valid token with mock resolver', async () => {
      const mockResolver = vi.fn(async () => 'issuer.example.com');
      const mockFetch = vi.fn(async (url: string) => {
        if (url.includes('/.well-known/email-verification')) {
          return new Response(
            JSON.stringify({
              issuance_endpoint: 'https://issuer.example.com/issuance',
              jwks_uri: 'https://issuer.example.com/jwks',
              signing_alg_values_supported: ['EdDSA'],
            })
          );
        }
        if (url.includes('/jwks')) {
          return new Response(
            JSON.stringify({
              keys: [{ ...issuerPublicJwk, kid: 'key-1', use: 'sig', alg: 'EdDSA' }],
            })
          );
        }
        return new Response('Not found', { status: 404 });
      });

      const verifier = new EmailVerificationVerifier({
        rpOrigin: 'https://myapp.example.com',
        dnsResolver: mockResolver,
        fetch: mockFetch,
      });

      const token = await createTestToken();
      const result = await verifier.verify(token, 'test-nonce');

      expect(result.email).toBe('user@example.com');
      expect(result.email_verified).toBe(true);
      expect(result.issuer).toBe('issuer.example.com');
      expect(result.issuedAt).toBeInstanceOf(Date);
    });

    it('should reject token with wrong nonce', async () => {
      const mockResolver = vi.fn(async () => 'issuer.example.com');
      const mockFetch = vi.fn(async (url: string) => {
        if (url.includes('/.well-known/email-verification')) {
          return new Response(
            JSON.stringify({
              issuance_endpoint: 'https://issuer.example.com/issuance',
              jwks_uri: 'https://issuer.example.com/jwks',
            })
          );
        }
        if (url.includes('/jwks')) {
          return new Response(
            JSON.stringify({
              keys: [{ ...issuerPublicJwk, kid: 'key-1', use: 'sig', alg: 'EdDSA' }],
            })
          );
        }
        return new Response('Not found', { status: 404 });
      });

      const verifier = new EmailVerificationVerifier({
        rpOrigin: 'https://myapp.example.com',
        dnsResolver: mockResolver,
        fetch: mockFetch,
      });

      const token = await createTestToken({ nonce: 'correct-nonce' });

      await expect(verifier.verify(token, 'wrong-nonce')).rejects.toThrow('nonce mismatch');
    });

    it('should reject token with wrong audience', async () => {
      const mockResolver = vi.fn(async () => 'issuer.example.com');
      const mockFetch = vi.fn(async (url: string) => {
        if (url.includes('/.well-known/email-verification')) {
          return new Response(
            JSON.stringify({
              issuance_endpoint: 'https://issuer.example.com/issuance',
              jwks_uri: 'https://issuer.example.com/jwks',
            })
          );
        }
        if (url.includes('/jwks')) {
          return new Response(
            JSON.stringify({
              keys: [{ ...issuerPublicJwk, kid: 'key-1', use: 'sig', alg: 'EdDSA' }],
            })
          );
        }
        return new Response('Not found', { status: 404 });
      });

      const verifier = new EmailVerificationVerifier({
        rpOrigin: 'https://myapp.example.com',
        dnsResolver: mockResolver,
        fetch: mockFetch,
      });

      const token = await createTestToken({ rpOrigin: 'https://evil.com' });

      await expect(verifier.verify(token, 'test-nonce')).rejects.toThrow('audience mismatch');
    });

    it('should reject token with wrong sd_hash', async () => {
      const mockResolver = vi.fn(async () => 'issuer.example.com');
      const mockFetch = vi.fn(async (url: string) => {
        if (url.includes('/.well-known/email-verification')) {
          return new Response(
            JSON.stringify({
              issuance_endpoint: 'https://issuer.example.com/issuance',
              jwks_uri: 'https://issuer.example.com/jwks',
            })
          );
        }
        if (url.includes('/jwks')) {
          return new Response(
            JSON.stringify({
              keys: [{ ...issuerPublicJwk, kid: 'key-1', use: 'sig', alg: 'EdDSA' }],
            })
          );
        }
        return new Response('Not found', { status: 404 });
      });

      const verifier = new EmailVerificationVerifier({
        rpOrigin: 'https://myapp.example.com',
        dnsResolver: mockResolver,
        fetch: mockFetch,
      });

      const token = await createTestToken({ wrongSdHash: true });

      await expect(verifier.verify(token, 'test-nonce')).rejects.toThrow('sd_hash does not match');
    });

    it('should reject token with issuer mismatch', async () => {
      const mockResolver = vi.fn(async () => 'different-issuer.com');
      const mockFetch = vi.fn(async () => new Response('Not found', { status: 404 }));

      const verifier = new EmailVerificationVerifier({
        rpOrigin: 'https://myapp.example.com',
        dnsResolver: mockResolver,
        fetch: mockFetch,
      });

      const token = await createTestToken({ issuer: 'issuer.example.com' });

      await expect(verifier.verify(token, 'test-nonce')).rejects.toThrow('Issuer mismatch');
    });
  });
});
