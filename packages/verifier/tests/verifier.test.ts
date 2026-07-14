import { base64url, EVPError, getCurrentTimestamp, sha256 } from '@aspect-evp/core';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
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

    it('should reject a non-HTTPS rpOrigin', () => {
      expect(() => new EmailVerificationVerifier({ rpOrigin: 'http://myapp.example.com' })).toThrow(
        'exact HTTPS origin'
      );
    });

    it('should throw for a malformed rpOrigin', () => {
      expect(() => new EmailVerificationVerifier({ rpOrigin: 'not a URL' })).toThrow(
        'Invalid RP origin'
      );
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
        .setProtectedHeader({ alg: 'EdDSA', typ: 'evt+jwt', kid: 'key-1' })
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
        isPrivateEmail?: boolean;
        evtOverrides?: Record<string, unknown>;
        evtHeaderOverrides?: Record<string, unknown>;
        kbOverrides?: Record<string, unknown>;
        kbHeaderOverrides?: Record<string, unknown>;
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
        sdJwtType = 'evt+jwt',
        kbJwtType = 'kb+jwt',
        wrongSdHash = false,
        isPrivateEmail = false,
        evtOverrides = {},
        evtHeaderOverrides = {},
        kbOverrides = {},
        kbHeaderOverrides = {},
      } = options;

      // Create SD-JWT
      const sdJwt = await new SignJWT({
        iss: issuer,
        email,
        email_verified: emailVerified,
        iat: sdJwtIat,
        cnf: { jwk: browserPublicJwk },
        ...(isPrivateEmail ? { is_private_email: true } : {}),
        ...evtOverrides,
      })
        .setProtectedHeader({
          alg: 'EdDSA',
          typ: sdJwtType as 'evt+jwt',
          kid: 'key-1',
          ...evtHeaderOverrides,
        })
        .sign(issuerKeyPair.privateKey);

      // Calculate sd_hash
      const sdHash = wrongSdHash ? 'wrong-hash' : await sha256(`${sdJwt}~`);

      // Create KB-JWT
      const kbJwt = await new SignJWT({
        aud: rpOrigin,
        nonce,
        iat: kbJwtIat,
        sd_hash: sdHash,
        ...kbOverrides,
      })
        .setProtectedHeader({ alg: 'EdDSA', typ: kbJwtType as 'kb+jwt', ...kbHeaderOverrides })
        .sign(browserKeyPair.privateKey);

      return `${sdJwt}~${kbJwt}`;
    }

    function mockFetch(): typeof globalThis.fetch {
      return vi.fn(async (url: string | URL | Request) => {
        if (String(url).includes('/.well-known/email-verification')) {
          return new Response(
            JSON.stringify({
              issuance_endpoint: 'https://issuer.example.com/issuance',
              jwks_uri: 'https://issuer.example.com/jwks',
              signing_alg_values_supported: ['EdDSA'],
            })
          );
        }
        return new Response(
          JSON.stringify({
            keys: [{ ...issuerPublicJwk, kid: 'key-1', use: 'sig', alg: 'EdDSA' }],
          })
        );
      }) as typeof globalThis.fetch;
    }

    function verifier(dnsIssuer = 'issuer.example.com'): EmailVerificationVerifier {
      return new EmailVerificationVerifier({
        rpOrigin: 'https://myapp.example.com',
        dnsResolver: async () => dnsIssuer,
        fetch: mockFetch(),
      });
    }

    function replaceHeader(jwt: string, header: Record<string, unknown>): string {
      const parts = jwt.split('.');
      parts[0] = base64url(new TextEncoder().encode(JSON.stringify(header)));
      return parts.join('.');
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

    it('should surface a verified private email marker', async () => {
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
        return new Response(
          JSON.stringify({
            keys: [{ ...issuerPublicJwk, kid: 'key-1', use: 'sig', alg: 'EdDSA' }],
          })
        );
      });
      const verifier = new EmailVerificationVerifier({
        rpOrigin: 'https://myapp.example.com',
        dnsResolver: mockResolver,
        fetch: mockFetch,
      });
      const result = await verifier.verify(
        await createTestToken({
          email: 'relay@private.example',
          isPrivateEmail: true,
        }),
        'test-nonce'
      );
      expect(result.isPrivateEmail).toBe(true);
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

    it.each([
      [{ sdJwtType: 'JWT' }, 'Invalid EVT type'],
      [{ evtOverrides: { iss: 'issuer.example.com/path' } }, 'invalid issuer identifier'],
      [{ evtOverrides: { iss: '%' } }, 'invalid issuer identifier'],
      [{ evtOverrides: { email: 'invalid' } }, 'invalid email claim'],
      [{ evtOverrides: { iat: 1.5 } }, 'iat must be an integer'],
      [{ emailVerified: false }, 'email_verified claim must be true'],
      [{ sdJwtIat: 0 }, 'EVT timestamp is outside acceptable range'],
      [{ evtOverrides: { cnf: undefined } }, 'must include cnf.jwk'],
      [{ evtOverrides: { is_private_email: false } }, 'is_private_email must be true'],
      [{ kbJwtType: 'JWT' }, 'Invalid KB-JWT type'],
      [{ kbOverrides: { aud: 42 } }, 'KB-JWT contains invalid required claims'],
      [{ kbJwtIat: 0 }, 'KB-JWT timestamp is outside acceptable range'],
    ] as const)('rejects invalid signed token claims %#', async (options, message) => {
      await expect(verifier().verify(await createTestToken(options), 'test-nonce')).rejects.toThrow(
        message
      );
    });

    it('requires a supported algorithm and kid in the EVT header', async () => {
      const token = await createTestToken();
      const [sdJwt, kbJwt] = token.split('~');
      expect(sdJwt).toBeDefined();
      expect(kbJwt).toBeDefined();
      for (const header of [
        { alg: 'EdDSA', typ: 'evt+jwt' },
        { alg: 'HS256', typ: 'evt+jwt', kid: 'key-1' },
      ]) {
        const changed = `${replaceHeader(sdJwt ?? '', header)}~${kbJwt}`;
        await expect(verifier().verify(changed, 'test-nonce')).rejects.toThrow(
          'supported alg and a kid'
        );
      }
    });

    it('requires a supported KB-JWT algorithm', async () => {
      const token = await createTestToken();
      const [sdJwt, kbJwt] = token.split('~');
      const changedKb = replaceHeader(kbJwt ?? '', { alg: 'HS256', typ: 'kb+jwt' });
      await expect(verifier().verify(`${sdJwt}~${changedKb}`, 'test-nonce')).rejects.toThrow(
        'unsupported algorithm'
      );
    });

    it('rejects empty encoded JWT components', async () => {
      await expect(verifier().verify('.payload.signature~a.b.c', 'test-nonce')).rejects.toThrow(
        'Invalid SD-JWT structure'
      );

      const token = await createTestToken();
      const [sdJwt, kbJwt] = token.split('~');
      const kbParts = (kbJwt ?? '').split('.');
      kbParts[0] = '';
      await expect(
        verifier().verify(`${sdJwt}~${kbParts.join('.')}`, 'test-nonce')
      ).rejects.toThrow('Invalid KB-JWT structure');
    });

    it('rejects an invalid confirmation key', async () => {
      const token = await createTestToken({
        evtOverrides: { cnf: { jwk: { kty: 'invalid' } } },
      });
      await expect(verifier().verify(token, 'test-nonce')).rejects.toThrow('Invalid cnf.jwk');
    });

    it('wraps invalid issuer and key-binding signatures', async () => {
      const token = await createTestToken();
      const [sdJwt, kbJwt] = token.split('~');
      const sdParts = (sdJwt ?? '').split('.');
      sdParts[2] = 'AAAA';
      await expect(
        verifier().verify(`${sdParts.join('.')}~${kbJwt}`, 'test-nonce')
      ).rejects.toThrow('SD-JWT signature verification failed');

      const kbParts = (kbJwt ?? '').split('.');
      kbParts[2] = 'AAAA';
      await expect(
        verifier().verify(`${sdJwt}~${kbParts.join('.')}`, 'test-nonce')
      ).rejects.toThrow('KB-JWT signature verification failed');
    });
  });
});
