/**
 * Test Flow Utilities for EVP
 *
 * Provides utilities for creating complete test scenarios for the
 * Email Verification Protocol (WICG).
 *
 * @see https://datatracker.ietf.org/doc/draft-hardt-email-verification/
 */

import type { IssuerMetadata } from '../types.js';
import { sha256 } from '../utils.js';

/**
 * Configuration for creating a test flow.
 */
export interface TestFlowConfig {
  /**
   * The issuer hostname that will sign tokens.
   * @example 'accounts.google.com'
   */
  issuer: string;

  /**
   * The Relying Party origin that will verify tokens.
   * @example 'https://myapp.example.com'
   */
  rpOrigin: string;

  /**
   * Signing algorithm. Defaults to 'EdDSA' (Ed25519).
   */
  algorithm?: string;
}

/**
 * Test flow instance containing mocks and utilities for testing EVP.
 */
export interface TestFlow {
  /**
   * Issuer's public key in JWK format.
   * Use this to configure your own issuer instance if needed.
   */
  issuerPublicJwk: JsonWebKey;

  /**
   * Browser's public key in JWK format.
   * Included in the SD-JWT's `cnf` claim.
   */
  browserPublicJwk: JsonWebKey;

  /**
   * Issuer metadata as served at `/.well-known/email-verification`.
   */
  metadata: IssuerMetadata;

  /**
   * Mock DNS resolver. Always returns the configured issuer.
   * Pass this to `EmailVerificationVerifier` config.
   */
  dnsResolver: (domain: string) => Promise<string | null>;

  /**
   * Mock fetch that handles metadata and JWKS endpoints.
   * Pass this to `EmailVerificationVerifier` config.
   */
  fetch: typeof globalThis.fetch;

  /**
   * Creates a complete SD-JWT+KB token simulating the browser flow.
   *
   * @param email - The email address to include in the token
   * @param nonce - The nonce provided by the RP
   * @returns Complete SD-JWT+KB token ready for verification
   *
   * @example
   * ```typescript
   * const token = await testFlow.createToken('user@example.com', 'session-nonce');
   * const result = await verifier.verify(token, 'session-nonce');
   * ```
   */
  createToken: (email: string, nonce: string) => Promise<string>;
}

/**
 * Creates a complete test environment for EVP integration tests.
 *
 * This utility generates all the cryptographic material and mocks needed
 * to test the full verification flow without real DNS or network calls.
 *
 * @example
 * ```typescript
 * import { createTestFlow } from '@aspect-evp/core/testing';
 * import { EmailVerificationVerifier } from '@aspect-evp/verifier';
 *
 * const testFlow = await createTestFlow({
 *   issuer: 'issuer.example.com',
 *   rpOrigin: 'https://myapp.example.com',
 * });
 *
 * const verifier = new EmailVerificationVerifier({
 *   rpOrigin: 'https://myapp.example.com',
 *   dnsResolver: testFlow.dnsResolver,
 *   fetch: testFlow.fetch,
 * });
 *
 * const token = await testFlow.createToken('user@example.com', 'nonce-123');
 * const result = await verifier.verify(token, 'nonce-123');
 *
 * expect(result.email).toBe('user@example.com');
 * ```
 */
export async function createTestFlow(config: TestFlowConfig): Promise<TestFlow> {
  const { issuer, rpOrigin, algorithm = 'EdDSA' } = config;

  // Dynamic import - jose is a peer dependency
  const jose = await import('jose');

  // Generate key pairs
  const issuerKeys = await jose.generateKeyPair(algorithm as 'EdDSA');
  const browserKeys = await jose.generateKeyPair(algorithm as 'EdDSA');

  const issuerPublicJwk = await jose.exportJWK(issuerKeys.publicKey);
  const browserPublicJwk = await jose.exportJWK(browserKeys.publicKey);

  // Issuer metadata
  const metadata: IssuerMetadata = {
    issuance_endpoint: `https://${issuer}/email-verification/issuance`,
    jwks_uri: `https://${issuer}/email-verification/jwks`,
    signing_alg_values_supported: [algorithm],
  };

  // Mock DNS resolver
  const dnsResolver = async (_domain: string): Promise<string | null> => issuer;

  // Mock fetch for metadata and JWKS
  const mockFetch = async (url: string | URL | Request): Promise<Response> => {
    const urlStr = url.toString();

    if (urlStr.includes('/.well-known/email-verification')) {
      return new Response(JSON.stringify(metadata), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (urlStr.includes('/jwks')) {
      return new Response(
        JSON.stringify({
          keys: [{ ...issuerPublicJwk, kid: 'test-key-1', use: 'sig', alg: algorithm }],
        }),
        { headers: { 'Content-Type': 'application/json' } }
      );
    }

    return new Response('Not found', { status: 404 });
  };

  // Token creation (simulates browser + issuer interaction)
  const createToken = async (email: string, nonce: string): Promise<string> => {
    const iat = Math.floor(Date.now() / 1000);

    // SD-JWT (signed by issuer, contains email and browser's public key)
    const sdJwt = await new jose.SignJWT({
      iss: issuer,
      iat,
      email,
      email_verified: true,
      cnf: { jwk: browserPublicJwk },
    })
      .setProtectedHeader({ alg: algorithm, typ: 'evt+jwt', kid: 'test-key-1' })
      .sign(issuerKeys.privateKey);

    // KB-JWT (signed by browser, binds token to RP)
    const kbJwt = await new jose.SignJWT({
      aud: rpOrigin,
      nonce,
      iat,
      sd_hash: await sha256(`${sdJwt}~`),
    })
      .setProtectedHeader({ alg: algorithm, typ: 'kb+jwt' })
      .sign(browserKeys.privateKey);

    return `${sdJwt}~${kbJwt}`;
  };

  return {
    issuerPublicJwk,
    browserPublicJwk,
    metadata,
    dnsResolver,
    fetch: mockFetch,
    createToken,
  };
}

/**
 * Generates a cryptographically random nonce for testing.
 *
 * @param length - Byte length of the nonce (default: 16)
 * @returns Base64url-encoded random string
 */
export function generateNonce(length = 16): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
