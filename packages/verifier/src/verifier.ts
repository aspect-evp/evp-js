/**
 * Email Verification Verifier
 *
 * Implementation of the EVP verifier for web applications (Relying Parties).
 */

import type {
  DnsResolver,
  IssuanceTokenHeader,
  IssuanceTokenPayload,
  KeyBindingPayload,
  VerificationResult,
  VerifierConfig,
} from '@aspect-evp/core';
import {
  DEFAULT_CLOCK_TOLERANCE,
  decodeJWTHeader,
  decodeJWTPayload,
  EVPError,
  getEmailDomain,
  isTimestampValid,
  KB_JWT_TYPE,
  parseSDJWTKB,
  SD_JWT_TYPE,
  sha256,
} from '@aspect-evp/core';
import { type JWK, jwtVerify } from 'jose';
import { defaultDnsResolver, resolveIssuer } from './dns.js';
import { createJWKSFetcher, fetchIssuerMetadata } from './jwks.js';

/**
 * Email Verification Verifier
 *
 * Use this class to verify EVP tokens received from browsers.
 * The verifier handles:
 * - Parsing SD-JWT+KB tokens
 * - DNS lookup for issuer discovery
 * - Fetching and verifying against issuer JWKS
 * - Validating all claims (nonce, audience, timestamps)
 *
 * @example
 * ```typescript
 * const verifier = new EmailVerificationVerifier({
 *   rpOrigin: 'https://myapp.example.com'
 * });
 *
 * const result = await verifier.verify(sdJwtKb, sessionNonce);
 * console.log('Verified email:', result.email);
 * ```
 */
export class EmailVerificationVerifier {
  private readonly config: {
    rpOrigin: string;
    dnsResolver: DnsResolver;
    fetch: typeof globalThis.fetch;
    clockTolerance: number;
    jwksCacheTTL: number;
  };

  constructor(config: VerifierConfig) {
    if (!config.rpOrigin) {
      throw new EVPError('invalid_request', 'RP origin is required');
    }

    // Validate origin format
    try {
      const url = new URL(config.rpOrigin);
      if (url.origin !== config.rpOrigin) {
        throw new EVPError(
          'invalid_request',
          `Invalid RP origin: must be exact origin without path (got ${config.rpOrigin})`
        );
      }
    } catch (e) {
      if (e instanceof EVPError) throw e;
      throw new EVPError('invalid_request', `Invalid RP origin: ${config.rpOrigin}`);
    }

    this.config = {
      rpOrigin: config.rpOrigin,
      dnsResolver: config.dnsResolver ?? defaultDnsResolver,
      fetch: config.fetch ?? globalThis.fetch,
      clockTolerance: config.clockTolerance ?? DEFAULT_CLOCK_TOLERANCE,
      jwksCacheTTL: config.jwksCacheTTL ?? 600,
    };
  }

  /**
   * Verify an SD-JWT+KB token
   *
   * @param sdJwtKb - The complete SD-JWT+KB token from the browser
   * @param expectedNonce - The nonce that was provided to the browser
   * @returns Verification result with email and metadata
   * @throws EVPError if verification fails
   *
   * @example
   * ```typescript
   * try {
   *   const result = await verifier.verify(token, sessionNonce);
   *   console.log('Email:', result.email);
   *   console.log('Issuer:', result.issuer);
   * } catch (error) {
   *   console.error('Verification failed:', error);
   * }
   * ```
   */
  async verify(sdJwtKb: string, expectedNonce: string): Promise<VerificationResult> {
    if (!sdJwtKb) {
      throw new EVPError('invalid_request', 'Token is required');
    }
    if (!expectedNonce) {
      throw new EVPError('invalid_request', 'Expected nonce is required');
    }

    // 1. Parse the token into SD-JWT and KB-JWT parts
    const { kbJwt, sdJwtForHash } = parseSDJWTKB(sdJwtKb);

    if (!kbJwt) {
      throw new EVPError('invalid_token', 'Token must include Key Binding JWT');
    }

    // 2. Decode SD-JWT header and payload (without verification yet)
    const sdJwtParts = sdJwtForHash.split('.');
    const headerPart = sdJwtParts[0];
    const payloadPart = sdJwtParts[1];

    if (!headerPart || !payloadPart) {
      throw new EVPError('invalid_token', 'Invalid SD-JWT structure');
    }

    const sdJwtHeader = decodeJWTHeader<IssuanceTokenHeader>(headerPart);
    const sdJwtPayload = decodeJWTPayload<IssuanceTokenPayload>(payloadPart);

    // 3. Validate SD-JWT header
    if (sdJwtHeader.typ !== SD_JWT_TYPE) {
      throw new EVPError(
        'invalid_token',
        `Invalid SD-JWT type: expected ${SD_JWT_TYPE}, got ${sdJwtHeader.typ}`
      );
    }

    // 4. Get email domain and resolve issuer via DNS
    const emailDomain = getEmailDomain(sdJwtPayload.email);
    const dnsIssuer = await resolveIssuer(emailDomain, this.config.dnsResolver);

    // 5. Verify SD-JWT issuer matches DNS
    if (sdJwtPayload.iss !== dnsIssuer) {
      throw new EVPError(
        'invalid_token',
        `Issuer mismatch: SD-JWT says ${sdJwtPayload.iss}, DNS says ${dnsIssuer}`
      );
    }

    // 6. Fetch issuer metadata and JWKS
    const issuerOrigin = `https://${dnsIssuer}`;
    const metadata = await fetchIssuerMetadata(issuerOrigin, this.config.fetch);
    const getKey = createJWKSFetcher(metadata.jwks_uri, {
      cacheTtl: this.config.jwksCacheTTL * 1000,
      fetch: this.config.fetch,
    });

    // 7. Verify SD-JWT signature
    try {
      await jwtVerify(sdJwtForHash, getKey, {
        algorithms: metadata.signing_alg_values_supported ?? [sdJwtHeader.alg],
      });
    } catch (error) {
      throw new EVPError(
        'invalid_token',
        `SD-JWT signature verification failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    // 8. Verify SD-JWT claims
    if (!sdJwtPayload.email_verified) {
      throw new EVPError('invalid_token', 'email_verified claim must be true');
    }

    if (!isTimestampValid(sdJwtPayload.iat, this.config.clockTolerance)) {
      throw new EVPError('invalid_token', 'SD-JWT timestamp is outside acceptable range');
    }

    // 9. Get browser's public key from cnf claim
    if (!sdJwtPayload.cnf?.jwk) {
      throw new EVPError('invalid_token', 'SD-JWT must include cnf.jwk claim');
    }

    const browserPublicKey = sdJwtPayload.cnf.jwk;

    // 10. Verify KB-JWT
    await this.verifyKeyBinding(kbJwt, browserPublicKey, sdJwtForHash, expectedNonce);

    // 11. Return verification result
    return {
      email: sdJwtPayload.email,
      email_verified: true,
      issuer: sdJwtPayload.iss,
      issuedAt: new Date(sdJwtPayload.iat * 1000),
    };
  }

  /**
   * Verify the Key Binding JWT
   */
  private async verifyKeyBinding(
    kbJwt: string,
    browserPublicKey: JsonWebKey,
    sdJwtForHash: string,
    expectedNonce: string
  ): Promise<void> {
    // Decode KB-JWT header
    const kbParts = kbJwt.split('.');
    const kbHeaderPart = kbParts[0];
    const kbPayloadPart = kbParts[1];

    if (!kbHeaderPart || !kbPayloadPart) {
      throw new EVPError('invalid_token', 'Invalid KB-JWT structure');
    }

    const kbHeader = decodeJWTHeader<{ typ: string; alg: string }>(kbHeaderPart);
    const kbPayload = decodeJWTPayload<KeyBindingPayload>(kbPayloadPart);

    // Validate KB-JWT header type
    if (kbHeader.typ !== KB_JWT_TYPE) {
      throw new EVPError(
        'invalid_token',
        `Invalid KB-JWT type: expected ${KB_JWT_TYPE}, got ${kbHeader.typ}`
      );
    }

    // Import browser's public key for verification
    const { importJWK } = await import('jose');
    const publicKey = await importJWK(browserPublicKey as JWK, kbHeader.alg);

    // Verify KB-JWT signature
    try {
      await jwtVerify(kbJwt, publicKey, {
        algorithms: [kbHeader.alg],
      });
    } catch (error) {
      throw new EVPError(
        'invalid_token',
        `KB-JWT signature verification failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    // Verify audience matches RP origin
    if (kbPayload.aud !== this.config.rpOrigin) {
      throw new EVPError(
        'invalid_token',
        `KB-JWT audience mismatch: expected ${this.config.rpOrigin}, got ${kbPayload.aud}`
      );
    }

    // Verify nonce
    if (kbPayload.nonce !== expectedNonce) {
      throw new EVPError('invalid_token', 'KB-JWT nonce mismatch: possible replay attack');
    }

    // Verify timestamp
    if (!isTimestampValid(kbPayload.iat, this.config.clockTolerance)) {
      throw new EVPError('invalid_token', 'KB-JWT timestamp is outside acceptable range');
    }

    // Verify sd_hash
    const expectedSdHash = await sha256(sdJwtForHash);
    if (kbPayload.sd_hash !== expectedSdHash) {
      throw new EVPError(
        'invalid_token',
        'KB-JWT sd_hash does not match SD-JWT: token may be tampered'
      );
    }
  }
}
