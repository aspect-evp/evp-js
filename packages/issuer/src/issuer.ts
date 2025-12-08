/**
 * Email Verification Issuer
 *
 * Implementation of the EVP issuer for email providers.
 */

import type {
  IssuerConfig,
  IssuerMetadata,
  JWKS,
  KeyPair,
  RequestTokenHeader,
  RequestTokenPayload,
  RequestTokenVerifyResult,
  SupportedAlgorithm,
} from '@aspect-evp/core';
import {
  DEFAULT_ALGORITHM,
  DEFAULT_CLOCK_TOLERANCE,
  EVPError,
  SD_JWT_TYPE,
  WELL_KNOWN_PATH,
  decodeJWTHeader,
  getCurrentTimestamp,
  isTimestampValid,
} from '@aspect-evp/core';
import { type JWK, SignJWT, exportJWK, importJWK, jwtVerify } from 'jose';
import { generateKeyPair, isAlgorithmSupported } from './keys.js';

/**
 * Email Verification Issuer
 *
 * Use this class to implement an EVP issuer for your email provider.
 * The issuer is responsible for:
 * - Serving metadata at /.well-known/email-verification
 * - Serving JWKS with public keys
 * - Verifying request tokens from browsers
 * - Issuing SD-JWT tokens for verified emails
 *
 * @example
 * ```typescript
 * const issuer = new EmailVerificationIssuer({
 *   issuer: 'mail.example.com',
 *   privateKey: yourPrivateKeyJWK,
 *   kid: '2024-01-key',
 *   algorithm: 'EdDSA'
 * });
 *
 * // Serve metadata
 * app.get('/.well-known/email-verification', (req, res) => {
 *   res.json(issuer.getMetadata('https://mail.example.com'));
 * });
 * ```
 */
export class EmailVerificationIssuer {
  private readonly config: Required<
    Pick<IssuerConfig, 'issuer' | 'privateKey' | 'kid' | 'algorithm' | 'clockTolerance'>
  >;

  constructor(config: IssuerConfig) {
    // Validate required fields
    if (!config.issuer) {
      throw new EVPError('invalid_request', 'Issuer identifier is required');
    }
    if (!config.privateKey) {
      throw new EVPError('invalid_request', 'Private key is required');
    }
    if (!config.kid) {
      throw new EVPError('invalid_request', 'Key ID (kid) is required');
    }

    const algorithm = config.algorithm ?? DEFAULT_ALGORITHM;
    if (!isAlgorithmSupported(algorithm)) {
      throw new EVPError('invalid_request', `Unsupported algorithm: ${algorithm}`);
    }

    this.config = {
      issuer: config.issuer,
      privateKey: config.privateKey,
      kid: config.kid,
      algorithm,
      clockTolerance: config.clockTolerance ?? DEFAULT_CLOCK_TOLERANCE,
    };
  }

  /**
   * Get issuer metadata for /.well-known/email-verification
   *
   * @param baseUrl - The base URL of your issuer (e.g., 'https://mail.example.com')
   * @returns IssuerMetadata object to be served as JSON
   */
  getMetadata(baseUrl: string): IssuerMetadata {
    // Normalize baseUrl (remove trailing slash)
    const normalizedUrl = baseUrl.replace(/\/$/, '');

    return {
      issuance_endpoint: `${normalizedUrl}/email-verification/issuance`,
      jwks_uri: `${normalizedUrl}/email-verification/jwks`,
      signing_alg_values_supported: [this.config.algorithm],
    };
  }

  /**
   * Get the JWKS containing public keys
   *
   * @returns JWKS with the issuer's public key(s)
   */
  async getJWKS(): Promise<JWKS> {
    // Import the private key to extract public key
    const privateKey = await importJWK(this.config.privateKey as JWK, this.config.algorithm);

    // Export the public key
    const fullJwk = await exportJWK(privateKey);

    // Create public key by extracting only public components
    // The destructured private key components are intentionally unused
    const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, ...publicComponents } = fullJwk;

    // Build public JWK with required fields for JWKS
    const publicJwk = {
      ...publicComponents,
      kid: this.config.kid,
      use: 'sig',
      alg: this.config.algorithm,
    } as JsonWebKey;

    return {
      keys: [publicJwk],
    };
  }

  /**
   * Verify a request token from the browser
   *
   * The request token is created by the browser and signed with an ephemeral key.
   * This method verifies:
   * - The token is properly signed
   * - The audience matches this issuer
   * - The timestamp is within tolerance
   *
   * @param requestToken - The JWT from the browser
   * @returns The decoded payload and browser's public key
   * @throws EVPError if verification fails
   */
  async verifyRequestToken(requestToken: string): Promise<RequestTokenVerifyResult> {
    if (!requestToken) {
      throw new EVPError('invalid_request', 'Request token is required');
    }

    // Parse token to extract header
    const parts = requestToken.split('.');
    if (parts.length !== 3) {
      throw new EVPError('invalid_token', 'Invalid JWT format');
    }

    const headerPart = parts[0];
    if (!headerPart) {
      throw new EVPError('invalid_token', 'Missing JWT header');
    }

    // Decode header to get the browser's public key
    const header = decodeJWTHeader<RequestTokenHeader>(headerPart);

    if (!header.jwk) {
      throw new EVPError('invalid_token', 'Request token must include jwk in header');
    }

    if (header.typ !== 'JWT') {
      throw new EVPError('invalid_token', 'Request token typ must be JWT');
    }

    // Import the browser's public key from the header
    const browserPublicKey = await importJWK(header.jwk as JWK, header.alg);

    try {
      // Verify the token signature using the browser's public key
      const { payload } = await jwtVerify(requestToken, browserPublicKey, {
        algorithms: [header.alg],
      });

      const tokenPayload = payload as unknown as RequestTokenPayload;

      // Verify audience matches our issuer
      if (tokenPayload.aud !== this.config.issuer) {
        throw new EVPError(
          'invalid_token',
          `Invalid audience: expected ${this.config.issuer}, got ${tokenPayload.aud}`
        );
      }

      // Verify timestamp is within tolerance
      if (!isTimestampValid(tokenPayload.iat, this.config.clockTolerance)) {
        throw new EVPError('invalid_token', 'Token timestamp is outside acceptable range');
      }

      // Verify email is present
      if (!tokenPayload.email) {
        throw new EVPError('invalid_token', 'Token must include email claim');
      }

      return {
        payload: tokenPayload,
        browserPublicKey: header.jwk,
      };
    } catch (error) {
      if (error instanceof EVPError) {
        throw error;
      }
      throw new EVPError(
        'invalid_token',
        `Token verification failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Issue an SD-JWT for a verified email
   *
   * Call this after:
   * 1. Verifying the request token
   * 2. Confirming the user owns the email address
   *
   * @param email - The verified email address
   * @param browserPublicKey - The browser's public key from the request token
   * @returns SD-JWT token (ends with ~)
   */
  async issueToken(email: string, browserPublicKey: JsonWebKey): Promise<string> {
    if (!email) {
      throw new EVPError('invalid_request', 'Email is required');
    }
    if (!browserPublicKey) {
      throw new EVPError('invalid_request', 'Browser public key is required');
    }

    // Import our private key
    const privateKey = await importJWK(this.config.privateKey as JWK, this.config.algorithm);

    // Create the SD-JWT payload
    const now = getCurrentTimestamp();
    const payload = {
      iss: this.config.issuer,
      iat: now,
      email,
      email_verified: true,
      cnf: {
        jwk: browserPublicKey,
      },
    };

    // Sign the JWT
    const jwt = await new SignJWT(payload)
      .setProtectedHeader({
        alg: this.config.algorithm,
        typ: SD_JWT_TYPE,
        kid: this.config.kid,
      })
      .sign(privateKey);

    // SD-JWT format: jwt~ (no disclosures for EVP)
    return `${jwt}~`;
  }

  /**
   * Get the well-known path for issuer metadata
   */
  static get wellKnownPath(): string {
    return WELL_KNOWN_PATH;
  }

  /**
   * Generate a new signing keypair
   *
   * Convenience method that wraps the generateKeyPair utility.
   *
   * @param algorithm - Signing algorithm (default: 'EdDSA')
   * @returns Generated keypair
   */
  static generateKeyPair(algorithm?: SupportedAlgorithm): Promise<KeyPair> {
    return generateKeyPair(algorithm);
  }
}
