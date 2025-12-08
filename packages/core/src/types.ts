/**
 * EVP Protocol Type Definitions
 *
 * Type definitions for the WICG Email Verification Protocol.
 * @see https://github.com/WICG/email-verification-protocol
 */

import type { SupportedAlgorithm } from './constants.js';

/**
 * EVP error codes as defined by the specification.
 */
export type EVPErrorCode =
  | 'invalid_request'
  | 'invalid_token'
  | 'authentication_required'
  | 'server_error';

/**
 * Issuer metadata served at /.well-known/email-verification
 */
export interface IssuerMetadata {
  /** URL where browsers POST request tokens */
  issuance_endpoint: string;

  /** URL of the JWKS containing issuer's public keys */
  jwks_uri: string;

  /** Supported signing algorithms. Default: ["EdDSA"] */
  signing_alg_values_supported?: string[];
}

/**
 * JWT payload sent by the browser to the issuer (request token)
 */
export interface RequestTokenPayload {
  /** Issuer identifier (must match the issuer's domain) */
  aud: string;

  /** Unix timestamp when the token was created */
  iat: number;

  /** Optional unique identifier for the token */
  jti?: string;

  /** Email address to verify */
  email: string;
}

/**
 * JWT header of the request token
 */
export interface RequestTokenHeader {
  /** Signing algorithm (e.g., "EdDSA") */
  alg: string;

  /** Token type, must be "JWT" */
  typ: 'JWT';

  /** Browser's ephemeral public key in JWK format */
  jwk: JsonWebKey;
}

/**
 * SD-JWT payload returned by the issuer (issuance token)
 */
export interface IssuanceTokenPayload {
  /** Issuer identifier */
  iss: string;

  /** Unix timestamp when issued */
  iat: number;

  /** Confirmation claim containing browser's public key */
  cnf: {
    jwk: JsonWebKey;
  };

  /** The verified email address */
  email: string;

  /** Must be true for valid verification */
  email_verified: true;
}

/**
 * SD-JWT header for issuance tokens
 */
export interface IssuanceTokenHeader {
  /** Signing algorithm */
  alg: string;

  /** Key ID referencing key in JWKS */
  kid: string;

  /** Token type for EVP */
  typ: 'evp+sd-jwt';
}

/**
 * KB-JWT payload created by the browser
 */
export interface KeyBindingPayload {
  /** RP's origin (e.g., "https://example.com") */
  aud: string;

  /** Nonce provided by the RP */
  nonce: string;

  /** Unix timestamp */
  iat: number;

  /** SHA-256 hash of the SD-JWT (base64url encoded) */
  sd_hash: string;

  /** Optional additional entropy */
  salt?: string;
}

/**
 * KB-JWT header
 */
export interface KeyBindingHeader {
  /** Signing algorithm */
  alg: string;

  /** Token type for key binding */
  typ: 'kb+jwt';
}

/**
 * Result of successful email verification
 */
export interface VerificationResult {
  /** The verified email address */
  email: string;

  /** Always true for successful verification */
  email_verified: boolean;

  /** The issuer that verified the email */
  issuer: string;

  /** When the token was issued */
  issuedAt: Date;
}

/**
 * Configuration for EmailVerificationIssuer
 */
export interface IssuerConfig {
  /** Issuer identifier (eTLD+1 domain) */
  issuer: string;

  /** Private signing key in JWK format */
  privateKey: JsonWebKey;

  /** Key identifier for JWKS */
  kid: string;

  /** Signing algorithm (default: 'EdDSA') */
  algorithm?: SupportedAlgorithm;

  /** Clock tolerance in seconds (default: 60) */
  clockTolerance?: number;
}

/**
 * Configuration for EmailVerificationVerifier
 */
export interface VerifierConfig {
  /** RP's origin (e.g., "https://example.com") */
  rpOrigin: string;

  /** Custom DNS resolver function */
  dnsResolver?: DnsResolver;

  /** Custom fetch implementation */
  fetch?: typeof globalThis.fetch;

  /** Clock tolerance in seconds (default: 60) */
  clockTolerance?: number;

  /** JWKS cache TTL in seconds (default: 600) */
  jwksCacheTTL?: number;
}

/**
 * DNS resolver function type
 */
export type DnsResolver = (emailDomain: string) => Promise<string | null>;

/**
 * Result of verifying a request token
 */
export interface RequestTokenVerifyResult {
  /** Decoded token payload */
  payload: RequestTokenPayload;

  /** Browser's public key extracted from token header */
  browserPublicKey: JsonWebKey;
}

/**
 * Key pair generated for signing
 */
export interface KeyPair {
  /** Private key in JWK format */
  privateKey: JsonWebKey;

  /** Public key in JWK format */
  publicKey: JsonWebKey;
}

/**
 * JWKS (JSON Web Key Set) structure
 */
export interface JWKS {
  /** Array of JWK public keys */
  keys: JsonWebKey[];
}

/**
 * Parsed SD-JWT+KB token components
 */
export interface ParsedSDJWTKB {
  /** The SD-JWT part (including trailing ~) */
  sdJwt: string;

  /** The KB-JWT part (if present) */
  kbJwt: string | null;

  /** The SD-JWT without trailing ~ (for hashing) */
  sdJwtForHash: string;
}
