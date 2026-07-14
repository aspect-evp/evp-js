/**
 * EVP Protocol Type Definitions
 *
 * Type definitions for the WICG Email Verification Protocol.
 * @see https://datatracker.ietf.org/doc/draft-hardt-email-verification/
 */

import type { SupportedAlgorithm } from './constants.js';

/**
 * EVP error codes as defined by the specification.
 */
export type EVPErrorCode =
  | 'invalid_request'
  | 'invalid_token'
  | 'invalid_signature'
  | 'authentication_required'
  | 'private_email_not_supported'
  | 'invalid_directed_email'
  | 'server_error';

/**
 * Issuer metadata served at /.well-known/email-verification
 */
export interface IssuerMetadata {
  /** URL where browsers POST signed issuance requests */
  issuance_endpoint: string;

  /** URL of the JWKS containing issuer's public keys */
  jwks_uri: string;

  /** Supported signing algorithms. Default: ["EdDSA"] */
  signing_alg_values_supported?: string[];

  /** Whether WebAuthn fallback authentication is supported. Default: false */
  webauthn_supported?: boolean;

  /** Whether private email addresses are supported. Default: false */
  private_email_supported?: boolean;
}

/** JSON body sent to the issuance endpoint. */
export interface IssuanceRequest {
  email: string;
  private_email?: boolean;
  directed_email?: string;
  webauthn_response?: WebAuthnResponse;
}

/** WebAuthn assertion forwarded by the browser to the issuer. */
export interface WebAuthnResponse {
  id: string;
  rawId: string;
  response: {
    authenticatorData: string;
    clientDataJSON: string;
    signature: string;
    userHandle?: string | null;
  };
  type: 'public-key';
}

/** WebAuthn challenge returned by an issuer when cookie authentication is unavailable. */
export interface WebAuthnChallenge {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: Array<{ type: 'public-key'; id: string }>;
  userVerification?: 'required' | 'preferred' | 'discouraged';
}

/**
 * JWT payload sent by the browser to the issuer (request token)
 * @deprecated The current IETF draft uses an HTTP Message Signature over a JSON request.
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
 * @deprecated The current IETF draft uses Signature-Key instead.
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

  /** Present and true when the issuer returned a private email address. */
  is_private_email?: true;
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
  typ: 'evt+jwt';
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

  /** True when the verified address is a private relay address. */
  isPrivateEmail?: boolean;
}

/**
 * Configuration for EmailVerificationIssuer
 */
export interface IssuerConfig {
  /** Issuer identifier (hostname without scheme, path, credentials, or port) */
  issuer: string;

  /** Private signing key in JWK format */
  privateKey: JsonWebKey;

  /** Key identifier for JWKS */
  kid: string;

  /** Signing algorithm (default: 'EdDSA') */
  algorithm?: SupportedAlgorithm;

  /** Clock tolerance in seconds (default: 60) */
  clockTolerance?: number;

  /** Advertise support for WebAuthn fallback authentication. */
  webauthnSupported?: boolean;

  /** Advertise support for private email addresses. */
  privateEmailSupported?: boolean;
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
 * @deprecated Compatibility type for the legacy WICG request-token flow.
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

  /** The complete SD-JWT including its trailing ~ (for hashing) */
  sdJwtForHash: string;
}
