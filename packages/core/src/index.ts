/**
 * @aspect-evp/core
 *
 * Shared types, constants, and utilities for the Email Verification Protocol.
 *
 * @packageDocumentation
 */

export type { SupportedAlgorithm } from './constants.js';
// Constants
export {
  DEFAULT_ALGORITHM,
  DEFAULT_CLOCK_TOLERANCE,
  DNS_RECORD_PREFIX,
  KB_JWT_TYPE,
  SD_JWT_TYPE,
  SUPPORTED_ALGORITHMS,
  WELL_KNOWN_PATH,
} from './constants.js';
// Errors
export { EVPError, getErrorMessage, isEVPError, toEVPError } from './errors.js';
export type {
  SignedIssuanceRequestOptions,
  VerifiedHttpMessageSignature,
} from './http-signatures.js';
export {
  createSignedIssuanceRequest,
  verifyHttpMessageSignature,
} from './http-signatures.js';
// Types
export type {
  DnsResolver,
  EVPErrorCode,
  IssuanceRequest,
  IssuanceTokenHeader,
  IssuanceTokenPayload,
  IssuerConfig,
  IssuerMetadata,
  JWKS,
  KeyBindingHeader,
  KeyBindingPayload,
  KeyPair,
  ParsedSDJWTKB,
  RequestTokenHeader,
  RequestTokenPayload,
  RequestTokenVerifyResult,
  VerificationResult,
  VerifierConfig,
  WebAuthnChallenge,
  WebAuthnResponse,
} from './types.js';

// Utilities
export {
  base64url,
  base64urlDecode,
  decodeJWTHeader,
  decodeJWTPayload,
  getCurrentTimestamp,
  getEmailDomain,
  isTimestampValid,
  isValidEmail,
  parseSDJWTKB,
  sha256,
} from './utils.js';
