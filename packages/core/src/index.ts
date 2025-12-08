/**
 * @evp/core
 *
 * Shared types, constants, and utilities for the Email Verification Protocol.
 *
 * @packageDocumentation
 */

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
export type { SupportedAlgorithm } from './constants.js';

// Types
export type {
  DnsResolver,
  EVPErrorCode,
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
} from './types.js';

// Errors
export { EVPError, isEVPError, toEVPError } from './errors.js';

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
