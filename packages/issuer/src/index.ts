/**
 * @aspect-evp/issuer
 *
 * EVP issuer implementation for email providers.
 *
 * @packageDocumentation
 */

// Re-export commonly used types from @aspect-evp/core
export type {
  IssuerConfig,
  IssuerMetadata,
  JWKS,
  KeyPair,
  RequestTokenPayload,
  RequestTokenVerifyResult,
  SupportedAlgorithm,
} from '@aspect-evp/core';
// Re-export utilities and errors from @aspect-evp/core
export {
  DEFAULT_ALGORITHM,
  DEFAULT_CLOCK_TOLERANCE,
  EVPError,
  isEVPError,
  SD_JWT_TYPE,
  SUPPORTED_ALGORITHMS,
  toEVPError,
  WELL_KNOWN_PATH,
} from '@aspect-evp/core';
// Main issuer class
export { EmailVerificationIssuer } from './issuer.js';
// Key utilities
export { generateKeyPair, getCurveForAlgorithm, isAlgorithmSupported } from './keys.js';
export type {
  HandleIssuanceResult,
  IssuanceErrorResponse,
  IssuanceSuccessResponse,
  IssuerMiddleware,
  VerifyUserOwnsEmail,
} from './middleware.js';
// Middleware helpers
export { createIssuerMiddleware, toResponse } from './middleware.js';
