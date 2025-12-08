/**
 * @evp/verifier
 *
 * EVP token verification for web applications (Relying Parties).
 *
 * @packageDocumentation
 */

// Main verifier class
export { EmailVerificationVerifier } from './verifier.js';

// DNS resolvers
export {
  createCachingResolver,
  defaultDnsResolver,
  nodeDnsResolver,
  resolveIssuer,
} from './dns.js';

// JWKS utilities
export {
  clearJWKSCache,
  createJWKSFetcher,
  fetchIssuerMetadata,
  getIssuerJWKS,
} from './jwks.js';

// Re-export commonly used types from @evp/core
export type {
  DnsResolver,
  IssuerMetadata,
  KeyBindingPayload,
  VerificationResult,
  VerifierConfig,
} from '@evp/core';

// Re-export utilities and errors from @evp/core
export {
  DEFAULT_CLOCK_TOLERANCE,
  DNS_RECORD_PREFIX,
  EVPError,
  isEVPError,
  KB_JWT_TYPE,
  SD_JWT_TYPE,
  toEVPError,
  WELL_KNOWN_PATH,
} from '@evp/core';
