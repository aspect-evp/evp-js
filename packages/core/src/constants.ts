/**
 * EVP Protocol Constants
 *
 * These constants are defined by the WICG Email Verification Protocol specification.
 * @see https://github.com/WICG/email-verification-protocol
 */

/** Default signing algorithm for EVP tokens */
export const DEFAULT_ALGORITHM = 'EdDSA';

/** Clock tolerance for timestamp validation (in seconds) */
export const DEFAULT_CLOCK_TOLERANCE = 60;

/** DNS TXT record prefix for EVP issuer discovery */
export const DNS_RECORD_PREFIX = '_email-verification';

/** Well-known path for issuer metadata */
export const WELL_KNOWN_PATH = '/.well-known/email-verification';

/** SD-JWT type header value for EVP issuance tokens */
export const SD_JWT_TYPE = 'evp+sd-jwt';

/** KB-JWT type header value for key binding tokens */
export const KB_JWT_TYPE = 'kb+jwt';

/** Supported signing algorithms */
export const SUPPORTED_ALGORITHMS = ['EdDSA', 'ES256', 'ES384', 'RS256'] as const;

/** Type for supported algorithms */
export type SupportedAlgorithm = (typeof SUPPORTED_ALGORITHMS)[number];
