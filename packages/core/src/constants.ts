/**
 * EVP Protocol Constants
 *
 * These constants are defined by the WICG Email Verification Protocol specification.
 * @see https://datatracker.ietf.org/doc/draft-hardt-email-verification/
 */

/** Default signing algorithm for EVP tokens */
export const DEFAULT_ALGORITHM = 'EdDSA';

/** Clock tolerance for timestamp validation (in seconds) */
export const DEFAULT_CLOCK_TOLERANCE = 60;

/** DNS TXT record prefix for EVP issuer discovery */
export const DNS_RECORD_PREFIX = '_email-verification';

/** Well-known path for issuer metadata */
export const WELL_KNOWN_PATH = '/.well-known/email-verification';

/** EVT JWT type header value */
export const SD_JWT_TYPE = 'evt+jwt';

/** KB-JWT type header value for key binding tokens */
export const KB_JWT_TYPE = 'kb+jwt';

/** Supported signing algorithms */
export const SUPPORTED_ALGORITHMS = ['EdDSA', 'ES256', 'ES384', 'RS256'] as const;

/** Type for supported algorithms */
export type SupportedAlgorithm = (typeof SUPPORTED_ALGORITHMS)[number];
