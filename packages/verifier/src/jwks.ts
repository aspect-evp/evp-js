/**
 * JWKS Utilities for EVP Verifier
 *
 * Provides utilities for fetching issuer metadata and JWKS.
 */

import type { IssuerMetadata } from '@aspect-evp/core';
import { EVPError, WELL_KNOWN_PATH } from '@aspect-evp/core';
import { type JWTVerifyGetKey, createLocalJWKSet, createRemoteJWKSet } from 'jose';

/**
 * Cache for remote JWKS
 */
const jwksCache = new Map<string, JWTVerifyGetKey>();

/**
 * Fetch issuer metadata from well-known endpoint
 *
 * @param issuerOrigin - The issuer's origin (e.g., 'https://accounts.google.com')
 * @param fetchFn - Custom fetch function (optional)
 * @returns The issuer metadata
 * @throws EVPError if metadata cannot be fetched or is invalid
 *
 * @example
 * ```typescript
 * const metadata = await fetchIssuerMetadata('https://accounts.google.com');
 * console.log(metadata.issuance_endpoint);
 * ```
 */
export async function fetchIssuerMetadata(
  issuerOrigin: string,
  fetchFn: typeof globalThis.fetch = globalThis.fetch
): Promise<IssuerMetadata> {
  const metadataUrl = `${issuerOrigin.replace(/\/$/, '')}${WELL_KNOWN_PATH}`;

  try {
    const response = await fetchFn(metadataUrl, {
      headers: {
        Accept: 'application/json',
      },
    });

    if (!response.ok) {
      throw new EVPError(
        'server_error',
        `Failed to fetch issuer metadata: HTTP ${response.status}`
      );
    }

    const metadata = (await response.json()) as IssuerMetadata;

    // Validate required fields
    if (!metadata.issuance_endpoint) {
      throw new EVPError('server_error', 'Invalid issuer metadata: missing issuance_endpoint');
    }

    if (!metadata.jwks_uri) {
      throw new EVPError('server_error', 'Invalid issuer metadata: missing jwks_uri');
    }

    return metadata;
  } catch (error) {
    if (error instanceof EVPError) {
      throw error;
    }
    throw new EVPError(
      'server_error',
      `Failed to fetch issuer metadata: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * Create a JWKS fetcher for an issuer
 *
 * Uses jose's createRemoteJWKSet which handles caching internally.
 *
 * @param jwksUri - The JWKS URI from issuer metadata
 * @param options - Optional configuration
 * @returns A function that can be used to get the public key for verification
 *
 * @example
 * ```typescript
 * const getKey = createJWKSFetcher('https://issuer.example.com/jwks');
 * ```
 */
export function createJWKSFetcher(
  jwksUri: string,
  options?: {
    /** Cache TTL in milliseconds */
    cacheTtl?: number;
    /** Custom fetch function - when provided, JWKS is fetched on first use */
    fetch?: typeof globalThis.fetch;
  }
): JWTVerifyGetKey {
  // When custom fetch is provided, create a lazy-loading local JWKS
  if (options?.fetch) {
    let localJwks: JWTVerifyGetKey | null = null;

    // Return a wrapper function that fetches JWKS on first use
    const fetchFn = options.fetch;
    const wrapper: JWTVerifyGetKey = async (protectedHeader, token) => {
      if (!localJwks) {
        const response = await fetchFn(jwksUri);
        if (!response.ok) {
          throw new EVPError('server_error', `Failed to fetch JWKS: HTTP ${response.status}`);
        }
        const jwksData = (await response.json()) as { keys: JsonWebKey[] };
        localJwks = createLocalJWKSet(jwksData as Parameters<typeof createLocalJWKSet>[0]);
      }
      return localJwks(protectedHeader, token);
    };

    return wrapper;
  }

  // Check cache first
  const cached = jwksCache.get(jwksUri);
  if (cached) {
    return cached;
  }

  // Create new remote JWKS
  const jwks = createRemoteJWKSet(new URL(jwksUri), {
    cooldownDuration: options?.cacheTtl ?? 30000,
    cacheMaxAge: options?.cacheTtl ?? 600000,
  });

  // Cache the JWKS fetcher
  jwksCache.set(jwksUri, jwks);

  return jwks;
}

/**
 * Clear the JWKS cache
 *
 * Useful for testing or when keys are rotated.
 */
export function clearJWKSCache(): void {
  jwksCache.clear();
}

/**
 * Get JWKS fetcher with metadata lookup
 *
 * Convenience function that fetches metadata and creates JWKS fetcher.
 *
 * @param issuerOrigin - The issuer's origin
 * @param fetchFn - Custom fetch function (optional)
 * @returns Object containing metadata and JWKS fetcher
 */
export async function getIssuerJWKS(
  issuerOrigin: string,
  fetchFn: typeof globalThis.fetch = globalThis.fetch
): Promise<{ metadata: IssuerMetadata; getKey: JWTVerifyGetKey }> {
  const metadata = await fetchIssuerMetadata(issuerOrigin, fetchFn);
  const getKey = createJWKSFetcher(metadata.jwks_uri);

  return { metadata, getKey };
}
