/**
 * JWKS Utilities for EVP Verifier
 *
 * Provides utilities for fetching issuer metadata and JWKS.
 */

import type { IssuerMetadata } from '@aspect-evp/core';
import { EVPError, getErrorMessage, SUPPORTED_ALGORITHMS, WELL_KNOWN_PATH } from '@aspect-evp/core';
import { createLocalJWKSet, createRemoteJWKSet, type JWTVerifyGetKey } from 'jose';

/**
 * Cache for remote JWKS
 */
const jwksCache = new Map<string, JWTVerifyGetKey>();

function requireHttpsUrl(value: string, field: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new EVPError('server_error', `Invalid issuer metadata: ${field} is not a URL`);
  }
  if (url.protocol !== 'https:' || url.username || url.password) {
    throw new EVPError('server_error', `Invalid issuer metadata: ${field} must use HTTPS`);
  }
  return url;
}

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
    requireHttpsUrl(metadata.issuance_endpoint, 'issuance_endpoint');
    requireHttpsUrl(metadata.jwks_uri, 'jwks_uri');
    if (metadata.signing_alg_values_supported) {
      if (
        metadata.signing_alg_values_supported.length === 0 ||
        metadata.signing_alg_values_supported.some(
          (algorithm) =>
            !SUPPORTED_ALGORITHMS.includes(algorithm as (typeof SUPPORTED_ALGORITHMS)[number])
        )
      ) {
        throw new EVPError(
          'server_error',
          'Invalid issuer metadata: unsupported signing algorithm'
        );
      }
    }

    return metadata;
  } catch (error) {
    if (error instanceof EVPError) {
      throw error;
    }
    throw new EVPError(
      'server_error',
      `Failed to fetch issuer metadata: ${getErrorMessage(error)}`
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
  requireHttpsUrl(jwksUri, 'jwks_uri');
  // When custom fetch is provided, create a lazy-loading local JWKS
  if (options?.fetch) {
    let localJwks: JWTVerifyGetKey | null = null;
    let expiresAt = 0;

    const fetchFn = options.fetch;
    const cacheTtl = options.cacheTtl ?? 600000;
    const refresh = async (): Promise<JWTVerifyGetKey> => {
      const response = await fetchFn(jwksUri, { headers: { Accept: 'application/json' } });
      if (!response.ok) {
        throw new EVPError('server_error', `Failed to fetch JWKS: HTTP ${response.status}`);
      }
      const jwksData = (await response.json()) as { keys?: JsonWebKey[] };
      if (!Array.isArray(jwksData.keys) || jwksData.keys.length === 0) {
        throw new EVPError('server_error', 'Invalid JWKS: keys must be a non-empty array');
      }
      localJwks = createLocalJWKSet(jwksData as Parameters<typeof createLocalJWKSet>[0]);
      expiresAt = Date.now() + cacheTtl;
      return localJwks;
    };

    const wrapper: JWTVerifyGetKey = async (protectedHeader, token) => {
      const active = !localJwks || Date.now() >= expiresAt ? await refresh() : localJwks;
      try {
        return await active(protectedHeader, token);
      } catch (error) {
        // A new kid can appear before TTL expiry during emergency key rotation.
        if (Date.now() < expiresAt) {
          const refreshed = await refresh();
          return refreshed(protectedHeader, token);
        }
        throw error;
      }
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
  const getKey = createJWKSFetcher(metadata.jwks_uri, { fetch: fetchFn });

  return { metadata, getKey };
}
