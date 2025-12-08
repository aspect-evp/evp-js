/**
 * Key Generation Utilities for EVP Issuer
 *
 * Provides utilities for generating signing keypairs for EVP token issuance.
 */

import type { KeyPair, SupportedAlgorithm } from '@evp/core';
import { DEFAULT_ALGORITHM, SUPPORTED_ALGORITHMS } from '@evp/core';
import { EVPError } from '@evp/core';
import { exportJWK, generateKeyPair as joseGenerateKeyPair } from 'jose';

/**
 * Map of algorithm names to jose algorithm identifiers and key generation parameters
 */
const ALGORITHM_CONFIG: Record<
  SupportedAlgorithm,
  { alg: string; crv?: string; modulusLength?: number }
> = {
  EdDSA: { alg: 'EdDSA', crv: 'Ed25519' },
  ES256: { alg: 'ES256', crv: 'P-256' },
  ES384: { alg: 'ES384', crv: 'P-384' },
  RS256: { alg: 'RS256', modulusLength: 2048 },
};

/**
 * Generate a new signing keypair
 *
 * @param algorithm - The signing algorithm to use (default: 'EdDSA')
 * @returns A keypair containing private and public keys in JWK format
 * @throws EVPError if the algorithm is not supported
 *
 * @example
 * ```typescript
 * // Generate EdDSA keypair (recommended)
 * const { privateKey, publicKey } = await generateKeyPair('EdDSA');
 *
 * // Generate ECDSA P-256 keypair
 * const { privateKey, publicKey } = await generateKeyPair('ES256');
 * ```
 */
export async function generateKeyPair(
  algorithm: SupportedAlgorithm = DEFAULT_ALGORITHM
): Promise<KeyPair> {
  if (!SUPPORTED_ALGORITHMS.includes(algorithm)) {
    throw new EVPError(
      'invalid_request',
      `Unsupported algorithm: ${algorithm}. Supported: ${SUPPORTED_ALGORITHMS.join(', ')}`
    );
  }

  const config = ALGORITHM_CONFIG[algorithm];

  try {
    // Build options object conditionally to satisfy exactOptionalPropertyTypes
    const options: { extractable: true; crv?: string; modulusLength?: number } = {
      extractable: true,
    };
    if (config.crv) {
      options.crv = config.crv;
    }
    if (config.modulusLength) {
      options.modulusLength = config.modulusLength;
    }

    // Generate the keypair using jose
    const { privateKey, publicKey } = await joseGenerateKeyPair(config.alg, options);

    // Export to JWK format
    const privateJwk = await exportJWK(privateKey);
    const publicJwk = await exportJWK(publicKey);

    // Add algorithm to JWK
    privateJwk.alg = algorithm;
    publicJwk.alg = algorithm;

    return {
      privateKey: privateJwk as JsonWebKey,
      publicKey: publicJwk as JsonWebKey,
    };
  } catch (error) {
    throw new EVPError(
      'server_error',
      `Failed to generate keypair: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * Check if an algorithm is supported
 *
 * @param algorithm - Algorithm to check
 * @returns true if the algorithm is supported
 */
export function isAlgorithmSupported(algorithm: string): algorithm is SupportedAlgorithm {
  return SUPPORTED_ALGORITHMS.includes(algorithm as SupportedAlgorithm);
}

/**
 * Get the curve name for an algorithm (for ECDSA/EdDSA)
 *
 * @param algorithm - The algorithm
 * @returns The curve name or undefined for RSA
 */
export function getCurveForAlgorithm(algorithm: SupportedAlgorithm): string | undefined {
  return ALGORITHM_CONFIG[algorithm].crv;
}
