/**
 * DNS Resolution for EVP Verifier
 *
 * Provides DNS resolvers for discovering EVP issuers via TXT records.
 */

import type { DnsResolver } from '@aspect-evp/core';
import { DNS_RECORD_PREFIX, EVPError } from '@aspect-evp/core';

/**
 * DNS-over-HTTPS response structure
 */
interface DoHResponse {
  Answer?: Array<{
    type: number;
    data: string;
  }>;
}

/**
 * Parse EVP issuer from DNS TXT record
 *
 * The TXT record format is: iss=issuer.example.com
 */
function parseIssuerFromTxtRecord(txtData: string): string | null {
  // Remove quotes if present
  const data = txtData.replace(/^"|"$/g, '');

  // Look for iss= prefix
  if (data.startsWith('iss=')) {
    return data.slice(4).trim();
  }

  return null;
}

/**
 * Default DNS resolver using DNS-over-HTTPS (Cloudflare)
 *
 * This resolver works in browsers and edge runtimes where native DNS
 * is not available. It uses Cloudflare's DNS-over-HTTPS service.
 *
 * @param emailDomain - The email domain to look up (e.g., 'gmail.com')
 * @returns The issuer identifier from DNS or null if not found
 *
 * @example
 * ```typescript
 * const issuer = await defaultDnsResolver('gmail.com');
 * // Returns: 'accounts.google.com' (hypothetical)
 * ```
 */
export const defaultDnsResolver: DnsResolver = async (
  emailDomain: string
): Promise<string | null> => {
  const recordName = `${DNS_RECORD_PREFIX}.${emailDomain}`;

  try {
    const response = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(recordName)}&type=TXT`,
      {
        headers: {
          Accept: 'application/dns-json',
        },
      }
    );

    if (!response.ok) {
      return null;
    }

    const data: DoHResponse = await response.json();

    if (!data.Answer || data.Answer.length === 0) {
      return null;
    }

    // TXT record type is 16
    for (const answer of data.Answer) {
      if (answer.type === 16) {
        const issuer = parseIssuerFromTxtRecord(answer.data);
        if (issuer) {
          return issuer;
        }
      }
    }

    return null;
  } catch {
    return null;
  }
};

/**
 * Node.js native DNS resolver
 *
 * This resolver uses Node.js's built-in dns/promises module.
 * It's faster than DoH when running in Node.js but not available
 * in browsers or edge runtimes.
 *
 * @param emailDomain - The email domain to look up
 * @returns The issuer identifier from DNS or null if not found
 *
 * @example
 * ```typescript
 * import { nodeDnsResolver } from '@aspect-evp/verifier';
 *
 * const verifier = new EmailVerificationVerifier({
 *   rpOrigin: 'https://myapp.com',
 *   dnsResolver: nodeDnsResolver
 * });
 * ```
 */
export const nodeDnsResolver: DnsResolver = async (emailDomain: string): Promise<string | null> => {
  const recordName = `${DNS_RECORD_PREFIX}.${emailDomain}`;

  try {
    // Dynamic import for Node.js dns module (not available in browsers)
    const dns = await import('node:dns/promises');
    const records = await dns.resolveTxt(recordName);

    // DNS TXT records can be split into multiple strings, join them
    for (const record of records) {
      const txtData = record.join('');
      const issuer = parseIssuerFromTxtRecord(txtData);
      if (issuer) {
        return issuer;
      }
    }

    return null;
  } catch {
    return null;
  }
};

/**
 * Create a custom DNS resolver with caching
 *
 * @param baseResolver - The underlying resolver to use
 * @param cacheTtlMs - Cache TTL in milliseconds (default: 5 minutes)
 * @returns A caching DNS resolver
 *
 * @example
 * ```typescript
 * const cachedResolver = createCachingResolver(defaultDnsResolver, 60000);
 * ```
 */
export function createCachingResolver(
  baseResolver: DnsResolver,
  cacheTtlMs: number = 5 * 60 * 1000
): DnsResolver {
  const cache = new Map<string, { issuer: string | null; expires: number }>();

  return async (emailDomain: string): Promise<string | null> => {
    const cached = cache.get(emailDomain);
    if (cached && cached.expires > Date.now()) {
      return cached.issuer;
    }

    const issuer = await baseResolver(emailDomain);
    cache.set(emailDomain, {
      issuer,
      expires: Date.now() + cacheTtlMs,
    });

    return issuer;
  };
}

/**
 * Resolve issuer for an email domain
 *
 * This is a utility function that wraps the resolver with error handling.
 *
 * @param emailDomain - The email domain
 * @param resolver - The DNS resolver to use
 * @returns The issuer identifier
 * @throws EVPError if no issuer is found
 */
export async function resolveIssuer(
  emailDomain: string,
  resolver: DnsResolver = defaultDnsResolver
): Promise<string> {
  const issuer = await resolver(emailDomain);

  if (!issuer) {
    throw new EVPError('invalid_request', `No EVP issuer found for domain: ${emailDomain}`);
  }

  return issuer;
}
