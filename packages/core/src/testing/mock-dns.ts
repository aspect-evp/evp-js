/**
 * Mock DNS Resolver for Testing
 *
 * Provides a configurable DNS resolver for unit tests.
 *
 * @see https://github.com/WICG/email-verification-protocol
 */

import type { DnsResolver } from '../types.js';

/**
 * Mock DNS Resolver
 *
 * A configurable DNS resolver for testing EVP integrations.
 * Allows you to set up expected DNS responses without making real DNS queries.
 *
 * @example
 * ```typescript
 * import { MockDnsResolver } from '@evp/core/testing';
 *
 * const mockDns = new MockDnsResolver();
 * mockDns.addRecord('gmail.com', 'accounts.google.com');
 * mockDns.addRecord('example.com', 'issuer.example.com');
 *
 * const verifier = new EmailVerificationVerifier({
 *   rpOrigin: 'https://myapp.com',
 *   dnsResolver: mockDns.resolve
 * });
 * ```
 */
export class MockDnsResolver {
  private records = new Map<string, string>();

  /**
   * Add a DNS record mapping
   *
   * @param emailDomain - The email domain (e.g., 'gmail.com')
   * @param issuer - The issuer hostname (e.g., 'accounts.google.com')
   */
  addRecord(emailDomain: string, issuer: string): void {
    this.records.set(emailDomain, issuer);
  }

  /**
   * Remove a DNS record
   *
   * @param emailDomain - The email domain to remove
   * @returns true if the record was removed, false if it didn't exist
   */
  removeRecord(emailDomain: string): boolean {
    return this.records.delete(emailDomain);
  }

  /**
   * Clear all DNS records
   */
  clear(): void {
    this.records.clear();
  }

  /**
   * Get all registered records
   *
   * @returns A readonly map of domain -> issuer mappings
   */
  getRecords(): ReadonlyMap<string, string> {
    return this.records;
  }

  /**
   * Check if a record exists
   *
   * @param emailDomain - The email domain to check
   * @returns true if a record exists for this domain
   */
  hasRecord(emailDomain: string): boolean {
    return this.records.has(emailDomain);
  }

  /**
   * The resolver function to pass to verifier config
   *
   * This is a bound method that can be used directly as a DnsResolver.
   */
  resolve: DnsResolver = async (emailDomain: string): Promise<string | null> => {
    return this.records.get(emailDomain) ?? null;
  };
}

/**
 * Create a simple mock resolver function
 *
 * For simpler cases where you only need to mock a single domain.
 *
 * @param records - Object mapping email domains to issuers
 * @returns A DnsResolver function
 *
 * @example
 * ```typescript
 * const resolver = createMockResolver({
 *   'gmail.com': 'accounts.google.com',
 *   'example.com': 'issuer.example.com'
 * });
 * ```
 */
export function createMockResolver(records: Record<string, string>): DnsResolver {
  return async (emailDomain: string): Promise<string | null> => {
    return records[emailDomain] ?? null;
  };
}
