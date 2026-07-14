/**
 * @aspect-evp/core/testing
 *
 * Testing utilities for EVP implementations.
 *
 * @see https://datatracker.ietf.org/doc/draft-hardt-email-verification/
 * @packageDocumentation
 */

export { createMockResolver, MockDnsResolver } from './mock-dns.js';
export type { TestFlow, TestFlowConfig } from './test-flow.js';
export { createTestFlow, generateNonce } from './test-flow.js';
