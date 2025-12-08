/**
 * @aspect-evp/core/testing
 *
 * Testing utilities for EVP implementations.
 *
 * @see https://github.com/WICG/email-verification-protocol
 * @packageDocumentation
 */

export { createMockResolver, MockDnsResolver } from './mock-dns.js';
export type { TestFlow, TestFlowConfig } from './test-flow.js';
export { createTestFlow, generateNonce } from './test-flow.js';
