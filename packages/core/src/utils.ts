/**
 * EVP Utility Functions
 *
 * Utility functions for parsing, encoding, and validating EVP data.
 */

import { webcrypto } from 'node:crypto';
import { EVPError } from './errors.js';
import type { ParsedSDJWTKB } from './types.js';

// Use webcrypto for Node.js compatibility (globalThis.crypto not available in Node 18)
const cryptoSubtle = webcrypto.subtle;

/**
 * Parse an SD-JWT+KB token into its components
 *
 * SD-JWT+KB format: `<header>.<payload>.<signature>~<kb-jwt>`
 * The SD-JWT always ends with `~` even when there are no disclosures.
 *
 * @param token - The complete SD-JWT+KB token string
 * @returns Parsed components including sdJwt, kbJwt, and sdJwtForHash
 * @throws EVPError if token format is invalid
 *
 * @example
 * ```typescript
 * const { sdJwt, kbJwt, sdJwtForHash } = parseSDJWTKB(token);
 * // sdJwt: 'eyJ...~'
 * // kbJwt: 'eyJ...' or null
 * // sdJwtForHash: 'eyJ...' (without trailing ~)
 * ```
 */
export function parseSDJWTKB(token: string): ParsedSDJWTKB {
  if (!token || typeof token !== 'string') {
    throw new EVPError('invalid_request', 'Token must be a non-empty string');
  }

  // Find the position of ~ which separates SD-JWT from KB-JWT
  // SD-JWT format: header.payload.signature~
  // With KB-JWT: header.payload.signature~kb-jwt
  const tildeIndex = token.indexOf('~');

  if (tildeIndex === -1) {
    throw new EVPError('invalid_request', 'Invalid SD-JWT format: missing ~ delimiter');
  }

  // SD-JWT is everything up to and including the ~
  const sdJwt = token.substring(0, tildeIndex + 1);

  // For hashing, we need the SD-JWT without the trailing ~
  const sdJwtForHash = token.substring(0, tildeIndex);

  // Validate SD-JWT has proper JWT structure (header.payload.signature)
  const jwtParts = sdJwtForHash.split('.');
  if (jwtParts.length !== 3) {
    throw new EVPError(
      'invalid_request',
      'Invalid SD-JWT: must have header.payload.signature format'
    );
  }

  // KB-JWT is everything after the ~
  const kbJwtPart = token.substring(tildeIndex + 1);
  const kbJwt = kbJwtPart.length > 0 ? kbJwtPart : null;

  // Validate KB-JWT structure if present
  if (kbJwt) {
    const kbParts = kbJwt.split('.');
    if (kbParts.length !== 3) {
      throw new EVPError(
        'invalid_request',
        'Invalid KB-JWT: must have header.payload.signature format'
      );
    }
  }

  return {
    sdJwt,
    kbJwt,
    sdJwtForHash,
  };
}

/**
 * Extract the domain from an email address
 *
 * @param email - Email address to extract domain from
 * @returns The domain part of the email
 * @throws EVPError if email format is invalid
 *
 * @example
 * ```typescript
 * getEmailDomain('user@gmail.com'); // 'gmail.com'
 * getEmailDomain('admin@mail.company.co.uk'); // 'mail.company.co.uk'
 * ```
 */
export function getEmailDomain(email: string): string {
  if (!email || typeof email !== 'string') {
    throw new EVPError('invalid_request', 'Email must be a non-empty string');
  }

  const atIndex = email.lastIndexOf('@');

  if (atIndex === -1 || atIndex === 0 || atIndex === email.length - 1) {
    throw new EVPError('invalid_request', 'Invalid email format');
  }

  const domain = email.substring(atIndex + 1);

  if (!domain || domain.includes(' ')) {
    throw new EVPError('invalid_request', 'Invalid email domain');
  }

  return domain.toLowerCase();
}

/**
 * Basic email format validation
 *
 * This performs basic validation only. The issuer is responsible for
 * full email validation.
 *
 * @param email - Email address to validate
 * @returns true if email has a valid basic format
 *
 * @example
 * ```typescript
 * isValidEmail('user@example.com'); // true
 * isValidEmail('invalid'); // false
 * ```
 */
export function isValidEmail(email: string): boolean {
  if (!email || typeof email !== 'string') {
    return false;
  }

  // Basic regex for email format validation
  // Intentionally simple - full validation is complex and issuer's responsibility
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Compute SHA-256 hash and return as base64url encoded string
 *
 * Uses Web Crypto API for portability across environments.
 *
 * @param data - String data to hash
 * @returns Base64url encoded SHA-256 hash
 *
 * @example
 * ```typescript
 * const hash = await sha256('hello world');
 * // 'uU0nuZNNPgilLlLX2n2r-sSE7-N6U4DukIj3rOLvzek'
 * ```
 */
export async function sha256(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await cryptoSubtle.digest('SHA-256', dataBuffer);
  return base64url(new Uint8Array(hashBuffer));
}

/**
 * Encode a Uint8Array as base64url (no padding)
 *
 * @param buffer - Data to encode
 * @returns Base64url encoded string
 *
 * @example
 * ```typescript
 * const encoded = base64url(new Uint8Array([1, 2, 3]));
 * ```
 */
export function base64url(buffer: Uint8Array): string {
  // Convert Uint8Array to base64
  let binary = '';
  for (const byte of buffer) {
    binary += String.fromCharCode(byte);
  }
  const base64 = btoa(binary);

  // Convert base64 to base64url (replace + with -, / with _, remove padding)
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decode a base64url string to Uint8Array
 *
 * @param str - Base64url encoded string
 * @returns Decoded data as Uint8Array
 *
 * @example
 * ```typescript
 * const decoded = base64urlDecode('AQID');
 * // Uint8Array([1, 2, 3])
 * ```
 */
export function base64urlDecode(str: string): Uint8Array {
  // Convert base64url to base64
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');

  // Add padding if necessary
  const padding = base64.length % 4;
  if (padding) {
    base64 += '='.repeat(4 - padding);
  }

  // Decode base64
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Decode a base64url encoded JSON payload
 *
 * @param encoded - Base64url encoded JSON string
 * @returns Parsed JSON object
 * @throws EVPError if decoding or parsing fails
 */
export function decodeJWTPayload<T = unknown>(encoded: string): T {
  try {
    const decoded = base64urlDecode(encoded);
    const text = new TextDecoder().decode(decoded);
    return JSON.parse(text) as T;
  } catch {
    throw new EVPError('invalid_token', 'Failed to decode JWT payload');
  }
}

/**
 * Decode a JWT header
 *
 * @param encoded - Base64url encoded header string
 * @returns Parsed header object
 * @throws EVPError if decoding or parsing fails
 */
export function decodeJWTHeader<T = unknown>(encoded: string): T {
  try {
    const decoded = base64urlDecode(encoded);
    const text = new TextDecoder().decode(decoded);
    return JSON.parse(text) as T;
  } catch {
    throw new EVPError('invalid_token', 'Failed to decode JWT header');
  }
}

/**
 * Get the current Unix timestamp in seconds
 *
 * @returns Current time as Unix timestamp (seconds)
 */
export function getCurrentTimestamp(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * Check if a timestamp is within tolerance of the current time
 *
 * @param timestamp - Unix timestamp to check
 * @param tolerance - Allowed deviation in seconds (default: 60)
 * @returns true if timestamp is within tolerance
 */
export function isTimestampValid(timestamp: number, tolerance = 60): boolean {
  const now = getCurrentTimestamp();
  const diff = Math.abs(now - timestamp);
  return diff <= tolerance;
}
