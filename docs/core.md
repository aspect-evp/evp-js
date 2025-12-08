# @evp/core

> Shared types, constants, and utilities for the Email Verification Protocol.

## Overview

`@evp/core` is the foundation package that provides:

- TypeScript type definitions for all EVP data structures
- Utility functions for parsing and validating tokens
- Constants and error types
- Testing utilities for simulating the browser's role

**This package has zero dependencies.**

## Installation

```bash
npm install @evp/core
```

## API Reference

### Types

#### `IssuerMetadata`

The structure served at `/.well-known/email-verification`:

```typescript
interface IssuerMetadata {
  /** URL where browsers POST request tokens */
  issuance_endpoint: string;
  
  /** URL of the JWKS containing issuer's public keys */
  jwks_uri: string;
  
  /** Supported signing algorithms. Default: ["EdDSA"] */
  signing_alg_values_supported?: string[];
}
```

**Example:**
```json
{
  "issuance_endpoint": "https://accounts.gmail.com/email-verification/issuance",
  "jwks_uri": "https://accounts.gmail.com/email-verification/jwks",
  "signing_alg_values_supported": ["EdDSA", "ES256"]
}
```

#### `RequestTokenPayload`

The JWT payload sent by the browser to the issuer:

```typescript
interface RequestTokenPayload {
  /** Issuer identifier (must match the issuer's domain) */
  aud: string;
  
  /** Unix timestamp when the token was created */
  iat: number;
  
  /** Optional unique identifier for the token */
  jti?: string;
  
  /** Email address to verify */
  email: string;
}
```

#### `RequestTokenHeader`

The JWT header of the request token:

```typescript
interface RequestTokenHeader {
  /** Signing algorithm (e.g., "EdDSA") */
  alg: string;
  
  /** Token type, must be "JWT" */
  typ: "JWT";
  
  /** Browser's ephemeral public key in JWK format */
  jwk: JsonWebKey;
}
```

#### `IssuanceTokenPayload`

The SD-JWT payload returned by the issuer:

```typescript
interface IssuanceTokenPayload {
  /** Issuer identifier */
  iss: string;
  
  /** Unix timestamp when issued */
  iat: number;
  
  /** Confirmation claim containing browser's public key */
  cnf: {
    jwk: JsonWebKey;
  };
  
  /** The verified email address */
  email: string;
  
  /** Must be true for valid verification */
  email_verified: true;
}
```

#### `IssuanceTokenHeader`

The SD-JWT header:

```typescript
interface IssuanceTokenHeader {
  /** Signing algorithm */
  alg: string;
  
  /** Key ID referencing key in JWKS */
  kid: string;
  
  /** Token type for EVP */
  typ: "evp+sd-jwt";
}
```

#### `KeyBindingPayload`

The KB-JWT payload created by the browser:

```typescript
interface KeyBindingPayload {
  /** RP's origin (e.g., "https://example.com") */
  aud: string;
  
  /** Nonce provided by the RP */
  nonce: string;
  
  /** Unix timestamp */
  iat: number;
  
  /** SHA-256 hash of the SD-JWT (base64url encoded) */
  sd_hash: string;
  
  /** Optional additional entropy */
  salt?: string;
}
```

#### `VerificationResult`

The result of successful verification:

```typescript
interface VerificationResult {
  /** The verified email address */
  email: string;
  
  /** Always true for successful verification */
  email_verified: boolean;
  
  /** The issuer that verified the email */
  issuer: string;
  
  /** When the token was issued */
  issuedAt: Date;
}
```

#### `EVPError`

Custom error class for EVP-specific errors:

```typescript
type EVPErrorCode = 
  | "invalid_request"      // Malformed request
  | "invalid_token"        // Token verification failed
  | "authentication_required" // User not authenticated
  | "server_error";        // Internal error

class EVPError extends Error {
  code: EVPErrorCode;
  description?: string;
  
  constructor(code: EVPErrorCode, description?: string);
}
```

### Utility Functions

#### `parseSDJWTKB(token: string)`

Parses an SD-JWT+KB token into its components:

```typescript
function parseSDJWTKB(token: string): {
  sdJwt: string;      // The SD-JWT part (ends with ~)
  kbJwt: string | null; // The KB-JWT part (if present)
}
```

**Example:**
```typescript
import { parseSDJWTKB } from '@evp/core';

const token = 'eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJpc3N1ZXIifQ.signature~eyJhbGciOiJFZERTQSJ9.eyJhdWQiOiJycCJ9.sig2';

const { sdJwt, kbJwt } = parseSDJWTKB(token);
// sdJwt: 'eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJpc3N1ZXIifQ.signature~'
// kbJwt: 'eyJhbGciOiJFZERTQSJ9.eyJhdWQiOiJycCJ9.sig2'
```

#### `getEmailDomain(email: string)`

Extracts the domain from an email address:

```typescript
function getEmailDomain(email: string): string;
```

**Example:**
```typescript
import { getEmailDomain } from '@evp/core';

getEmailDomain('user@gmail.com'); // 'gmail.com'
getEmailDomain('admin@mail.company.co.uk'); // 'mail.company.co.uk'
```

**Throws:** `EVPError` with code `invalid_request` if email format is invalid.

#### `isValidEmail(email: string)`

Validates email format (basic validation):

```typescript
function isValidEmail(email: string): boolean;
```

**Note:** This is intentionally simple. Email validation is complex, and this only checks basic format. The actual verification is done by the issuer.

#### `sha256(data: string)`

Computes SHA-256 hash and returns base64url-encoded result:

```typescript
async function sha256(data: string): Promise<string>;
```

**Example:**
```typescript
import { sha256 } from '@evp/core';

const hash = await sha256('hello world');
// 'uU0nuZNNPgilLlLX2n2r-sSE7-N6U4DukIj3rOLvzek'
```

#### `base64url(buffer: Uint8Array)`

Encodes a buffer as base64url (no padding):

```typescript
function base64url(buffer: Uint8Array): string;
```

#### `base64urlDecode(str: string)`

Decodes a base64url string to Uint8Array:

```typescript
function base64urlDecode(str: string): Uint8Array;
```

### Constants

```typescript
/** Default signing algorithm */
export const DEFAULT_ALGORITHM = 'EdDSA';

/** Clock tolerance for timestamp validation (seconds) */
export const DEFAULT_CLOCK_TOLERANCE = 60;

/** DNS record prefix for EVP issuer discovery */
export const DNS_RECORD_PREFIX = '_email-verification';

/** Well-known path for issuer metadata */
export const WELL_KNOWN_PATH = '/.well-known/email-verification';

/** SD-JWT type header value */
export const SD_JWT_TYPE = 'evp+sd-jwt';

/** KB-JWT type header value */
export const KB_JWT_TYPE = 'kb+jwt';
```

## Testing Utilities

### `createTestFlow(config)`

Creates a complete test environment with mocks for EVP integration tests:

```typescript
import { createTestFlow } from '@evp/core/testing';
import { EmailVerificationVerifier } from '@evp/verifier';

const testFlow = await createTestFlow({
  issuer: 'issuer.example.com',
  rpOrigin: 'https://myapp.example.com',
});

// Create verifier with test mocks
const verifier = new EmailVerificationVerifier({
  rpOrigin: 'https://myapp.example.com',
  dnsResolver: testFlow.dnsResolver,
  fetch: testFlow.fetch,
});

// Create a token simulating the browser flow
const token = await testFlow.createToken('user@example.com', 'test-nonce');

// Verify the token
const result = await verifier.verify(token, 'test-nonce');
console.log(result.email); // 'user@example.com'
```

**Returns:**
- `issuerPublicJwk` - Issuer's public key in JWK format
- `browserPublicJwk` - Browser's public key in JWK format
- `metadata` - Issuer metadata for `/.well-known/email-verification`
- `dnsResolver` - Mock DNS resolver (pass to verifier config)
- `fetch` - Mock fetch for metadata/JWKS (pass to verifier config)
- `createToken(email, nonce)` - Creates SD-JWT+KB token for testing

### `MockDnsResolver`

A configurable mock DNS resolver for testing multiple domains:

```typescript
import { MockDnsResolver } from '@evp/core/testing';

const mockDns = new MockDnsResolver();
mockDns.addRecord('gmail.com', 'accounts.google.com');
mockDns.addRecord('example.com', 'issuer.example.com');

const verifier = new EmailVerificationVerifier({
  rpOrigin: 'https://myapp.com',
  dnsResolver: mockDns.resolve,
});
```

### `createMockResolver(records)`

Simple function-based mock for quick tests:

```typescript
import { createMockResolver } from '@evp/core/testing';

const resolver = createMockResolver({
  'gmail.com': 'accounts.google.com',
  'example.com': 'issuer.example.com',
});
```

### `generateNonce(length?)`

Generates a cryptographically random nonce:

```typescript
import { generateNonce } from '@evp/core/testing';

const nonce = generateNonce(); // 16 bytes, base64url encoded
```

## Implementation Notes

### Why These Specific Types?

The types in this package are derived directly from the [WICG EVP specification](https://github.com/WICG/email-verification-protocol). We've made them:

1. **Strict where the spec is strict** - Required fields are required
2. **Flexible where the spec allows** - Optional fields are optional
3. **Documented with spec references** - Each type links to relevant spec sections

### Browser Compatibility

The utility functions use:
- `crypto.subtle` for hashing (available in all modern environments)
- `TextEncoder` for string encoding
- `atob`/`btoa` for base64 (with polyfill notes for Node.js < 16)

### Bundle Size

This package is designed to be minimal:
- Zero dependencies
- Tree-shakeable exports
- ~2KB minified + gzipped (estimated)

## Limitations

### What This Package Does NOT Provide

1. **HTTP clients** - You bring your own `fetch`
2. **DNS resolution** - Provided by `@evp/verifier`
3. **Key generation** - Provided by `@evp/issuer`
4. **Framework integrations** - This is framework-agnostic

### Known Limitations

1. **Email validation is basic** - Complex email validation is out of scope
2. **No internationalized email support** - IDN emails may need preprocessing
3. **Timestamps are Unix seconds** - Millisecond precision is not supported

## Changelog

### 0.1.0 (Unreleased)

- Initial implementation
- Core types and utilities
- Testing utilities

## License

MIT
