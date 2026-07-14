# @aspect-evp/core

> Shared types, constants, and utilities for the Email Verification Protocol.

[![npm version](https://img.shields.io/npm/v/@aspect-evp/core.svg)](https://www.npmjs.com/package/@aspect-evp/core)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

```bash
npm install @aspect-evp/core
```

## Usage

```typescript
import {
  EVPError,
  parseSDJWTKB,
  sha256,
  getEmailDomain,
  SD_JWT_TYPE,
  KB_JWT_TYPE,
  createSignedIssuanceRequest,
} from '@aspect-evp/core';

// Parse EVT+KB token
const { sdJwt, kbJwt, sdJwtForHash } = parseSDJWTKB(token);

// Get email domain
const domain = getEmailDomain('user@gmail.com'); // 'gmail.com'

// Hash for sd_hash claim
const hash = await sha256(sdJwt);

// Browser/test tooling: create the current JSON + RFC 9421 issuance request
const request = await createSignedIssuanceRequest(
  'https://issuer.example/email-verification/issuance',
  { email: 'user@example.com' },
  ephemeralPrivateJwk,
  { cookie: 'session=...' }
);
```

## Testing Utilities

```typescript
import { createTestFlow, MockDnsResolver } from '@aspect-evp/core/testing';

// Create test fixtures
const testFlow = await createTestFlow({
  issuer: 'issuer.example.com',
  rpOrigin: 'https://myapp.example.com',
});

// Create tokens for testing
const token = await testFlow.createToken('user@example.com', 'nonce');
```

## Documentation

See the [full documentation](https://github.com/aspect-evp/evp-js/blob/main/docs/core.md) for complete API reference.

## License

MIT
