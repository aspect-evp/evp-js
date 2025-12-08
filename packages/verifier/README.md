# @aspect-evp/verifier

> EVP token verification for web applications (Relying Parties).

[![npm version](https://img.shields.io/npm/v/@aspect-evp/verifier.svg)](https://www.npmjs.com/package/@aspect-evp/verifier)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

```bash
npm install @aspect-evp/verifier
```

## Usage

```typescript
import { EmailVerificationVerifier } from '@aspect-evp/verifier';

const verifier = new EmailVerificationVerifier({
  rpOrigin: 'https://myapp.example.com'
});

// When you receive an SD-JWT+KB from the browser
async function handleEmailVerification(sdJwtKb: string, sessionNonce: string) {
  try {
    const result = await verifier.verify(sdJwtKb, sessionNonce);

    console.log('Verified email:', result.email);
    console.log('Issuer:', result.issuer);
    console.log('Issued at:', result.issuedAt);

    // Proceed with user registration/login
  } catch (error) {
    if (error instanceof EVPError) {
      console.log('Verification failed:', error.code);
    }
  }
}
```

## Configuration

```typescript
const verifier = new EmailVerificationVerifier({
  // Required: your application's origin
  rpOrigin: 'https://myapp.example.com',

  // Optional: clock tolerance in seconds (default: 60)
  clockTolerance: 120,

  // Optional: custom DNS resolver
  dnsResolver: customResolver,

  // Optional: custom fetch for JWKS
  fetch: customFetch,
});
```

## DNS Resolvers

```typescript
import {
  EmailVerificationVerifier,
  defaultDnsResolver,  // DNS-over-HTTPS (Cloudflare)
  nodeDnsResolver      // Node.js dns/promises
} from '@aspect-evp/verifier';

// Use Node.js DNS (faster in server environments)
const verifier = new EmailVerificationVerifier({
  rpOrigin: 'https://myapp.example.com',
  dnsResolver: nodeDnsResolver,
});
```

## Verification Result

```typescript
interface VerificationResult {
  email: string;      // Verified email address
  issuer: string;     // Issuer domain
  issuedAt: Date;     // Token issuance time
}
```

## Documentation

See the [full documentation](https://github.com/aspect/evp/blob/main/docs/verifier.md) for complete API reference.

## License

MIT
