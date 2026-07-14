# @aspect-evp/issuer

> EVP issuer implementation for email providers.

[![npm version](https://img.shields.io/npm/v/@aspect-evp/issuer.svg)](https://www.npmjs.com/package/@aspect-evp/issuer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

```bash
npm install @aspect-evp/issuer
```

## Usage

```typescript
import { createIssuerMiddleware, EmailVerificationIssuer } from '@aspect-evp/issuer';

// Initialize with your signing key
const issuer = new EmailVerificationIssuer({
  issuer: 'mail.example.com',
  privateKey: yourPrivateKeyJWK,
  kid: '2024-01-key',
  algorithm: 'EdDSA',
  privateEmailSupported: true,
  webauthnSupported: true,
});

const middleware = createIssuerMiddleware(
  issuer,
  async (cookie, email) => userSessionOwnsEmail(cookie, email),
  {
    createPrivateEmail: async (email) => createRelayAddress(email),
    verifyDirectedEmail: async (email, directed) => relayBelongsTo(email, directed),
    createWebAuthnChallenge: async (email) => createChallenge(email),
    verifyWebAuthnResponse: async (email, response, cookie) =>
      verifyAssertion(email, response, cookie),
  }
);

// Serve /.well-known/email-verification
app.get('/.well-known/email-verification', (req, res) => {
  res.json(issuer.getMetadata('https://mail.example.com'));
});

// Serve JWKS
app.get('/email-verification/jwks', async (req, res) => {
  res.json(await issuer.getJWKS());
});

// Pass a standard Web Request to middleware.handleIssuance() and serialize
// its { status, headers, body } result with your framework adapter.
```

## Key Generation

```typescript
import { EmailVerificationIssuer } from '@aspect-evp/issuer';

// Generate a new EdDSA key pair
const keyPair = await EmailVerificationIssuer.generateKeyPair('EdDSA');
console.log(keyPair.privateKey); // Store securely
console.log(keyPair.publicKey);  // Expose via JWKS
```

## Supported Algorithms

- `EdDSA` (recommended)
- `ES256`
- `ES384`
- `RS256`

## Documentation

See the [full documentation](https://github.com/aspect-evp/evp-js/blob/main/docs/issuer.md) for complete API reference.

## License

MIT
