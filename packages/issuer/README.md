# @evp/issuer

> EVP issuer implementation for email providers.

[![npm version](https://img.shields.io/npm/v/@evp/issuer.svg)](https://www.npmjs.com/package/@evp/issuer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

```bash
npm install @evp/issuer
```

## Usage

```typescript
import { EmailVerificationIssuer } from '@evp/issuer';

// Initialize with your signing key
const issuer = new EmailVerificationIssuer({
  issuer: 'mail.example.com',
  privateKey: yourPrivateKeyJWK,
  kid: '2024-01-key',
  algorithm: 'EdDSA'
});

// Serve /.well-known/email-verification
app.get('/.well-known/email-verification', (req, res) => {
  res.json(issuer.getMetadata('https://mail.example.com'));
});

// Serve JWKS
app.get('/email-verification/jwks', async (req, res) => {
  res.json(await issuer.getJWKS());
});

// Handle issuance requests
app.post('/email-verification/issuance', async (req, res) => {
  const { request_token } = req.body;

  // Verify the request token from browser
  const { email, cnf } = await issuer.verifyRequestToken(request_token);

  // Verify user owns this email (your auth logic)
  if (!userOwnsEmail(req.session.userId, email)) {
    return res.status(403).json({ error: 'unauthorized_email' });
  }

  // Issue SD-JWT
  const sdJwt = await issuer.issueToken(email, cnf.jwk);
  res.json({ token: sdJwt });
});
```

## Key Generation

```typescript
import { EmailVerificationIssuer } from '@evp/issuer';

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

See the [full documentation](https://github.com/aspect/evp/blob/main/docs/issuer.md) for complete API reference.

## License

MIT
