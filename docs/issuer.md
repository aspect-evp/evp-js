# @evp/issuer

> EVP issuer implementation for email providers.

## Overview

`@evp/issuer` provides everything an email provider needs to implement the Email Verification Protocol. It handles:

- Generating issuer metadata (`/.well-known/email-verification`)
- Serving JWKS (JSON Web Key Set)
- Verifying browser request tokens
- Issuing SD-JWT tokens for verified emails

## Who Should Use This?

This package is for **email providers** who want to enable their users to verify email ownership without traditional email verification flows.

**Examples:**
- Gmail, Outlook, Yahoo Mail, ProtonMail
- Corporate email providers (Google Workspace, Microsoft 365)
- Self-hosted email solutions (Postfix, Dovecot with webmail)
- Email-as-a-service platforms

## Installation

```bash
npm install @evp/issuer @evp/core
```

## Dependencies

| Package | Why |
|---------|-----|
| `jose` | JWT signing/verification, JWKS generation |
| `@evp/core` | Shared types and utilities |

## Quick Start

### 1. Generate Signing Keys

First, generate a signing keypair. This should be done once and stored securely:

```typescript
import { EmailVerificationIssuer } from '@evp/issuer';

// Generate a new EdDSA keypair
const { privateKey, publicKey } = await EmailVerificationIssuer.generateKeyPair('EdDSA');

// Store privateKey securely (e.g., in a secret manager)
console.log('Private Key (KEEP SECRET):', JSON.stringify(privateKey));
console.log('Public Key:', JSON.stringify(publicKey));
```

### 2. Initialize the Issuer

```typescript
import { EmailVerificationIssuer } from '@evp/issuer';

const issuer = new EmailVerificationIssuer({
  // Your email domain (eTLD+1)
  issuer: 'mail.example.com',
  
  // Your private signing key (JWK format)
  privateKey: {
    kty: 'OKP',
    crv: 'Ed25519',
    x: '...',
    d: '...' // Private key component
  },
  
  // Key identifier (use for key rotation)
  kid: '2024-01-key',
  
  // Signing algorithm (default: 'EdDSA')
  algorithm: 'EdDSA'
});
```

### 3. Configure DNS

Add a TXT record to your DNS:

```
_email-verification.mail.example.com. IN TXT "iss=mail.example.com"
```

This tells browsers that `mail.example.com` is authorized to verify emails for `@mail.example.com`.

### 4. Serve Required Endpoints

```typescript
// Using Express.js as an example

import express from 'express';

const app = express();

// 1. Metadata endpoint
app.get('/.well-known/email-verification', (req, res) => {
  res.json(issuer.getMetadata('https://mail.example.com'));
});

// 2. JWKS endpoint
app.get('/email-verification/jwks', async (req, res) => {
  res.json(await issuer.getJWKS());
});

// 3. Issuance endpoint
app.post('/email-verification/issuance', 
  express.urlencoded({ extended: false }),
  async (req, res) => {
    // See full implementation below
  }
);
```

## Complete API Reference

### `EmailVerificationIssuer`

#### Constructor

```typescript
new EmailVerificationIssuer(config: IssuerConfig)
```

**Config Options:**

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `issuer` | `string` | ✅ | Your issuer identifier (eTLD+1 domain) |
| `privateKey` | `JsonWebKey` | ✅ | Private signing key in JWK format |
| `kid` | `string` | ✅ | Key identifier for JWKS |
| `algorithm` | `string` | ❌ | Signing algorithm (default: `'EdDSA'`) |

#### `getMetadata(baseUrl: string): IssuerMetadata`

Returns the metadata object for `/.well-known/email-verification`:

```typescript
const metadata = issuer.getMetadata('https://accounts.example.com');
// {
//   issuance_endpoint: 'https://accounts.example.com/email-verification/issuance',
//   jwks_uri: 'https://accounts.example.com/email-verification/jwks',
//   signing_alg_values_supported: ['EdDSA']
// }
```

#### `getJWKS(): Promise<{ keys: JsonWebKey[] }>`

Returns the JWKS containing public keys:

```typescript
const jwks = await issuer.getJWKS();
// {
//   keys: [{
//     kty: 'OKP',
//     crv: 'Ed25519',
//     x: '...',
//     kid: '2024-01-key',
//     use: 'sig',
//     alg: 'EdDSA'
//   }]
// }
```

#### `verifyRequestToken(requestToken: string): Promise<VerifyResult>`

Verifies a request token from the browser:

```typescript
interface VerifyResult {
  payload: RequestTokenPayload;
  browserPublicKey: JsonWebKey;
}

try {
  const { payload, browserPublicKey } = await issuer.verifyRequestToken(token);
  console.log('Email to verify:', payload.email);
  console.log('Browser public key:', browserPublicKey);
} catch (error) {
  if (error instanceof EVPError) {
    console.error('Verification failed:', error.code, error.description);
  }
}
```

**Verification Steps:**
1. Decode JWT header and extract `jwk`
2. Verify `aud` matches issuer identifier
3. Verify `iat` is within 60 seconds of current time
4. Verify JWT signature using browser's public key

#### `issueToken(email: string, browserPublicKey: JsonWebKey): Promise<string>`

Issues an SD-JWT for a verified email:

```typescript
const sdJwt = await issuer.issueToken(
  'user@example.com',
  browserPublicKey
);
// Returns: 'eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJtYWlsLmV4YW1wbGUuY29tIn0.signature~'
```

**The returned token:**
- Is signed with your private key
- Contains `email` and `email_verified: true` claims
- Contains `cnf` claim with browser's public key
- Ends with `~` (SD-JWT format with no disclosures)

#### Static: `generateKeyPair(algorithm?: string)`

Generates a new signing keypair:

```typescript
const { privateKey, publicKey } = await EmailVerificationIssuer.generateKeyPair('EdDSA');
```

**Supported Algorithms:**
- `EdDSA` (recommended, uses Ed25519)
- `ES256` (ECDSA with P-256)
- `ES384` (ECDSA with P-384)
- `RS256` (RSA, larger keys)

### `createIssuerMiddleware(issuer, verifyUserOwnsEmail)`

Creates request handlers for common frameworks:

```typescript
import { createIssuerMiddleware } from '@evp/issuer';

const middleware = createIssuerMiddleware(
  issuer,
  async (sessionCookie, email) => {
    // Your logic to verify the user controls this email
    // Return true if the logged-in user owns the email
    const user = await getUserFromSession(sessionCookie);
    return user?.emails.includes(email) ?? false;
  }
);

// Use with any framework that supports Request/Response
app.post('/email-verification/issuance', (req) => middleware.handleIssuance(req));
```

## Complete Implementation Example

### Express.js

```typescript
import express from 'express';
import { EmailVerificationIssuer, EVPError } from '@evp/issuer';

const app = express();

// Initialize issuer (in production, load key from secret manager)
const issuer = new EmailVerificationIssuer({
  issuer: 'mail.example.com',
  privateKey: JSON.parse(process.env.EVP_PRIVATE_KEY!),
  kid: process.env.EVP_KEY_ID!
});

// Your user authentication logic
async function getUserFromSession(cookie: string): Promise<User | null> {
  // Parse session cookie and return user
  // This is YOUR responsibility to implement
}

async function userOwnsEmail(cookie: string, email: string): Promise<boolean> {
  const user = await getUserFromSession(cookie);
  if (!user) return false;
  
  // Check if user has verified ownership of this email
  return user.verifiedEmails.includes(email.toLowerCase());
}

// Metadata endpoint
app.get('/.well-known/email-verification', (req, res) => {
  res.json(issuer.getMetadata(`https://${req.hostname}`));
});

// JWKS endpoint
app.get('/email-verification/jwks', async (req, res) => {
  res.json(await issuer.getJWKS());
});

// Issuance endpoint
app.post('/email-verification/issuance',
  express.urlencoded({ extended: false }),
  async (req, res) => {
    // 1. Verify Content-Type
    if (!req.is('application/x-www-form-urlencoded')) {
      return res.status(415).end();
    }
    
    // 2. Verify Sec-Fetch-Dest header
    if (req.get('Sec-Fetch-Dest') !== 'email-verification') {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing or invalid Sec-Fetch-Dest header'
      });
    }
    
    // 3. Get request token
    const requestToken = req.body.request_token;
    if (!requestToken) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing request_token'
      });
    }
    
    try {
      // 4. Verify the request token
      const { payload, browserPublicKey } = await issuer.verifyRequestToken(requestToken);
      
      // 5. Check if user owns this email
      const cookie = req.get('Cookie') || '';
      const ownsEmail = await userOwnsEmail(cookie, payload.email);
      
      if (!ownsEmail) {
        return res.status(401).json({
          error: 'authentication_required',
          error_description: 'User must be authenticated and control the email'
        });
      }
      
      // 6. Issue the token
      const issuanceToken = await issuer.issueToken(payload.email, browserPublicKey);
      
      // 7. Return success
      return res.json({ issuance_token: issuanceToken });
      
    } catch (error) {
      if (error instanceof EVPError) {
        const status = error.code === 'authentication_required' ? 401 : 400;
        return res.status(status).json({
          error: error.code,
          error_description: error.description
        });
      }
      
      console.error('EVP issuance error:', error);
      return res.status(500).json({
        error: 'server_error',
        error_description: 'Internal server error'
      });
    }
  }
);

app.listen(3000);
```

### Hono (Edge/Cloudflare Workers)

```typescript
import { Hono } from 'hono';
import { EmailVerificationIssuer, createIssuerMiddleware } from '@evp/issuer';

const app = new Hono();

// Initialize from environment
const issuer = new EmailVerificationIssuer({
  issuer: 'mail.example.com',
  privateKey: JSON.parse(EVP_PRIVATE_KEY),
  kid: EVP_KEY_ID
});

const middleware = createIssuerMiddleware(issuer, async (cookie, email) => {
  // Your auth logic here
  return true; // Replace with real verification
});

app.get('/.well-known/email-verification', (c) => {
  return c.json(issuer.getMetadata('https://mail.example.com'));
});

app.get('/email-verification/jwks', async (c) => {
  return c.json(await issuer.getJWKS());
});

app.post('/email-verification/issuance', async (c) => {
  return middleware.handleIssuance(c.req.raw);
});

export default app;
```

## Key Management

### Key Rotation

You should rotate signing keys periodically. Here's a recommended approach:

```typescript
// 1. Generate new key
const newKey = await EmailVerificationIssuer.generateKeyPair();
const newKid = `key-${Date.now()}`;

// 2. Add to JWKS (keep old key for verification)
const issuer = new EmailVerificationIssuer({
  issuer: 'mail.example.com',
  privateKey: newKey.privateKey,
  kid: newKid
});

// 3. Update JWKS to include both old and new public keys
app.get('/email-verification/jwks', async (req, res) => {
  const currentJwks = await issuer.getJWKS();
  
  // Add old keys that might still be in use
  const allKeys = [
    ...currentJwks.keys,
    ...oldPublicKeys // Keys from previous rotations
  ];
  
  res.json({ keys: allKeys });
});

// 4. After sufficient time (e.g., 24 hours), remove old keys
```

### Security Recommendations

1. **Store private keys in a secret manager** (AWS Secrets Manager, HashiCorp Vault, etc.)
2. **Never log or expose private keys**
3. **Use separate keys for different environments** (dev, staging, prod)
4. **Rotate keys at least annually**
5. **Keep old public keys in JWKS for 24-48 hours after rotation**

## Error Handling

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `invalid_request` | 400 | Malformed request or missing parameters |
| `invalid_token` | 400 | Token signature or claims invalid |
| `authentication_required` | 401 | User not logged in or doesn't own email |
| `server_error` | 500 | Internal server error |

### Error Response Format

```json
{
  "error": "invalid_token",
  "error_description": "Token signature verification failed"
}
```

## Security Considerations

### What You MUST Implement

1. **User Authentication**
   - Verify the user is logged in before issuing tokens
   - Verify the user actually controls the email address
   - Your session management is your responsibility

2. **HTTPS**
   - All endpoints MUST be served over HTTPS
   - Cookies should have `Secure` flag

3. **Rate Limiting**
   - Limit issuance requests per user/IP
   - Prevent enumeration attacks

4. **Logging & Monitoring**
   - Log issuance requests (without sensitive data)
   - Monitor for unusual patterns

### What This Library Handles

- ✅ Cryptographic signing with secure algorithms
- ✅ Token structure validation
- ✅ Timestamp validation
- ✅ Audience validation

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Stolen private key | Key rotation, secure storage |
| Replay attacks | Short token lifetime (60s), nonce in KB-JWT |
| Email enumeration | Rate limiting, don't reveal if email exists |
| Session hijacking | Your session security (HTTPOnly, Secure cookies) |

## Testing

### Unit Testing Your Implementation

```typescript
import { EmailVerificationIssuer } from '@evp/issuer';
import { createTestFlow } from '@evp/core/testing';

describe('Email Verification Issuer', () => {
  let issuer: EmailVerificationIssuer;
  
  beforeAll(async () => {
    const keys = await EmailVerificationIssuer.generateKeyPair();
    issuer = new EmailVerificationIssuer({
      issuer: 'test.example.com',
      privateKey: keys.privateKey,
      kid: 'test-key'
    });
  });
  
  it('should return valid metadata', () => {
    const metadata = issuer.getMetadata('https://test.example.com');
    
    expect(metadata.issuance_endpoint).toBe(
      'https://test.example.com/email-verification/issuance'
    );
    expect(metadata.jwks_uri).toBe(
      'https://test.example.com/email-verification/jwks'
    );
  });
  
  it('should issue valid tokens', async () => {
    const browserKey = await generateTestBrowserKey();
    
    const token = await issuer.issueToken('user@test.example.com', browserKey);
    
    expect(token).toMatch(/^eyJ.*~$/); // JWT ending with ~
  });
});
```

## Limitations

### Current Limitations

1. **No browser support yet** - Can't test end-to-end with real browsers
2. **Single key per issuer** - Multi-key support planned
3. **No key storage** - You must implement key persistence
4. **No built-in rate limiting** - Implement in your middleware

### Future Improvements

- [ ] Multi-key support for seamless rotation
- [ ] Built-in metrics/observability
- [ ] Passkey authentication support (per spec roadmap)
- [ ] Automatic JWKS caching headers

## Changelog

### 0.1.0 (Unreleased)

- Initial implementation
- EdDSA and ECDSA support
- Express and Hono examples

## License

MIT
