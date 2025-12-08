# @aspect-evp/verifier

> EVP token verification for web applications (Relying Parties).

## Overview

`@aspect-evp/verifier` enables web applications to verify EVP tokens received from browsers. It handles:

- Parsing SD-JWT+KB tokens
- DNS lookup for issuer discovery
- Fetching and caching issuer JWKS
- Cryptographic verification of both SD-JWT and KB-JWT
- Nonce and audience validation

## Who Should Use This?

This package is for **web applications** (Relying Parties) that want to accept verified emails via EVP instead of traditional email verification.

**Examples:**
- User registration flows
- Account recovery
- Email change verification
- Any flow that currently sends verification emails

## Installation

```bash
npm install @aspect-evp/verifier @aspect-evp/core
```

## Dependencies

| Package | Why |
|---------|-----|
| `jose` | JWT verification, JWKS fetching |
| `@aspect-evp/core` | Shared types and utilities |

## Quick Start

```typescript
import { EmailVerificationVerifier } from '@aspect-evp/verifier';

// Initialize verifier with your origin
const verifier = new EmailVerificationVerifier({
  rpOrigin: 'https://myapp.example.com'
});

// When you receive an SD-JWT+KB from the browser's emailverified event
async function handleVerification(sdJwtKb: string, sessionNonce: string) {
  try {
    const result = await verifier.verify(sdJwtKb, sessionNonce);
    
    // Success! User has verified control of this email
    console.log('Email:', result.email);
    console.log('Verified by:', result.issuer);
    console.log('Issued at:', result.issuedAt);
    
    // Create user account or log them in
    await createOrLoginUser(result.email);
    
  } catch (error) {
    // Verification failed - don't trust the email
    console.error('Verification failed:', error);
    // Fall back to traditional email verification
  }
}
```

## Complete API Reference

### `EmailVerificationVerifier`

#### Constructor

```typescript
new EmailVerificationVerifier(config: VerifierConfig)
```

**Config Options:**

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `rpOrigin` | `string` | ✅ | - | Your application's origin (e.g., `https://example.com`) |
| `dnsResolver` | `function` | ❌ | DNS-over-HTTPS | Custom DNS resolver |
| `fetch` | `function` | ❌ | `globalThis.fetch` | Custom fetch implementation |
| `clockTolerance` | `number` | ❌ | `60` | Timestamp tolerance in seconds |
| `jwksCacheTTL` | `number` | ❌ | `600` | JWKS cache duration in seconds |

#### `verify(sdJwtKb: string, expectedNonce: string): Promise<VerificationResult>`

Verifies an SD-JWT+KB token:

```typescript
interface VerificationResult {
  email: string;           // The verified email address
  email_verified: boolean; // Always true
  issuer: string;          // Who verified the email
  issuedAt: Date;          // When the token was issued
}
```

**Verification Steps:**

1. **Parse token** - Split SD-JWT and KB-JWT components
2. **Extract claims** - Decode SD-JWT payload
3. **DNS lookup** - Find issuer for email domain
4. **Validate issuer** - Ensure SD-JWT issuer matches DNS
5. **Fetch JWKS** - Get issuer's public keys
6. **Verify SD-JWT** - Check signature and claims
7. **Verify KB-JWT** - Check signature, audience, nonce, and sd_hash

**Example:**

```typescript
const verifier = new EmailVerificationVerifier({
  rpOrigin: 'https://myapp.com'
});

try {
  const result = await verifier.verify(token, 'session-nonce-123');
  console.log(`Verified: ${result.email} by ${result.issuer}`);
} catch (error) {
  if (error instanceof EVPError) {
    switch (error.code) {
      case 'invalid_token':
        console.error('Token is invalid or tampered');
        break;
      case 'invalid_request':
        console.error('Malformed token format');
        break;
    }
  }
}
```

### DNS Resolution

#### Default: DNS-over-HTTPS (DoH)

By default, the verifier uses Cloudflare's DNS-over-HTTPS:

```typescript
// Default behavior - works in browsers and edge runtimes
const verifier = new EmailVerificationVerifier({
  rpOrigin: 'https://myapp.com'
});
```

#### Node.js Native DNS

For Node.js servers, you can use native DNS:

```typescript
import { EmailVerificationVerifier, nodeDnsResolver } from '@aspect-evp/verifier';

const verifier = new EmailVerificationVerifier({
  rpOrigin: 'https://myapp.com',
  dnsResolver: nodeDnsResolver
});
```

#### Custom DNS Resolver

For testing or special environments:

```typescript
const verifier = new EmailVerificationVerifier({
  rpOrigin: 'https://myapp.com',
  dnsResolver: async (emailDomain) => {
    // Your custom logic to resolve _email-verification.{domain}
    // Return the issuer identifier or null if not found
    return 'issuer.example.com';
  }
});
```

### JWKS Caching

The verifier caches JWKS responses to avoid repeated fetches:

```typescript
const verifier = new EmailVerificationVerifier({
  rpOrigin: 'https://myapp.com',
  jwksCacheTTL: 300 // Cache for 5 minutes
});
```

**Note:** The `jose` library handles JWKS caching internally. The `jwksCacheTTL` option configures the maximum age.

## Integration Examples

### Express.js

```typescript
import express from 'express';
import crypto from 'crypto';
import { EmailVerificationVerifier, EVPError } from '@aspect-evp/verifier';

const app = express();
app.use(express.json());

const verifier = new EmailVerificationVerifier({
  rpOrigin: process.env.APP_ORIGIN!
});

// Store nonces in session (use Redis in production)
const sessionNonces = new Map<string, string>();

// Step 1: Generate nonce for the email form
app.get('/api/email-verification/nonce', (req, res) => {
  const sessionId = req.session.id; // Your session management
  const nonce = crypto.randomUUID();
  
  sessionNonces.set(sessionId, nonce);
  
  res.json({ nonce });
});

// Step 2: Verify the token from browser
app.post('/api/email-verification/verify', async (req, res) => {
  const { token } = req.body;
  const sessionId = req.session.id;
  
  // Get expected nonce
  const expectedNonce = sessionNonces.get(sessionId);
  if (!expectedNonce) {
    return res.status(400).json({ error: 'No pending verification' });
  }
  
  try {
    const result = await verifier.verify(token, expectedNonce);
    
    // Clean up nonce
    sessionNonces.delete(sessionId);
    
    // Success - create or login user
    const user = await findOrCreateUser(result.email);
    req.session.userId = user.id;
    
    res.json({ 
      success: true, 
      email: result.email 
    });
    
  } catch (error) {
    sessionNonces.delete(sessionId);
    
    if (error instanceof EVPError) {
      return res.status(400).json({
        error: error.code,
        message: error.description
      });
    }
    
    res.status(500).json({ error: 'Verification failed' });
  }
});
```

### Next.js App Router

```typescript
// app/api/verify-email/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { EmailVerificationVerifier } from '@aspect-evp/verifier';

const verifier = new EmailVerificationVerifier({
  rpOrigin: process.env.NEXT_PUBLIC_APP_URL!
});

export async function POST(request: NextRequest) {
  const { token } = await request.json();
  
  // Get nonce from cookie
  const cookieStore = cookies();
  const nonce = cookieStore.get('evp_nonce')?.value;
  
  if (!nonce) {
    return NextResponse.json(
      { error: 'No pending verification' },
      { status: 400 }
    );
  }
  
  try {
    const result = await verifier.verify(token, nonce);
    
    // Clear nonce cookie
    cookieStore.delete('evp_nonce');
    
    return NextResponse.json({
      success: true,
      email: result.email,
      issuer: result.issuer
    });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Verification failed' },
      { status: 400 }
    );
  }
}
```

### Hono (Edge/Workers)

```typescript
import { Hono } from 'hono';
import { EmailVerificationVerifier } from '@aspect-evp/verifier';

const app = new Hono();

const verifier = new EmailVerificationVerifier({
  rpOrigin: 'https://myapp.workers.dev'
});

app.post('/verify', async (c) => {
  const { token, nonce } = await c.req.json();
  
  // In production, validate nonce against session/KV store
  
  try {
    const result = await verifier.verify(token, nonce);
    
    return c.json({
      email: result.email,
      verified: true
    });
    
  } catch (error) {
    return c.json({ error: 'Verification failed' }, 400);
  }
});

export default app;
```

## Frontend Integration

### HTML Form with EVP Support

```html
<!-- This won't work until browsers support EVP -->
<form id="signup-form">
  <input 
    id="email"
    type="email"
    autocomplete="email"
    data-nonce="generated-server-side"
  />
  <button type="submit">Sign Up</button>
</form>

<script>
const emailInput = document.getElementById('email');
const form = document.getElementById('signup-form');

// Listen for EVP verification event (future browser API)
emailInput.addEventListener('emailverified', async (event) => {
  const { presentationToken } = event;
  
  // Send to your server for verification
  const response = await fetch('/api/verify-email', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ 
      token: presentationToken,
      nonce: emailInput.dataset.nonce
    })
  });
  
  if (response.ok) {
    const { email } = await response.json();
    console.log('Email verified:', email);
    // Proceed with signup
  }
});

// Fallback for browsers without EVP
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  
  // Traditional email verification flow
  await sendVerificationEmail(emailInput.value);
});
</script>
```

### React Hook (Future)

```typescript
// This is conceptual - EVP browser APIs don't exist yet

import { useEVP } from '@aspect-evp/react'; // Hypothetical future package

function SignupForm() {
  const { 
    verifiedEmail, 
    isSupported, 
    requestVerification 
  } = useEVP({
    rpOrigin: 'https://myapp.com',
    onVerified: async (email) => {
      await createAccount(email);
    }
  });
  
  if (!isSupported) {
    return <TraditionalEmailForm />;
  }
  
  return (
    <form>
      <EVPEmailInput 
        onVerified={requestVerification}
      />
    </form>
  );
}
```

## Error Handling

### Error Types

| Code | Meaning | Common Causes |
|------|---------|---------------|
| `invalid_request` | Malformed input | Missing token, invalid format |
| `invalid_token` | Verification failed | Tampered token, expired, wrong nonce |

### Detailed Error Handling

```typescript
import { EVPError } from '@aspect-evp/core';

try {
  const result = await verifier.verify(token, nonce);
} catch (error) {
  if (error instanceof EVPError) {
    switch (error.code) {
      case 'invalid_token':
        // Token verification failed
        if (error.description?.includes('expired')) {
          // Token too old
        } else if (error.description?.includes('nonce')) {
          // Nonce mismatch - possible replay attack
        } else if (error.description?.includes('issuer')) {
          // Issuer doesn't match DNS
        }
        break;
        
      case 'invalid_request':
        // Malformed token
        break;
    }
    
    // Log for debugging (don't expose to client)
    console.error(`EVP Error [${error.code}]: ${error.description}`);
    
    // Generic error to client
    return { error: 'Email verification failed' };
  }
  
  // Unexpected error
  throw error;
}
```

## Security Considerations

### Nonce Management

**Critical:** Nonces prevent replay attacks. You MUST:

1. **Generate cryptographically random nonces** - Use `crypto.randomUUID()` or similar
2. **Bind nonces to sessions** - Each session gets one nonce
3. **Single-use nonces** - Delete after verification (success or failure)
4. **Short-lived nonces** - Expire after ~5 minutes

```typescript
// Good: Cryptographically random
const nonce = crypto.randomUUID();

// Bad: Predictable
const nonce = Date.now().toString(); // ❌ Don't do this
```

### Origin Validation

The `rpOrigin` config must exactly match your application's origin:

```typescript
// ✅ Correct
new EmailVerificationVerifier({ rpOrigin: 'https://myapp.com' });

// ❌ Wrong - trailing slash
new EmailVerificationVerifier({ rpOrigin: 'https://myapp.com/' });

// ❌ Wrong - different port in production
new EmailVerificationVerifier({ rpOrigin: 'https://myapp.com:443' });
```

### Trust Model

When you verify an EVP token, you're trusting:

1. **The email provider** - That they correctly verified user owns the email
2. **DNS** - That the TXT record points to the legitimate issuer
3. **The browser** - That it correctly mediated the flow

**Risks:**
- Compromised email provider could issue false verifications
- DNS hijacking could redirect to malicious issuer
- Malicious browser extensions could intercept tokens

**Mitigations:**
- EVP is meant to complement, not replace, other security measures
- Consider requiring additional verification for sensitive operations
- Monitor for unusual patterns (many verifications from same IP, etc.)

## Testing

### Unit Tests

```typescript
import { EmailVerificationVerifier } from '@aspect-evp/verifier';
import { createTestFlow } from '@aspect-evp/core/testing';

describe('EmailVerificationVerifier', () => {
  let verifier: EmailVerificationVerifier;
  let testFlow: Awaited<ReturnType<typeof createTestFlow>>;

  beforeAll(async () => {
    testFlow = await createTestFlow({
      issuer: 'issuer.example.com',
      rpOrigin: 'https://myapp.com',
    });

    verifier = new EmailVerificationVerifier({
      rpOrigin: 'https://myapp.com',
      dnsResolver: testFlow.dnsResolver,
      fetch: testFlow.fetch,
    });
  });

  it('should verify valid tokens', async () => {
    const nonce = 'test-nonce-123';
    const token = await testFlow.createToken('user@example.com', nonce);

    const result = await verifier.verify(token, nonce);

    expect(result.email).toBe('user@example.com');
    expect(result.email_verified).toBe(true);
  });

  it('should reject wrong nonce', async () => {
    const token = await testFlow.createToken('user@example.com', 'correct-nonce');

    await expect(
      verifier.verify(token, 'wrong-nonce')
    ).rejects.toThrow('nonce mismatch');
  });
});
```

### Integration Tests

```typescript
import { EmailVerificationVerifier, nodeDnsResolver } from '@aspect-evp/verifier';

describe('Integration', () => {
  it('should resolve real DNS (if configured)', async () => {
    // This test requires actual DNS setup
    const verifier = new EmailVerificationVerifier({
      rpOrigin: 'https://myapp.com',
      dnsResolver: nodeDnsResolver
    });
    
    // Test with a domain that has EVP configured
    // (Currently no public issuers exist)
  });
});
```

## Performance Considerations

### Caching

- **JWKS is cached** - The `jose` library caches JWKS responses
- **DNS is NOT cached by default** - Consider caching in production

```typescript
// Custom DNS resolver with caching
const dnsCache = new Map<string, { issuer: string; expires: number }>();

const cachedDnsResolver = async (domain: string) => {
  const cached = dnsCache.get(domain);
  if (cached && cached.expires > Date.now()) {
    return cached.issuer;
  }
  
  const issuer = await defaultDnsResolver(domain);
  if (issuer) {
    dnsCache.set(domain, {
      issuer,
      expires: Date.now() + 5 * 60 * 1000 // 5 minutes
    });
  }
  
  return issuer;
};
```

### Latency

Verification involves:
1. DNS lookup (~50-200ms)
2. Metadata fetch (~50-200ms)
3. JWKS fetch (~50-200ms if not cached)
4. Cryptographic verification (~1-5ms)

**First verification:** 150-600ms
**Subsequent (cached):** 50-100ms

## Limitations

### Current Limitations

1. **No browser support** - EVP is not implemented in any browser yet
2. **No public issuers** - No email providers support EVP yet
3. **DNS-over-HTTPS only in browsers** - Native DNS not available
4. **No automatic fallback** - You must implement fallback to email

### What This Package Cannot Do

- ❌ Work without browser implementation
- ❌ Verify emails independently (relies on issuers)
- ❌ Replace DKIM/SPF/DMARC email authentication
- ❌ Work offline

## Changelog

### 0.1.0 (Unreleased)

- Initial implementation
- DNS-over-HTTPS and Node.js DNS support
- Full verification pipeline
- Comprehensive error handling

## License

MIT
