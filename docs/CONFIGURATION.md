<!-- generated-by: gsd-doc-writer -->
# Configuration

EVP is a library, not a hosted service. It reads no environment variables and has no runtime config file. Applications pass configuration explicitly to issuer and verifier constructors and provide policy callbacks to the issuance middleware.

## Environment variables

| Variable | Required | Default | Description |
|---|---:|---:|---|
| None | — | — | The repository contains no `process.env` configuration reads. |

Deployment code should load signing keys and application secrets from its own secret manager, then pass the resulting JWK and callbacks to this library.

## Issuer configuration

| Setting | Required | Default | Purpose |
|---|---:|---:|---|
| `issuer` | Yes | — | Issuer hostname without a scheme, path, credentials, or port. |
| `privateKey` | Yes | — | Private asymmetric JWK used to sign EVTs. |
| `kid` | Yes | — | Identifier published with the public JWK and EVT header. |
| `algorithm` | No | `EdDSA` | `EdDSA`, `ES256`, `ES384`, or `RS256`. |
| `clockTolerance` | No | `60` seconds | Tolerance used by the deprecated request-token verifier. |
| `webauthnSupported` | No | `false` | Advertises WebAuthn fallback support in metadata. |
| `privateEmailSupported` | No | `false` | Advertises private email support in metadata. |

```typescript
const issuer = new EmailVerificationIssuer({
  issuer: 'mail.example.com',
  privateKey,
  kid: '2026-07',
  algorithm: 'EdDSA',
  webauthnSupported: true,
  privateEmailSupported: true,
});
```

## Issuance middleware policy

`createIssuerMiddleware()` requires a `verifyUserOwnsEmail(cookie, email)` callback. Optional callbacks add private addresses, directed-address validation, and WebAuthn challenge/response handling. `clockTolerance` controls HTTP Message Signature freshness.

Do not advertise a capability unless its callbacks and application policy are deployed together.

## Verifier configuration

| Setting | Required | Default | Purpose |
|---|---:|---:|---|
| `rpOrigin` | Yes | — | Exact HTTPS origin expected in the KB-JWT audience. |
| `dnsResolver` | No | `defaultDnsResolver` | Resolves the email domain to an issuer hostname. |
| `fetch` | No | `globalThis.fetch` | Fetches metadata and JWKS. |
| `clockTolerance` | No | `60` seconds | Maximum timestamp skew for EVT and KB-JWT. |
| `jwksCacheTTL` | No | `600` seconds | TTL for JWKS loaded through a custom fetch function. |

```typescript
const verifier = new EmailVerificationVerifier({
  rpOrigin: 'https://app.example.com',
  dnsResolver: nodeDnsResolver,
  clockTolerance: 60,
  jwksCacheTTL: 600,
});
```

The constructor rejects origins with a path or trailing slash. Use the externally visible RP origin exactly as the browser places it in `aud`.

## Per-environment overrides

Construct separate configuration objects in application code for development, staging, and production. Tests should inject `createTestFlow()` fixtures or explicit DNS and fetch doubles instead of changing global process state.
