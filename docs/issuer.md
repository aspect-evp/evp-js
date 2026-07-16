<!-- generated-by: gsd-doc-writer -->
# Issuer API

[Documentation home](README.md) · [Protocol flow](PROTOCOL-FLOW.md) · [Configuration](CONFIGURATION.md) · [Testing](TESTING.md)

`@aspect-evp/issuer` implements issuer metadata, JWKS publication, current-draft issuance request verification, and EVT creation.

## Configuration

```typescript
const issuer = new EmailVerificationIssuer({
  issuer: 'issuer.example',
  privateKey,
  kid: '2026-07',
  algorithm: 'EdDSA',
  clockTolerance: 60,
  privateEmailSupported: true,
  webauthnSupported: true,
});
```

Capability flags are included in `getMetadata()` only when enabled.

## Published endpoints

```typescript
issuer.getMetadata('https://issuer.example');
issuer.getJWKS();
```

Serve these values from `GET /.well-known/email-verification` and the `jwks_uri` returned by metadata.

## Issuance middleware

```typescript
const middleware = createIssuerMiddleware(
  issuer,
  async (cookie, email) => userSessionOwnsEmail(cookie, email),
  {
    createPrivateEmail: async (email) => createRelayAddress(email),
    verifyDirectedEmail: async (email, directed) => relayBelongsTo(email, directed),
    createWebAuthnChallenge: async (email) => createChallenge(email),
    verifyWebAuthnResponse: async (email, assertion, cookie) =>
      verifyAssertion(email, assertion, cookie),
  }
);

const result = await middleware.handleIssuance(webRequest);
const response = toResponse(result);
```

The middleware requires POST, JSON, `Sec-Fetch-Dest: email-verification`, the three HTTP Message Signature headers, coverage of the required RFC 9421 components and cookies when present, a fresh signature timestamp, and a syntactically valid email. Other destination values are rejected.

Authentication, private-address storage/routing, and WebAuthn credential policy remain application responsibilities and are injected through callbacks.

## Private emails

`private_email` and `directed_email` are mutually exclusive. A private address callback must return a syntactically valid email. Directed addresses are issued only after the application confirms their association with the requested account. Issued private EVTs contain `is_private_email: true`.

## WebAuthn fallback

If cookie authentication fails, `createWebAuthnChallenge` can return a `PublicKeyCredentialRequestOptions`-compatible challenge. A subsequent request containing `webauthn_response` is delegated to `verifyWebAuthnResponse`.

## Legacy request tokens

`EmailVerificationIssuer.verifyRequestToken()` remains available for experiments built against the older WICG request-token flow. It is deprecated and is not used by `createIssuerMiddleware()`.

## Operational requirements

- Keep signing keys outside source control and rotate them through stable `kid` values.
- Return the same `authentication_required` response whether an address is absent, logged out, or not controlled by the session.
- Normalize response timing and apply rate limiting to reduce address enumeration.
- Validate WebAuthn challenges, origins, RP IDs, counters, and credential policy in application code; the library only delegates to callbacks.
- Apply deliverability, domain-reputation, abuse, and session-freshness policy in application code; an EVT does not replace those controls.

See [standards status and conformance](STANDARDS-CONFORMANCE.md) for the implementation's conformance policy and unresolved upstream differences.
