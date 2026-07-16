<!-- generated-by: gsd-doc-writer -->
# Verifier API

[Documentation home](README.md) · [Protocol flow](PROTOCOL-FLOW.md) · [Configuration](CONFIGURATION.md) · [Testing](TESTING.md)

`@aspect-evp/verifier` verifies an EVT+KB submitted to a relying party.

## Basic use

```typescript
const verifier = new EmailVerificationVerifier({
  rpOrigin: 'https://rp.example',
});

const result = await verifier.verify(token, sessionNonce);
```

The RP must generate a cryptographically random nonce with at least 128 bits of entropy, bind it to the user session, expire it quickly, and consume it after successful verification.

## Verification sequence

The verifier:

1. Parses the `<EVT>~<KB-JWT>` presentation.
2. Validates the required `typ: evt+jwt`, `alg`, and `kid` header parameters.
3. Resolves exactly one `iss=` DNS TXT delegation for the email domain.
4. Requires HTTPS issuer metadata and JWKS endpoints.
5. Verifies the EVT signature and required claims.
6. Verifies the KB-JWT with `cnf.jwk`.
7. Checks RP origin, nonce, timestamp, and `sd_hash` over the complete EVT including `~`.

## Configuration

```typescript
const verifier = new EmailVerificationVerifier({
  rpOrigin: 'https://rp.example',
  clockTolerance: 60,
  jwksCacheTTL: 600,
  dnsResolver: nodeDnsResolver,
  fetch: instrumentedFetch,
});
```

Use `nodeDnsResolver` in conventional Node.js services. The default resolver uses Cloudflare DNS-over-HTTPS for environments without native DNS. A custom resolver and `fetch` implementation make policy, observability, and testing explicit.

## Result

```typescript
interface VerificationResult {
  email: string;
  email_verified: boolean;
  issuer: string;
  issuedAt: Date;
  isPrivateEmail?: boolean;
}
```

## Caching and rotation

Remote JWKS uses `jose` caching. Custom-fetch JWKS is refreshed after `jwksCacheTTL`, and an unknown `kid` triggers an immediate refresh to support emergency rotation.

## Failure handling

All parse, discovery, metadata, signature, claim, audience, nonce, and timestamp failures reject with `EVPError`. Do not treat an unverified token as an email assertion; use the application's normal email-verification flow instead.

Consume the expected nonce after a successful verification and reject reuse in application session state. The verifier checks equality and freshness but does not own nonce persistence.

Verification authenticates an issuer assertion; it does not prove deliverability or replace application login and abuse policy. See [standards status and conformance](STANDARDS-CONFORMANCE.md).
