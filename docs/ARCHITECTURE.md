<!-- generated-by: gsd-doc-writer -->
# Architecture

EVP is a framework-agnostic TypeScript monorepo. It separates protocol primitives, issuer behavior, relying-party verification, and developer tooling into independently published packages. The libraries use standard Web APIs at HTTP boundaries and `jose` for JOSE operations.

## System overview

The issuer accepts a signed JSON issuance request, delegates authentication and private-address policy to application callbacks, and returns a signed EVT. The verifier accepts an EVT+KB presentation, discovers the authoritative issuer through DNS, retrieves HTTPS metadata and JWKS, and validates both signatures and all binding claims.

## Component diagram

```mermaid
graph TD
    AppIssuer[Issuer application] --> Issuer[@aspect-evp/issuer]
    Issuer --> Core[@aspect-evp/core]
    Browser[Browser or test client] --> Issuer
    Browser --> AppRP[RP application]
    AppRP --> Verifier[@aspect-evp/verifier]
    Verifier --> Core
    Verifier --> DNS[DNS resolver]
    Verifier --> Metadata[Issuer metadata and JWKS]
    CLI[@aspect-evp/cli] --> Core
    CLI --> Issuer
    CLI --> Verifier
```

## Package boundaries

| Package | Responsibility | Depends on |
|---|---|---|
| `@aspect-evp/core` | Types, constants, errors, encoding, EVT parsing, hashing, HTTP Message Signatures, and test fixtures. | `jose` |
| `@aspect-evp/issuer` | Issuer metadata, JWKS, key generation, EVT signing, and framework-neutral issuance middleware. | core, `jose` |
| `@aspect-evp/verifier` | DNS discovery, metadata/JWKS loading, caching, and complete EVT+KB verification. | core, `jose` |
| `@aspect-evp/cli` | Commands for key generation, issuance, inspection, DNS lookup, verification, and simulations. | core, issuer, verifier |

Dependencies point inward toward core. Issuer and verifier do not depend on each other.

## Data flow

1. `createSignedIssuanceRequest()` creates a JSON POST signed by the browser's ephemeral private key.
2. `createIssuerMiddleware()` validates the HTTP envelope and signature before parsing attacker-controlled JSON.
3. Application callbacks authenticate the email and apply private-address or WebAuthn policy.
4. `EmailVerificationIssuer.issueToken()` signs an EVT containing the browser public key in `cnf.jwk`.
5. The browser creates a KB-JWT over the RP origin, nonce, timestamp, and EVT hash.
6. `EmailVerificationVerifier.verify()` resolves DNS, loads metadata/JWKS, verifies the EVT, then verifies key binding.

See [Protocol flow](PROTOCOL-FLOW.md) for field-level details.

## Key abstractions

| Abstraction | Location | Role |
|---|---|---|
| `EVPError` | `packages/core/src/errors.ts` | Typed protocol errors and HTTP status mapping. |
| `createSignedIssuanceRequest()` | `packages/core/src/http-signatures.ts` | Builds the browser/test-side HTTP Message Signature request. |
| `verifyHttpMessageSignature()` | `packages/core/src/http-signatures.ts` | Verifies covered components, freshness, key type, and signature. |
| `EmailVerificationIssuer` | `packages/issuer/src/issuer.ts` | Publishes metadata/JWKS and signs EVTs. |
| `createIssuerMiddleware()` | `packages/issuer/src/middleware.ts` | Framework-neutral issuance pipeline and policy callback boundary. |
| `EmailVerificationVerifier` | `packages/verifier/src/verifier.ts` | Orchestrates complete RP verification. |
| `createJWKSFetcher()` | `packages/verifier/src/jwks.ts` | Provides remote or injected-fetch JWKS loading and rotation behavior. |
| `DnsResolver` | `packages/core/src/types.ts` | Injected DNS discovery interface. |

## Trust boundaries

- **HTTP request:** all headers and JSON are untrusted until signature and schema validation complete.
- **Authentication callbacks:** application code owns session, email-control, WebAuthn, and relay-address policy.
- **DNS and network:** verifier discovery is untrusted input; issuer identifiers and metadata URLs are validated and HTTPS is required.
- **JWKS:** only keys selected by the verified issuer metadata are used for EVT verification.
- **Presentation:** decoded claims are never returned before both EVT and KB-JWT validation succeeds.

## Failure and cache behavior

The implementation fails closed with `EVPError`. The custom-fetch JWKS path caches keys for `jwksCacheTTL` and refreshes immediately when an unknown `kid` appears before expiry. DNS caching is opt-in through `createCachingResolver()`.

## Directory structure

```text
packages/
  core/       Shared protocol and testing primitives
  issuer/     Email-provider implementation
  verifier/   Relying-party implementation
  cli/        Developer commands
docs/         Guided documentation and package API guides
.github/      CI and release workflows
.changeset/   Release notes and versioning metadata
```
