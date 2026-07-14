<!-- generated-by: gsd-doc-writer -->
# Core API

[Documentation home](README.md) · [Protocol flow](PROTOCOL-FLOW.md) · [Issuer](issuer.md) · [Verifier](verifier.md)

`@aspect-evp/core` contains the protocol types, constants, token utilities, HTTP Message Signature profile, and test fixtures shared by issuers and relying parties.

The implementation tracks `draft-hardt-email-verification-00`. The WICG `request_token` format is retained only as a deprecated compatibility surface in the issuer package.

## Protocol constants

```typescript
import {
  createSignedIssuanceRequest,
  DNS_RECORD_PREFIX, // _email-verification
  WELL_KNOWN_PATH,   // /.well-known/email-verification
  SD_JWT_TYPE,       // evt+jwt
  KB_JWT_TYPE,       // kb+jwt
  parseSDJWTKB,
  verifyHttpMessageSignature,
} from '@aspect-evp/core';
```

## EVT+KB parsing

```typescript
const { sdJwt, kbJwt, sdJwtForHash } = parseSDJWTKB(token);
```

- `sdJwt` includes the required trailing `~`.
- `sdJwtForHash` also includes the trailing `~`, as required by the current draft.
- `kbJwt` is `null` when key binding is absent.

## HTTP Message Signatures

The draft profile covers `@method`, `@authority`, `@path`, and `signature-key`. When a Cookie header is present, it is covered as well.

```typescript
const request = await createSignedIssuanceRequest(
  'https://issuer.example/email-verification/issuance',
  { email: 'user@example.com' },
  ephemeralPrivateJwk,
  { cookie: 'session=...' }
);

const { publicKey, algorithm } = await verifyHttpMessageSignature(request);
```

Supported key profiles are Ed25519/EdDSA, P-256/ES256, P-384/ES384, and RSA/RS256. Signature timestamps default to a 60-second tolerance.

## Metadata extensions

`IssuerMetadata` includes `issuance_endpoint`, `jwks_uri`, `signing_alg_values_supported`, `webauthn_supported`, and `private_email_supported`.

## Test fixtures

```typescript
import { createTestFlow } from '@aspect-evp/core/testing';

const flow = await createTestFlow({
  issuer: 'issuer.example',
  rpOrigin: 'https://rp.example',
});

const token = await flow.createToken('user@example.com', nonce);
```

Fixtures create `evt+jwt` tokens and hash the complete EVT including its trailing `~`.

## Error handling

`EVPError` carries a machine-readable code, optional description, JSON serialization, and an HTTP status mapping. `toEVPError()` normalizes unknown failures, while `getErrorMessage()` extracts a safe message from values thrown by JavaScript or dependencies.

## Runtime requirements

- Node.js 20 or newer.
- Modern browser and edge runtimes with Web Crypto, `Request`, `Response`, `fetch`, `atob`, and `btoa`.

## References

- [IETF Email Verification Protocol draft](https://datatracker.ietf.org/doc/draft-hardt-email-verification/)
- [WICG Email Verification API](https://github.com/WICG/email-verification)
