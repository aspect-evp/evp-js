# Architecture & Technical Decisions

This document explains the architectural decisions behind the EVP libraries.

## Project Structure

```
evp/
├── packages/
│   ├── core/                 # @aspect-evp/core
│   │   ├── src/
│   │   │   ├── index.ts      # Public exports
│   │   │   ├── types.ts      # Type definitions
│   │   │   ├── utils.ts      # Utility functions
│   │   │   ├── errors.ts     # EVPError class
│   │   │   ├── constants.ts  # Protocol constants
│   │   │   └── testing/      # Test utilities
│   │   │       ├── index.ts
│   │   │       ├── test-flow.ts
│   │   │       └── mock-dns.ts
│   │   ├── package.json
│   │   └── tsconfig.json
│   │
│   ├── issuer/               # @aspect-evp/issuer
│   │   ├── src/
│   │   │   ├── index.ts      # Public exports
│   │   │   ├── issuer.ts     # EmailVerificationIssuer class
│   │   │   ├── middleware.ts # Framework middleware helpers
│   │   │   └── keys.ts       # Key generation utilities
│   │   ├── package.json
│   │   └── tsconfig.json
│   │
│   └── verifier/             # @aspect-evp/verifier
│       ├── src/
│       │   ├── index.ts      # Public exports
│       │   ├── verifier.ts   # EmailVerificationVerifier class
│       │   ├── dns.ts        # DNS resolution implementations
│       │   └── jwks.ts       # JWKS fetching utilities
│       ├── package.json
│       └── tsconfig.json
│
├── docs/                     # Documentation
│   ├── core.md
│   ├── issuer.md
│   └── verifier.md
│
├── examples/                 # Example implementations
│   ├── express-issuer/
│   ├── express-verifier/
│   ├── hono-issuer/
│   └── nextjs-verifier/
│
├── package.json              # Monorepo root
├── pnpm-workspace.yaml       # pnpm workspace config
├── tsconfig.json             # Base TypeScript config
├── vitest.config.ts          # Test configuration
└── README.md
```

## Design Principles

### 1. Minimal Dependencies

**Decision:** Only use `jose` as external dependency.

**Rationale:**
- `jose` has zero dependencies itself
- Tree-shakeable, only imports what you use
- ~8KB total footprint
- Maintained by security expert (Filip Skokan)
- Works in all JavaScript runtimes

**Rejected alternatives:**
- `@sd-jwt/*` - Too heavy, 10+ packages, oriented toward VCs
- `jsonwebtoken` - Large bundle, node-forge dependency
- `node-jose` - Heavy, includes unused crypto polyfills

### 2. Framework Agnostic

**Decision:** Core libraries have no framework dependencies.

**Rationale:**
- Works with Express, Hono, Fastify, Koa, plain Node.js
- Works in edge runtimes (Cloudflare Workers, Vercel Edge)
- Works in browsers (when EVP is supported)
- Users bring their own HTTP layer

**Implementation:**
- Middleware helpers accept standard `Request` objects
- Return standard `Response` objects
- No express/hono/etc types in core

### 3. Explicit Over Implicit

**Decision:** Require explicit configuration, don't auto-detect.

**Rationale:**
- Security-sensitive code should be explicit
- Easier to audit and understand
- Prevents surprise behavior in production

**Example:**
```typescript
// We require this:
new EmailVerificationVerifier({ rpOrigin: 'https://example.com' });

// Instead of auto-detecting from request:
new EmailVerificationVerifier(); // ❌ Dangerous - what if request is spoofed?
```

### 4. Fail Closed

**Decision:** Any verification failure results in rejection.

**Rationale:**
- Security-first approach
- Better to reject valid tokens than accept invalid ones
- Forces proper error handling

**Implementation:**
- No "lenient" modes
- Strict timestamp validation
- Exact nonce matching
- Full signature verification

### 5. Testability First

**Decision:** Include comprehensive test utilities.

**Rationale:**
- EVP can't be tested end-to-end (no browser support)
- Developers need to simulate the complete flow
- Mock components enable unit testing

**Implementation:**
- `@aspect-evp/core/testing` exports test utilities
- `createTestFlow()` simulates entire protocol
- `MockDnsResolver` for controlled DNS responses

## Technical Decisions

### Token Format

**SD-JWT+KB structure:**
```
<SD-JWT>~<KB-JWT>
```

Where SD-JWT is:
```
<header>.<payload>.<signature>~
```

Note the trailing `~` even with no disclosures. This is per the SD-JWT spec.

**Why not standard JWT?**
- Key Binding (KB-JWT) proves browser possession of private key
- Prevents token theft/replay by third parties
- Issuer doesn't learn which RP receives the token

### Algorithm Support

**Supported algorithms:**
| Algorithm | Key Type | Notes |
|-----------|----------|-------|
| `EdDSA` | Ed25519 | **Recommended** - Fast, small keys, quantum-resistant prep |
| `ES256` | P-256 | Good compatibility, NIST approved |
| `ES384` | P-384 | Higher security margin |
| `RS256` | RSA 2048+ | Legacy compatibility, larger keys |

**Default:** `EdDSA`

**Rationale for EdDSA default:**
- Fastest verification
- Smallest keys/signatures
- No known timing attacks
- Increasing adoption (Passkeys, etc.)

### DNS Resolution

**Approaches implemented:**

1. **DNS-over-HTTPS (DoH)** - Default
   - Works in browsers
   - Works in edge runtimes
   - Uses Cloudflare (1.1.1.1)
   - Privacy-preserving

2. **Node.js native DNS** - Optional
   - Uses `dns/promises`
   - Faster in Node.js
   - Uses system resolver

**Why DoH as default?**
- Only option in browsers
- Works everywhere without dependencies
- Consistent behavior across environments

### Error Handling

**Error codes follow the spec:**
```typescript
type EVPErrorCode = 
  | "invalid_request"      // 400 - Bad input
  | "invalid_token"        // 400 - Verification failed  
  | "authentication_required" // 401 - User not authed (issuer only)
  | "server_error";        // 500 - Internal error
```

**Design:**
- Errors are classes, not strings
- Include machine-readable code
- Include human-readable description
- Can be serialized to JSON for HTTP responses

### Timestamp Handling

**Clock tolerance:** 60 seconds (configurable)

**Why 60 seconds?**
- Spec recommends 60 seconds for `iat`
- Accounts for clock skew between systems
- Short enough to prevent significant replay window

**Validation:**
```typescript
const now = Math.floor(Date.now() / 1000);
const diff = Math.abs(now - tokenIat);
if (diff > clockTolerance) {
  throw new EVPError('invalid_token', 'Token timestamp out of range');
}
```

## Security Analysis

### Threat Model

#### Assets to Protect
1. User's email address (privacy)
2. Verification integrity (prevent false verification)
3. Session security (prevent hijacking)

#### Threats Considered

| Threat | Likelihood | Impact | Mitigation |
|--------|------------|--------|------------|
| Token replay | High | High | Nonce binding, short lifetime |
| Token theft | Medium | High | KB-JWT proves possession |
| DNS spoofing | Low | Critical | DNSSEC (when available) |
| Issuer compromise | Low | Critical | DNS binding, multiple issuers |
| Key compromise | Low | Critical | Key rotation support |

#### Out of Scope

- Browser vulnerabilities (trust browser security model)
- Email provider trustworthiness (trust model assumption)
- Network-level attacks (assume TLS everywhere)

### Cryptographic Choices

| Component | Algorithm | Notes |
|-----------|-----------|-------|
| Signing | EdDSA/ECDSA/RSA | Per issuer configuration |
| Hashing | SHA-256 | For sd_hash in KB-JWT |
| Key Exchange | N/A | No encryption needed |

**No encryption because:**
- Tokens don't contain secrets
- Email addresses are provided by user anyway
- TLS handles transport security

## Performance Considerations

### Verification Latency Budget

| Operation | Time | Notes |
|-----------|------|-------|
| DNS lookup | 50-200ms | Cacheable |
| Metadata fetch | 50-200ms | Cacheable |
| JWKS fetch | 50-200ms | Cached by jose |
| Parse token | <1ms | CPU only |
| Verify SD-JWT | 1-5ms | Crypto operation |
| Verify KB-JWT | 1-5ms | Crypto operation |
| **Total (cold)** | **150-600ms** | |
| **Total (warm)** | **50-100ms** | With caching |

### Bundle Size Budget

| Package | Target | Notes |
|---------|--------|-------|
| @aspect-evp/core | <2KB | Types + utils only |
| @aspect-evp/issuer | <5KB | + jose imports |
| @aspect-evp/verifier | <5KB | + jose imports |
| jose (shared) | ~8KB | Tree-shaken |
| **Total** | **<15KB** | gzipped |

### Memory Usage

- No persistent state in libraries
- JWKS cached by jose (configurable)
- DNS cache optional, user-provided

## Compatibility Matrix

### Runtime Support

| Runtime | @aspect-evp/core | @aspect-evp/issuer | @aspect-evp/verifier |
|---------|-----------|-------------|---------------|
| Node.js 18+ | ✅ | ✅ | ✅ |
| Node.js 16-17 | ✅ | ✅ | ✅ (DoH only) |
| Deno | ✅ | ✅ | ✅ |
| Bun | ✅ | ✅ | ✅ |
| Cloudflare Workers | ✅ | ✅ | ✅ |
| Browser (future) | ✅ | ❌ | ✅ |

### TypeScript Support

- Minimum TypeScript: 4.7+
- Full type inference
- Strict mode compatible
- No `any` types in public API

## Future Considerations

### Planned Features

1. **Multi-key support for issuers**
   - Array of keys in config
   - Automatic key selection
   - Rotation without downtime

2. **Observability hooks**
   - Event emitters for metrics
   - OpenTelemetry integration
   - Audit logging

3. **Passkey authentication (per spec roadmap)**
   - WebAuthn challenge in issuance
   - No cookies needed
   - Works on shared computers

### Breaking Change Policy

Pre-1.0:
- Minor version bumps may include breaking changes
- Changelog will clearly document
- Migration guides provided

Post-1.0:
- Semantic versioning strictly followed
- Breaking changes only in major versions
- Deprecation warnings before removal

## Contributing Guidelines

### Code Style

- Use Biome for formatting/linting
- No default exports
- Explicit return types on public functions
- JSDoc comments on all public APIs

### Testing Requirements

- Unit tests for all public functions
- Integration tests for flows
- 90%+ coverage target
- Test in multiple runtimes

### PR Process

1. Create issue first for significant changes
2. Fork and create feature branch
3. Write tests before implementation
4. Update documentation
5. Submit PR with description

---

This architecture is designed to evolve with the EVP specification. As browsers implement support and email providers adopt the protocol, we'll adapt these libraries accordingly.
