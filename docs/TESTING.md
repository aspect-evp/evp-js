<!-- generated-by: gsd-doc-writer -->
# Testing

## Framework and setup

The repository uses Vitest 4 with the V8 coverage provider. Install dependencies once with `pnpm install`; tests require Node.js 20 or newer and no external services.

`vitest.config.ts` aliases workspace package names to their live TypeScript entry points. This prevents tests from accidentally exercising stale `dist/` output.

## Running tests

Full suite:

```bash
pnpm test
```

Coverage gate and HTML/JSON reports:

```bash
pnpm test:coverage
```

Watch mode:

```bash
pnpm test:watch
```

One test file or matching test name:

```bash
pnpm exec vitest run packages/verifier/tests/verifier.test.ts
pnpm exec vitest run -t "rejects invalid signed token claims"
```

## Coverage requirements

| Metric | Threshold |
|---|---:|
| Statements | 100% |
| Branches | 100% |
| Functions | 100% |
| Lines | 100% |

The measured scope is executable production-library code in core, issuer, and verifier. Type-only modules, barrel files, dedicated test fixtures, and the interactive CLI are explicitly excluded because they do not represent the protocol library runtime scope.

Do not add coverage ignores to hide reachable behavior. Remove genuinely unreachable branches, or write a dependency-boundary test when a branch represents a third-party failure contract.

## Writing tests

- Place tests in the package's `tests/` directory using `*.test.ts`.
- Assert the observable success result and the exact failure class or stable message fragment.
- Cover both valid protocol flows and malformed attacker-controlled input.
- Use real Web Crypto keys for signature interoperability tests.
- Use isolated `vi.mock()` files only for dependency results that cannot be produced through a real valid key.
- Restore fake timers, global stubs, and console spies in the test that creates them.

The `@aspect-evp/core/testing` export provides `createTestFlow()`, `generateNonce()`, `MockDnsResolver`, and `createMockResolver()` for consumer integration tests.

## Security-critical cases

At minimum, protocol changes must retain tests for:

- HTTP Message Signature component and cookie binding;
- stale timestamps and unsupported keys;
- malformed JSON and mutually exclusive issuance options;
- issuer/DNS mismatch and invalid metadata URLs;
- JWKS rotation and expired-cache behavior;
- EVT and KB-JWT signatures, audience, nonce, timestamps, and `sd_hash`;
- private key removal from published JWKS and `cnf.jwk`.

## CI integration

`.github/workflows/ci.yml` runs on pushes and pull requests targeting `main` with Node.js 20 and 22. Both matrix jobs build, lint, validate documentation links, type-check, and test. The Node.js 20 job also runs `pnpm test:coverage`. A dependent publish-check job builds and packs every workspace package.

Documentation validation can also be run locally:

```bash
pnpm docs:check
```
