<!-- generated-by: gsd-doc-writer -->
# Getting started

This guide gets a contributor from a clean machine to a verified EVP test flow.

## Prerequisites

- Node.js `>=20.0.0`.
- pnpm `9.x`; the workspace declares `pnpm@9.0.0`.
- Git.

No environment variables, external DNS records, or browser implementation are required for the local test flow.

## Install the workspace

1. Clone and enter the repository.

   ```bash
   git clone https://github.com/aspect-evp/evp-js.git
   cd evp-js
   ```

2. Install the locked dependency graph.

   ```bash
   pnpm install --frozen-lockfile
   ```

3. Build every package.

   ```bash
   pnpm build
   ```

## First verification

Run the test suite and its coverage gate:

```bash
pnpm test
pnpm test:coverage
```

The coverage command must report 100% for statements, branches, functions, and lines across the executable core, issuer, and verifier modules.

To exercise a simulated end-to-end flow from the CLI package during development:

```bash
pnpm --filter @aspect-evp/cli dev test --email user@example.com
```

The simulation uses generated keys, mock DNS, mock metadata, and mock JWKS; it does not contact a real issuer.

## Common setup issues

### pnpm reports an unsupported Node.js version

Check `node --version`. Upgrade to Node.js 20 or newer, remove no lockfile, and rerun `pnpm install --frozen-lockfile`.

### Workspace packages resolve stale build output

Run `pnpm build` before executing package binaries. The test runner aliases workspace package names directly to their TypeScript entry points, so unit tests always exercise the current source.

### Web Crypto APIs are unavailable

The libraries require modern Web Crypto plus `Request`, `Response`, `fetch`, `atob`, and `btoa`. Node.js 20 supplies these APIs.

## Next steps

- Read the [protocol flow](PROTOCOL-FLOW.md).
- Follow the [issuer](issuer.md) or [verifier](verifier.md) guide.
- See [testing](TESTING.md) before changing protocol behavior.
- See [development](DEVELOPMENT.md) before opening a pull request.
