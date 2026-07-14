<!-- generated-by: gsd-doc-writer -->
# Development

## Local setup

Fork the repository, clone your fork, and install dependencies with pnpm 9 on Node.js 20 or newer.

```bash
git clone https://github.com/<your-account>/evp-js.git
cd evp-js
pnpm install
pnpm build
```

The project has no `.env` setup. Keep test and production private keys out of the repository.

## Build and quality commands

| Command | Description |
|---|---|
| `pnpm build` | Compile every workspace package with TypeScript. |
| `pnpm test` | Run all Vitest tests once. |
| `pnpm test:watch` | Run Vitest in watch mode. |
| `pnpm test:coverage` | Run the suite with the enforced 100% production-library coverage gate. |
| `pnpm docs:check` | Validate every local Markdown link and anchor. |
| `pnpm lint` | Check the repository with Biome. |
| `pnpm lint:fix` | Apply safe Biome lint fixes. |
| `pnpm format` | Format the repository with Biome. |
| `pnpm typecheck` | Type-check all packages without emitting output. |
| `pnpm clean` | Remove package build output and root dependencies. |
| `pnpm changeset` | Create release metadata for a user-visible package change. |
| `pnpm version` | Apply pending changesets to package versions and changelogs. |
| `pnpm release` | Build, test, and publish packages through Changesets. |

Run the package CLI from source with:

```bash
pnpm --filter @aspect-evp/cli dev --help
```

## Code style

Biome is configured in `biome.json`. TypeScript uses strict compiler settings from `tsconfig.json`.

- Two-space indentation and a 100-character line width.
- Single quotes and semicolons in JavaScript/TypeScript.
- No unused imports or variables.
- Public behavior changes require tests and documentation.

Before requesting review, run:

```bash
pnpm format
pnpm lint
pnpm docs:check
pnpm typecheck
pnpm test:coverage
pnpm build
```

## Test organization

Tests live under `packages/<package>/tests/` and use the `*.test.ts` suffix. Dependency-boundary tests use isolated Vitest module mocks to exercise failures that real cryptographic providers do not normally return. See [Testing](TESTING.md).

## Branch and commit conventions

Use a short descriptive branch such as `feat/http-signatures` or `fix/jwks-rotation`. Existing contribution guidance uses conventional-style commit subjects such as `feat(verifier): ...`, `fix(issuer): ...`, and `test(core): ...`.

## Pull request process

1. Keep the change focused and include a changeset for publishable behavior changes.
2. Add or update tests for every reachable branch and failure mode.
3. Update the root, package, or wiki documentation when public behavior changes.
4. Run all local quality commands listed above.
5. Open a PR against `main` and explain protocol compatibility and security impact.

GitHub CI runs build, lint, typecheck, tests, and coverage on Node.js 20 and 22. It also packs every package after the build to verify publish contents.
