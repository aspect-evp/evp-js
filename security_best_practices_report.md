# Security dependency review

## Executive summary

The previous lockfile contained 14 npm advisories represented by 12 open Dependabot alerts: 1 critical, 5 high, 7 moderate, and 1 low. All affected packages were reachable only through root development tooling (`vitest`, `vite`, and `@changesets/cli`). The remediated lockfile now reports zero known vulnerabilities in both the complete and production-only audits.

The dependency set has been repaired and automated audit gates now protect CI and releases from future high or critical advisories. Vitest UI and development servers should still never be exposed to untrusted networks.

The repository is a TypeScript library/CLI monorepo rather than an Express, Next.js, React, Vue, or browser application, so the available framework-specific security references do not directly apply. This report therefore uses npm advisory data and the actual dependency graph as its primary evidence.

## Critical

### SEC-001 — Vulnerable direct Vitest dependency

**Impact:** A remotely reachable Vitest UI server could allow an attacker to read and execute arbitrary local files.

- Previous version: Vitest `4.0.18`.
- Advisory: `GHSA-5xrq-8626-4rwp`.
- Affected range: `>=4.0.0 <4.1.0`.
- Resolution: `vitest` and `@vitest/coverage-v8` were updated together to `4.1.10` in `package.json:44-47` and the lockfile was regenerated.

## High

### SEC-002 — Vulnerable Vite development-server chain

- Previous versions: Vite `7.3.1` and Picomatch `4.0.3`.
- Advisories included arbitrary file reads through the WebSocket, `server.fs.deny` bypasses, Windows alternate-path disclosure, and Picomatch ReDoS.
- Resolution: Vite is explicitly resolved to `7.3.6` and Picomatch 4.x to `4.0.5` through the direct dependency and bounded overrides in `package.json:46-57`.
- Operational safeguard: never run Vitest UI or Vite with a public `--host`, and do not expose their ports outside the developer machine or isolated CI runner.

### SEC-003 — Legacy Picomatch through Changesets

- Previous version: Picomatch `2.3.1` through the `@manypkg/get-packages`/`micromatch` chain.
- Advisories: method injection in POSIX character classes and extglob ReDoS.
- Resolution: `@changesets/cli` was updated to `2.31.0` and a narrowly scoped override resolves Picomatch 2.x to `2.3.2` without crossing a major-version boundary.

## Moderate and low

### SEC-004 — Vulnerable PostCSS and esbuild through Vite

- Previous versions: PostCSS `8.5.8` and esbuild `0.27.3`.
- Risks: CSS stringification XSS and Windows development-server arbitrary file read.
- Resolution: the regenerated lockfile selects PostCSS `8.5.19` and esbuild `0.28.1`.

### SEC-005 — Vulnerable js-yaml through Changesets

- Previous versions: js-yaml `3.14.2` and `4.1.1` through separate transitive paths.
- Risk: quadratic-complexity denial of service while parsing crafted YAML merge aliases.
- Resolution: bounded overrides select js-yaml `3.15.0` and `4.3.0` for their respective major lines.

## Applied remediation

1. Updated `vitest` and `@vitest/coverage-v8` together to `4.1.10`.
2. Updated `@changesets/cli` to `2.31.0`.
3. Regenerated the lockfile with Vite `7.3.6`, PostCSS `8.5.19`, Picomatch 4.x `4.0.5`, and esbuild `0.28.1`.
4. Added narrowly scoped overrides for Picomatch 2.x `2.3.2` and the two vulnerable js-yaml release lines.
5. Added `pnpm audit --audit-level=high` to CI and Release, plus a production-only audit command.

## Verification snapshot

- Previous full audit: 14 advisories — 1 critical, 5 high, 7 moderate, 1 low.
- Current full audit: 0 known vulnerabilities.
- Current production-only audit: 0 known vulnerabilities across 9 runtime dependencies.
- Directly shipped packages are not affected by these dependency advisories.
- CI and Release now fail on newly reported high or critical advisories.
