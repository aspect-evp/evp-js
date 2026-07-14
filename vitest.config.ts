import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      '@aspect-evp/core': fileURLToPath(new URL('./packages/core/src/index.ts', import.meta.url)),
      '@aspect-evp/issuer': fileURLToPath(
        new URL('./packages/issuer/src/index.ts', import.meta.url)
      ),
      '@aspect-evp/verifier': fileURLToPath(
        new URL('./packages/verifier/src/index.ts', import.meta.url)
      ),
    },
  },
  test: {
    globals: true,
    environment: 'node',
    include: ['packages/**/tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['packages/**/src/**/*.ts'],
      exclude: [
        'packages/**/src/**/index.ts',
        'packages/**/src/**/types.ts', // Type-only modules have no runtime behavior.
        'packages/**/src/testing/**',
        'packages/cli/**', // CLI is UI code, excluded from coverage
      ],
      thresholds: {
        lines: 100,
        functions: 100,
        branches: 100,
        statements: 100,
      },
    },
  },
});
