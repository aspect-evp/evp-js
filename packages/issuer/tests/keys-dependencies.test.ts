import { beforeEach, describe, expect, it, vi } from 'vitest';

const joseGenerateKeyPair = vi.hoisted(() => vi.fn());

vi.mock('jose', async (importOriginal) => ({
  ...(await importOriginal<typeof import('jose')>()),
  generateKeyPair: joseGenerateKeyPair,
}));

import { generateKeyPair } from '../src/keys.js';

describe('key generation dependency boundary', () => {
  beforeEach(() => {
    joseGenerateKeyPair.mockReset();
  });

  it('normalizes key generation failures', async () => {
    joseGenerateKeyPair.mockRejectedValueOnce(new Error('entropy source unavailable'));
    await expect(generateKeyPair('EdDSA')).rejects.toThrow(
      'Failed to generate keypair: entropy source unavailable'
    );
  });
});
