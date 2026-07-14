import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getCurrentTimestamp } from '../src/utils.js';

const importJWK = vi.hoisted(() => vi.fn());

vi.mock('jose', async (importOriginal) => ({
  ...(await importOriginal<typeof import('jose')>()),
  importJWK,
}));

import { createSignedIssuanceRequest, verifyHttpMessageSignature } from '../src/http-signatures.js';

describe('HTTP signature dependency boundaries', () => {
  beforeEach(() => {
    importJWK.mockReset().mockResolvedValue(new Uint8Array());
  });

  it('rejects a non-asymmetric signing key returned by jose', async () => {
    await expect(
      createSignedIssuanceRequest(
        'https://issuer.example/issuance',
        {},
        { kty: 'OKP', crv: 'Ed25519', x: 'AA', d: 'AA' }
      )
    ).rejects.toThrow('HTTP signature key is not asymmetric');
  });

  it('rejects a non-asymmetric verification key returned by jose', async () => {
    const created = getCurrentTimestamp();
    const request = new Request('https://issuer.example/issuance', {
      method: 'POST',
      headers: {
        Signature: 'sig=:AAAA:',
        'Signature-Input': `sig=("@method" "@authority" "@path" "signature-key");created=${created}`,
        'Signature-Key': 'sig=hwk; kty="OKP"; crv="Ed25519"; x="AA"',
      },
    });
    await expect(verifyHttpMessageSignature(request)).rejects.toThrow(
      'HTTP signature key is not asymmetric'
    );
  });
});
