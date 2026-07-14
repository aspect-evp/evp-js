import { EVPError, WELL_KNOWN_PATH } from '@aspect-evp/core';
import { exportJWK, generateKeyPair } from 'jose';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  clearJWKSCache,
  createJWKSFetcher,
  fetchIssuerMetadata,
  getIssuerJWKS,
} from '../src/jwks.js';

describe('fetchIssuerMetadata', () => {
  const mockFetch = vi.fn();

  beforeEach(() => {
    mockFetch.mockReset();
  });

  it('should fetch and return valid metadata', async () => {
    const metadata = {
      issuance_endpoint: 'https://issuer.example.com/issuance',
      jwks_uri: 'https://issuer.example.com/jwks',
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => metadata,
    });

    const result = await fetchIssuerMetadata('https://issuer.example.com', mockFetch);

    expect(result).toEqual(metadata);
    expect(mockFetch).toHaveBeenCalledWith(
      `https://issuer.example.com${WELL_KNOWN_PATH}`,
      expect.objectContaining({
        headers: { Accept: 'application/json' },
      })
    );
  });

  it('should strip trailing slash from origin', async () => {
    const metadata = {
      issuance_endpoint: 'https://issuer.example.com/issuance',
      jwks_uri: 'https://issuer.example.com/jwks',
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => metadata,
    });

    await fetchIssuerMetadata('https://issuer.example.com/', mockFetch);

    expect(mockFetch).toHaveBeenCalledWith(
      `https://issuer.example.com${WELL_KNOWN_PATH}`,
      expect.any(Object)
    );
  });

  it('should throw EVPError on HTTP error', async () => {
    mockFetch.mockResolvedValue({
      ok: false,
      status: 404,
    });

    await expect(fetchIssuerMetadata('https://issuer.example.com', mockFetch)).rejects.toThrow(
      EVPError
    );

    await expect(fetchIssuerMetadata('https://issuer.example.com', mockFetch)).rejects.toThrow(
      'HTTP 404'
    );
  });

  it('should throw EVPError if issuance_endpoint is missing', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        jwks_uri: 'https://issuer.example.com/jwks',
      }),
    });

    await expect(fetchIssuerMetadata('https://issuer.example.com', mockFetch)).rejects.toThrow(
      'missing issuance_endpoint'
    );
  });

  it('should throw EVPError if jwks_uri is missing', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        issuance_endpoint: 'https://issuer.example.com/issuance',
      }),
    });

    await expect(fetchIssuerMetadata('https://issuer.example.com', mockFetch)).rejects.toThrow(
      'missing jwks_uri'
    );
  });

  it('should throw EVPError on network error', async () => {
    mockFetch.mockRejectedValue(new Error('Network error'));

    await expect(fetchIssuerMetadata('https://issuer.example.com', mockFetch)).rejects.toThrow(
      EVPError
    );

    mockFetch.mockRejectedValue(new Error('Network error'));
    await expect(fetchIssuerMetadata('https://issuer.example.com', mockFetch)).rejects.toThrow(
      'Network error'
    );
  });

  it('should reject non-HTTPS endpoint metadata', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        issuance_endpoint: 'https://issuer.example.com/issuance',
        jwks_uri: 'http://issuer.example.com/jwks',
      }),
    });
    await expect(fetchIssuerMetadata('https://issuer.example.com', mockFetch)).rejects.toThrow(
      'must use HTTPS'
    );
  });

  it('should reject malformed and credential-bearing metadata URLs', async () => {
    for (const jwks_uri of ['not a URL', 'https://user:pass@issuer.example.com/jwks']) {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          issuance_endpoint: 'https://issuer.example.com/issuance',
          jwks_uri,
        }),
      });
      await expect(fetchIssuerMetadata('https://issuer.example.com', mockFetch)).rejects.toThrow(
        'Invalid issuer metadata'
      );
    }
  });

  it('should reject unsupported signing algorithms', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        issuance_endpoint: 'https://issuer.example.com/issuance',
        jwks_uri: 'https://issuer.example.com/jwks',
        signing_alg_values_supported: ['none'],
      }),
    });
    await expect(fetchIssuerMetadata('https://issuer.example.com', mockFetch)).rejects.toThrow(
      'unsupported signing algorithm'
    );
  });

  it('should reject an empty signing algorithm list', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        issuance_endpoint: 'https://issuer.example.com/issuance',
        jwks_uri: 'https://issuer.example.com/jwks',
        signing_alg_values_supported: [],
      }),
    });
    await expect(fetchIssuerMetadata('https://issuer.example.com', mockFetch)).rejects.toThrow(
      'unsupported signing algorithm'
    );
  });

  it('normalizes non-Error fetch failures', async () => {
    mockFetch.mockRejectedValueOnce('offline');
    await expect(fetchIssuerMetadata('https://issuer.example.com', mockFetch)).rejects.toThrow(
      'offline'
    );
  });

  it('should re-throw EVPError as-is', async () => {
    mockFetch.mockImplementationOnce(() => {
      throw new EVPError('invalid_request', 'Custom error');
    });

    await expect(fetchIssuerMetadata('https://issuer.example.com', mockFetch)).rejects.toThrow(
      'Custom error'
    );
  });
});

describe('createJWKSFetcher', () => {
  beforeEach(() => {
    clearJWKSCache();
  });

  it('should create a fetcher with custom fetch function', async () => {
    const mockFetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        keys: [
          {
            kty: 'OKP',
            crv: 'Ed25519',
            x: 'test-public-key',
          },
        ],
      }),
    });

    const fetcher = createJWKSFetcher('https://issuer.example.com/jwks', {
      fetch: mockFetch,
    });

    expect(fetcher).toBeInstanceOf(Function);

    // The fetch is lazy - it won't be called until the fetcher is used
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('should throw EVPError on JWKS fetch failure with custom fetch', async () => {
    const mockFetch = vi.fn().mockResolvedValueOnce({
      ok: false,
      status: 500,
    });

    const fetcher = createJWKSFetcher('https://issuer.example.com/jwks', {
      fetch: mockFetch,
    });

    // When the fetcher is called, it should throw
    await expect(
      fetcher({ alg: 'EdDSA' }, { payload: '', protectedHeader: { alg: 'EdDSA' }, signature: '' })
    ).rejects.toThrow('Failed to fetch JWKS');
  });

  it.each([
    {},
    { keys: [] },
    { keys: 'invalid' },
  ])('should reject malformed JWKS documents', async (document) => {
    const mockFetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: async () => document,
    });
    const fetcher = createJWKSFetcher('https://issuer.example.com/jwks', {
      fetch: mockFetch,
    });
    await expect(
      fetcher({ alg: 'EdDSA' }, { payload: '', protectedHeader: { alg: 'EdDSA' }, signature: '' })
    ).rejects.toThrow('keys must be a non-empty array');
  });

  it('should cache JWKS fetchers', () => {
    const fetcher1 = createJWKSFetcher('https://issuer.example.com/jwks');
    const fetcher2 = createJWKSFetcher('https://issuer.example.com/jwks');

    expect(fetcher1).toBe(fetcher2); // Same instance from cache
  });

  it('should create different fetchers for different URIs', () => {
    const fetcher1 = createJWKSFetcher('https://issuer1.example.com/jwks');
    const fetcher2 = createJWKSFetcher('https://issuer2.example.com/jwks');

    expect(fetcher1).not.toBe(fetcher2);
  });

  it('should refresh immediately when a new kid appears', async () => {
    const firstPair = await generateKeyPair('EdDSA', { extractable: true });
    const secondPair = await generateKeyPair('EdDSA', { extractable: true });
    const first = { ...(await exportJWK(firstPair.publicKey)), kid: 'key-1', alg: 'EdDSA' };
    const second = { ...(await exportJWK(secondPair.publicKey)), kid: 'key-2', alg: 'EdDSA' };
    const mockFetch = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ keys: [first] }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ keys: [second] }) });
    const fetcher = createJWKSFetcher('https://issuer.example.com/jwks', {
      fetch: mockFetch,
      cacheTtl: 60000,
    });
    await expect(
      fetcher(
        { alg: 'EdDSA', kid: 'key-2' },
        { payload: '', protectedHeader: { alg: 'EdDSA', kid: 'key-2' }, signature: '' }
      )
    ).resolves.toBeDefined();
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('should reuse a valid local JWKS before its TTL expires', async () => {
    const pair = await generateKeyPair('EdDSA', { extractable: true });
    const key = { ...(await exportJWK(pair.publicKey)), kid: 'key-1', alg: 'EdDSA' };
    const mockFetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ keys: [key] }) });
    const fetcher = createJWKSFetcher('https://issuer.example.com/jwks', {
      fetch: mockFetch,
      cacheTtl: 60000,
    });
    const token = {
      payload: '',
      protectedHeader: { alg: 'EdDSA', kid: 'key-1' },
      signature: '',
    };
    await fetcher({ alg: 'EdDSA', kid: 'key-1' }, token);
    await fetcher({ alg: 'EdDSA', kid: 'key-1' }, token);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('should preserve lookup errors after an already-expired refresh', async () => {
    const pair = await generateKeyPair('EdDSA', { extractable: true });
    const key = { ...(await exportJWK(pair.publicKey)), kid: 'known', alg: 'EdDSA' };
    const mockFetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ keys: [key] }) });
    const fetcher = createJWKSFetcher('https://issuer.example.com/jwks', {
      fetch: mockFetch,
      cacheTtl: 0,
    });
    await expect(
      fetcher(
        { alg: 'EdDSA', kid: 'unknown' },
        { payload: '', protectedHeader: { alg: 'EdDSA', kid: 'unknown' }, signature: '' }
      )
    ).rejects.toThrow();
  });

  it('should reject a malformed JWKS URI before creating a fetcher', () => {
    expect(() => createJWKSFetcher('not a URL')).toThrow('is not a URL');
  });
});

describe('clearJWKSCache', () => {
  it('should clear cached fetchers', () => {
    const fetcher1 = createJWKSFetcher('https://issuer.example.com/jwks');
    clearJWKSCache();
    const fetcher2 = createJWKSFetcher('https://issuer.example.com/jwks');

    expect(fetcher1).not.toBe(fetcher2); // Different instances after cache clear
  });
});

describe('getIssuerJWKS', () => {
  const mockFetch = vi.fn();

  beforeEach(() => {
    mockFetch.mockReset();
    clearJWKSCache();
  });

  it('should fetch metadata and create JWKS fetcher', async () => {
    const metadata = {
      issuance_endpoint: 'https://issuer.example.com/issuance',
      jwks_uri: 'https://issuer.example.com/jwks',
    };

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => metadata,
    });

    const result = await getIssuerJWKS('https://issuer.example.com', mockFetch);

    expect(result.metadata).toEqual(metadata);
    expect(result.getKey).toBeInstanceOf(Function);
  });
});
