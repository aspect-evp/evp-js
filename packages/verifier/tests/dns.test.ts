import { EVPError } from '@aspect-evp/core';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createCachingResolver, defaultDnsResolver, resolveIssuer } from '../src/dns.js';

// Mock fetch for defaultDnsResolver tests
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

describe('defaultDnsResolver', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it('should return issuer from DNS-over-HTTPS response', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        Answer: [{ type: 16, data: '"iss=accounts.google.com"' }],
      }),
    });

    const result = await defaultDnsResolver('gmail.com');
    expect(result).toBe('accounts.google.com');
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('_email-verification.gmail.com'),
      expect.objectContaining({
        headers: { Accept: 'application/dns-json' },
      })
    );
  });

  it('should return issuer without quotes', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        Answer: [{ type: 16, data: 'iss=issuer.example.com' }],
      }),
    });

    const result = await defaultDnsResolver('example.com');
    expect(result).toBe('issuer.example.com');
  });

  it('should return null if response is not ok', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
    });

    const result = await defaultDnsResolver('example.com');
    expect(result).toBeNull();
  });

  it('should return null if no Answer in response', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({}),
    });

    const result = await defaultDnsResolver('example.com');
    expect(result).toBeNull();
  });

  it('should return null if Answer is empty', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ Answer: [] }),
    });

    const result = await defaultDnsResolver('example.com');
    expect(result).toBeNull();
  });

  it('should return null if no TXT record (type 16)', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        Answer: [{ type: 1, data: '192.168.1.1' }], // A record, not TXT
      }),
    });

    const result = await defaultDnsResolver('example.com');
    expect(result).toBeNull();
  });

  it('should return null if TXT record does not contain iss=', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        Answer: [{ type: 16, data: '"v=spf1 include:example.com"' }],
      }),
    });

    const result = await defaultDnsResolver('example.com');
    expect(result).toBeNull();
  });

  it('should return null on fetch error', async () => {
    mockFetch.mockRejectedValueOnce(new Error('Network error'));

    const result = await defaultDnsResolver('example.com');
    expect(result).toBeNull();
  });

  it('should find issuer among multiple TXT records', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        Answer: [
          { type: 16, data: '"v=spf1 include:example.com"' },
          { type: 16, data: '"iss=issuer.example.com"' },
          { type: 16, data: '"google-site-verification=abc123"' },
        ],
      }),
    });

    const result = await defaultDnsResolver('example.com');
    expect(result).toBe('issuer.example.com');
  });

  it('should reject multiple EVP issuer records', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        Answer: [
          { type: 16, data: '"iss=issuer-one.example.com"' },
          { type: 16, data: '"iss=issuer-two.example.com"' },
        ],
      }),
    });
    await expect(defaultDnsResolver('example.com')).resolves.toBeNull();
  });

  it('should reject issuer values that are not hostnames', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ Answer: [{ type: 16, data: '"iss=evil.example/path"' }] }),
    });
    await expect(defaultDnsResolver('example.com')).resolves.toBeNull();
  });

  it.each([
    '%',
    'issuer.example.com:443',
    'user@issuer.example.com',
  ])('should reject malformed issuer hostname %s', async (issuer) => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ Answer: [{ type: 16, data: `"iss=${issuer}"` }] }),
    });
    await expect(defaultDnsResolver('example.com')).resolves.toBeNull();
  });
});

describe('nodeDnsResolver', () => {
  it('should return issuer from DNS TXT record', async () => {
    // Mock the dynamic import
    vi.doMock('node:dns/promises', () => ({
      resolveTxt: vi.fn().mockResolvedValue([['iss=issuer.example.com']]),
    }));

    // Force re-import to use mock
    vi.resetModules();
    const { nodeDnsResolver: freshResolver } = await import('../src/dns.js');

    const result = await freshResolver('example.com');
    expect(result).toBe('issuer.example.com');

    vi.doUnmock('node:dns/promises');
  });

  it('should return null on DNS error', async () => {
    vi.doMock('node:dns/promises', () => ({
      resolveTxt: vi.fn().mockRejectedValue(new Error('ENOTFOUND')),
    }));

    vi.resetModules();
    const { nodeDnsResolver: freshResolver } = await import('../src/dns.js');

    const result = await freshResolver('nonexistent.com');
    expect(result).toBeNull();

    vi.doUnmock('node:dns/promises');
  });

  it('should join split TXT records', async () => {
    vi.doMock('node:dns/promises', () => ({
      resolveTxt: vi.fn().mockResolvedValue([['iss=', 'issuer.example.com']]),
    }));

    vi.resetModules();
    const { nodeDnsResolver: freshResolver } = await import('../src/dns.js');

    const result = await freshResolver('example.com');
    expect(result).toBe('issuer.example.com');

    vi.doUnmock('node:dns/promises');
  });

  it('should return null if no iss= record found', async () => {
    vi.doMock('node:dns/promises', () => ({
      resolveTxt: vi.fn().mockResolvedValue([['v=spf1 include:example.com']]),
    }));

    vi.resetModules();
    const { nodeDnsResolver: freshResolver } = await import('../src/dns.js');

    const result = await freshResolver('example.com');
    expect(result).toBeNull();

    vi.doUnmock('node:dns/promises');
  });

  it('should reject multiple issuer records from native DNS', async () => {
    vi.doMock('node:dns/promises', () => ({
      resolveTxt: vi.fn().mockResolvedValue([['iss=one.example.com'], ['iss=two.example.com']]),
    }));
    vi.resetModules();
    const { nodeDnsResolver: freshResolver } = await import('../src/dns.js');
    await expect(freshResolver('example.com')).resolves.toBeNull();
    vi.doUnmock('node:dns/promises');
  });
});

describe('createCachingResolver', () => {
  it('should cache results', async () => {
    const mockResolver = vi.fn(async () => 'issuer.example.com');
    const cachedResolver = createCachingResolver(mockResolver, 60000);

    // First call
    const result1 = await cachedResolver('example.com');
    expect(result1).toBe('issuer.example.com');
    expect(mockResolver).toHaveBeenCalledTimes(1);

    // Second call should use cache
    const result2 = await cachedResolver('example.com');
    expect(result2).toBe('issuer.example.com');
    expect(mockResolver).toHaveBeenCalledTimes(1); // Still 1, used cache
  });

  it('should cache null results', async () => {
    const mockResolver = vi.fn(async () => null);
    const cachedResolver = createCachingResolver(mockResolver, 60000);

    const result1 = await cachedResolver('unknown.com');
    expect(result1).toBeNull();
    expect(mockResolver).toHaveBeenCalledTimes(1);

    const result2 = await cachedResolver('unknown.com');
    expect(result2).toBeNull();
    expect(mockResolver).toHaveBeenCalledTimes(1); // Still 1
  });

  it('should refresh after TTL expires', async () => {
    vi.useFakeTimers();

    const mockResolver = vi.fn(async () => 'issuer.example.com');
    const cachedResolver = createCachingResolver(mockResolver, 1000); // 1 second TTL

    // First call
    await cachedResolver('example.com');
    expect(mockResolver).toHaveBeenCalledTimes(1);

    // Advance time past TTL
    vi.advanceTimersByTime(1001);

    // Should call resolver again
    await cachedResolver('example.com');
    expect(mockResolver).toHaveBeenCalledTimes(2);

    vi.useRealTimers();
  });

  it('should cache different domains separately', async () => {
    const mockResolver = vi.fn(async (domain: string) => `issuer.${domain}`);
    const cachedResolver = createCachingResolver(mockResolver, 60000);

    await cachedResolver('example.com');
    await cachedResolver('test.com');

    expect(mockResolver).toHaveBeenCalledTimes(2);
    expect(mockResolver).toHaveBeenCalledWith('example.com');
    expect(mockResolver).toHaveBeenCalledWith('test.com');
  });

  it('should use default TTL of 5 minutes', async () => {
    vi.useFakeTimers();

    const mockResolver = vi.fn(async () => 'issuer.example.com');
    const cachedResolver = createCachingResolver(mockResolver); // Default TTL

    await cachedResolver('example.com');
    expect(mockResolver).toHaveBeenCalledTimes(1);

    // Advance 4 minutes - should still use cache
    vi.advanceTimersByTime(4 * 60 * 1000);
    await cachedResolver('example.com');
    expect(mockResolver).toHaveBeenCalledTimes(1);

    // Advance past 5 minutes total
    vi.advanceTimersByTime(2 * 60 * 1000);
    await cachedResolver('example.com');
    expect(mockResolver).toHaveBeenCalledTimes(2);

    vi.useRealTimers();
  });
});

describe('resolveIssuer', () => {
  it('should return issuer from resolver', async () => {
    const mockResolver = vi.fn(async () => 'issuer.example.com');
    const result = await resolveIssuer('example.com', mockResolver);
    expect(result).toBe('issuer.example.com');
  });

  it('should throw EVPError if no issuer found', async () => {
    const mockResolver = vi.fn(async () => null);
    await expect(resolveIssuer('unknown.com', mockResolver)).rejects.toThrow(EVPError);
    await expect(resolveIssuer('unknown.com', mockResolver)).rejects.toThrow('No EVP issuer found');
  });

  it('should include domain in error message', async () => {
    const mockResolver = vi.fn(async () => null);
    try {
      await resolveIssuer('specific-domain.com', mockResolver);
    } catch (error) {
      expect(error).toBeInstanceOf(EVPError);
      expect((error as EVPError).message).toContain('specific-domain.com');
    }
  });
});
