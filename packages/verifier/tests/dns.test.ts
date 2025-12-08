import { EVPError } from '@evp/core';
import { describe, expect, it, vi } from 'vitest';
import { createCachingResolver, resolveIssuer } from '../src/dns.js';

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
});
