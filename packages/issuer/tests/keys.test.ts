import { EVPError } from '@evp/core';
import { describe, expect, it } from 'vitest';
import { generateKeyPair, getCurveForAlgorithm, isAlgorithmSupported } from '../src/keys.js';

describe('generateKeyPair', () => {
  it('should generate EdDSA keypair by default', async () => {
    const { privateKey, publicKey } = await generateKeyPair();

    expect(privateKey.kty).toBe('OKP');
    expect(privateKey.crv).toBe('Ed25519');
    expect(privateKey.alg).toBe('EdDSA');
    expect(privateKey.d).toBeDefined(); // Private key component

    expect(publicKey.kty).toBe('OKP');
    expect(publicKey.crv).toBe('Ed25519');
    expect(publicKey.alg).toBe('EdDSA');
    expect(publicKey.d).toBeUndefined(); // No private key component
  });

  it('should generate ES256 keypair', async () => {
    const { privateKey, publicKey } = await generateKeyPair('ES256');

    expect(privateKey.kty).toBe('EC');
    expect(privateKey.crv).toBe('P-256');
    expect(privateKey.alg).toBe('ES256');
    expect(privateKey.d).toBeDefined();

    expect(publicKey.kty).toBe('EC');
    expect(publicKey.crv).toBe('P-256');
    expect(publicKey.alg).toBe('ES256');
    expect(publicKey.d).toBeUndefined();
  });

  it('should generate ES384 keypair', async () => {
    const { privateKey, publicKey } = await generateKeyPair('ES384');

    expect(privateKey.kty).toBe('EC');
    expect(privateKey.crv).toBe('P-384');
    expect(privateKey.alg).toBe('ES384');

    expect(publicKey.kty).toBe('EC');
    expect(publicKey.crv).toBe('P-384');
    expect(publicKey.alg).toBe('ES384');
  });

  it('should generate RS256 keypair', async () => {
    const { privateKey, publicKey } = await generateKeyPair('RS256');

    expect(privateKey.kty).toBe('RSA');
    expect(privateKey.alg).toBe('RS256');
    expect(privateKey.d).toBeDefined();

    expect(publicKey.kty).toBe('RSA');
    expect(publicKey.alg).toBe('RS256');
    expect(publicKey.d).toBeUndefined();
  });

  it('should throw for unsupported algorithm', async () => {
    await expect(generateKeyPair('INVALID' as 'EdDSA')).rejects.toThrow(EVPError);
    await expect(generateKeyPair('INVALID' as 'EdDSA')).rejects.toThrow('Unsupported algorithm');
  });
});

describe('isAlgorithmSupported', () => {
  it('should return true for supported algorithms', () => {
    expect(isAlgorithmSupported('EdDSA')).toBe(true);
    expect(isAlgorithmSupported('ES256')).toBe(true);
    expect(isAlgorithmSupported('ES384')).toBe(true);
    expect(isAlgorithmSupported('RS256')).toBe(true);
  });

  it('should return false for unsupported algorithms', () => {
    expect(isAlgorithmSupported('HS256')).toBe(false);
    expect(isAlgorithmSupported('RS512')).toBe(false);
    expect(isAlgorithmSupported('INVALID')).toBe(false);
    expect(isAlgorithmSupported('')).toBe(false);
  });
});

describe('getCurveForAlgorithm', () => {
  it('should return Ed25519 for EdDSA', () => {
    expect(getCurveForAlgorithm('EdDSA')).toBe('Ed25519');
  });

  it('should return P-256 for ES256', () => {
    expect(getCurveForAlgorithm('ES256')).toBe('P-256');
  });

  it('should return P-384 for ES384', () => {
    expect(getCurveForAlgorithm('ES384')).toBe('P-384');
  });

  it('should return undefined for RS256', () => {
    expect(getCurveForAlgorithm('RS256')).toBeUndefined();
  });
});
