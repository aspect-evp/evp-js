import { EVPError, getCurrentTimestamp, WELL_KNOWN_PATH } from '@aspect-evp/core';
import { importJWK, SignJWT } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { EmailVerificationIssuer } from '../src/issuer.js';
import { generateKeyPair } from '../src/keys.js';

describe('EmailVerificationIssuer', () => {
  let issuerKeyPair: { privateKey: JsonWebKey; publicKey: JsonWebKey };
  let browserKeyPair: { privateKey: JsonWebKey; publicKey: JsonWebKey };

  beforeAll(async () => {
    issuerKeyPair = await generateKeyPair('EdDSA');
    browserKeyPair = await generateKeyPair('EdDSA');
  });

  describe('constructor', () => {
    it('should create issuer with valid config', () => {
      const issuer = new EmailVerificationIssuer({
        issuer: 'mail.example.com',
        privateKey: issuerKeyPair.privateKey,
        kid: 'test-key-1',
      });

      expect(issuer).toBeInstanceOf(EmailVerificationIssuer);
    });

    it('should throw for missing issuer', () => {
      expect(
        () =>
          new EmailVerificationIssuer({
            issuer: '',
            privateKey: issuerKeyPair.privateKey,
            kid: 'test-key',
          })
      ).toThrow(EVPError);
    });

    it('should throw for missing privateKey', () => {
      expect(
        () =>
          new EmailVerificationIssuer({
            issuer: 'mail.example.com',
            privateKey: null as unknown as JsonWebKey,
            kid: 'test-key',
          })
      ).toThrow(EVPError);
    });

    it('should throw for missing kid', () => {
      expect(
        () =>
          new EmailVerificationIssuer({
            issuer: 'mail.example.com',
            privateKey: issuerKeyPair.privateKey,
            kid: '',
          })
      ).toThrow(EVPError);
    });

    it('should throw for unsupported algorithm', () => {
      expect(
        () =>
          new EmailVerificationIssuer({
            issuer: 'mail.example.com',
            privateKey: issuerKeyPair.privateKey,
            kid: 'test-key',
            algorithm: 'INVALID' as 'EdDSA',
          })
      ).toThrow(EVPError);
    });
  });

  describe('getMetadata', () => {
    it('should return valid metadata', () => {
      const issuer = new EmailVerificationIssuer({
        issuer: 'mail.example.com',
        privateKey: issuerKeyPair.privateKey,
        kid: 'test-key',
      });

      const metadata = issuer.getMetadata('https://accounts.example.com');

      expect(metadata.issuance_endpoint).toBe(
        'https://accounts.example.com/email-verification/issuance'
      );
      expect(metadata.jwks_uri).toBe('https://accounts.example.com/email-verification/jwks');
      expect(metadata.signing_alg_values_supported).toEqual(['EdDSA']);
    });

    it('should handle trailing slash in baseUrl', () => {
      const issuer = new EmailVerificationIssuer({
        issuer: 'mail.example.com',
        privateKey: issuerKeyPair.privateKey,
        kid: 'test-key',
      });

      const metadata = issuer.getMetadata('https://accounts.example.com/');

      expect(metadata.issuance_endpoint).toBe(
        'https://accounts.example.com/email-verification/issuance'
      );
    });
  });

  describe('getJWKS', () => {
    it('should return JWKS with public key', async () => {
      const issuer = new EmailVerificationIssuer({
        issuer: 'mail.example.com',
        privateKey: issuerKeyPair.privateKey,
        kid: 'test-key-2024',
      });

      const jwks = await issuer.getJWKS();

      expect(jwks.keys).toHaveLength(1);
      const key = jwks.keys[0];
      expect(key).toBeDefined();
      expect(key?.kid).toBe('test-key-2024');
      expect(key?.use).toBe('sig');
      expect(key?.alg).toBe('EdDSA');
      expect(key?.d).toBeUndefined(); // No private key
    });
  });

  describe('verifyRequestToken', () => {
    it('should verify valid request token', async () => {
      const issuer = new EmailVerificationIssuer({
        issuer: 'mail.example.com',
        privateKey: issuerKeyPair.privateKey,
        kid: 'test-key',
      });

      // Create a valid request token
      const browserPrivateKey = await importJWK(browserKeyPair.privateKey, 'EdDSA');
      const requestToken = await new SignJWT({
        aud: 'mail.example.com',
        iat: getCurrentTimestamp(),
        email: 'user@example.com',
      })
        .setProtectedHeader({
          alg: 'EdDSA',
          typ: 'JWT',
          jwk: browserKeyPair.publicKey,
        })
        .sign(browserPrivateKey);

      const result = await issuer.verifyRequestToken(requestToken);

      expect(result.payload.email).toBe('user@example.com');
      expect(result.payload.aud).toBe('mail.example.com');
      expect(result.browserPublicKey).toEqual(browserKeyPair.publicKey);
    });

    it('should reject empty token', async () => {
      const issuer = new EmailVerificationIssuer({
        issuer: 'mail.example.com',
        privateKey: issuerKeyPair.privateKey,
        kid: 'test-key',
      });

      await expect(issuer.verifyRequestToken('')).rejects.toThrow(EVPError);
    });

    it('should reject token with wrong audience', async () => {
      const issuer = new EmailVerificationIssuer({
        issuer: 'mail.example.com',
        privateKey: issuerKeyPair.privateKey,
        kid: 'test-key',
      });

      const browserPrivateKey = await importJWK(browserKeyPair.privateKey, 'EdDSA');
      const requestToken = await new SignJWT({
        aud: 'wrong-issuer.com',
        iat: getCurrentTimestamp(),
        email: 'user@example.com',
      })
        .setProtectedHeader({
          alg: 'EdDSA',
          typ: 'JWT',
          jwk: browserKeyPair.publicKey,
        })
        .sign(browserPrivateKey);

      await expect(issuer.verifyRequestToken(requestToken)).rejects.toThrow('Invalid audience');
    });

    it('should reject expired token', async () => {
      const issuer = new EmailVerificationIssuer({
        issuer: 'mail.example.com',
        privateKey: issuerKeyPair.privateKey,
        kid: 'test-key',
        clockTolerance: 60,
      });

      const browserPrivateKey = await importJWK(browserKeyPair.privateKey, 'EdDSA');
      const requestToken = await new SignJWT({
        aud: 'mail.example.com',
        iat: getCurrentTimestamp() - 120, // 2 minutes ago
        email: 'user@example.com',
      })
        .setProtectedHeader({
          alg: 'EdDSA',
          typ: 'JWT',
          jwk: browserKeyPair.publicKey,
        })
        .sign(browserPrivateKey);

      await expect(issuer.verifyRequestToken(requestToken)).rejects.toThrow(
        'timestamp is outside acceptable range'
      );
    });

    it('should reject token without email', async () => {
      const issuer = new EmailVerificationIssuer({
        issuer: 'mail.example.com',
        privateKey: issuerKeyPair.privateKey,
        kid: 'test-key',
      });

      const browserPrivateKey = await importJWK(browserKeyPair.privateKey, 'EdDSA');
      const requestToken = await new SignJWT({
        aud: 'mail.example.com',
        iat: getCurrentTimestamp(),
      })
        .setProtectedHeader({
          alg: 'EdDSA',
          typ: 'JWT',
          jwk: browserKeyPair.publicKey,
        })
        .sign(browserPrivateKey);

      await expect(issuer.verifyRequestToken(requestToken)).rejects.toThrow(
        'must include email claim'
      );
    });
  });

  describe('issueToken', () => {
    it('should issue valid SD-JWT', async () => {
      const issuer = new EmailVerificationIssuer({
        issuer: 'mail.example.com',
        privateKey: issuerKeyPair.privateKey,
        kid: 'test-key',
      });

      const token = await issuer.issueToken('user@example.com', browserKeyPair.publicKey);

      // Should end with ~ (SD-JWT format)
      expect(token).toMatch(/~$/);

      // Should be a valid JWT
      const parts = token.slice(0, -1).split('.'); // Remove trailing ~
      expect(parts).toHaveLength(3);
    });

    it('should reject empty email', async () => {
      const issuer = new EmailVerificationIssuer({
        issuer: 'mail.example.com',
        privateKey: issuerKeyPair.privateKey,
        kid: 'test-key',
      });

      await expect(issuer.issueToken('', browserKeyPair.publicKey)).rejects.toThrow(
        'Email is required'
      );
    });

    it('should reject missing browser public key', async () => {
      const issuer = new EmailVerificationIssuer({
        issuer: 'mail.example.com',
        privateKey: issuerKeyPair.privateKey,
        kid: 'test-key',
      });

      await expect(
        issuer.issueToken('user@example.com', null as unknown as JsonWebKey)
      ).rejects.toThrow('Browser public key is required');
    });
  });

  describe('static methods', () => {
    it('should return correct wellKnownPath', () => {
      expect(EmailVerificationIssuer.wellKnownPath).toBe(WELL_KNOWN_PATH);
    });

    it('should generate keypair', async () => {
      const { privateKey, publicKey } = await EmailVerificationIssuer.generateKeyPair();
      expect(privateKey.kty).toBe('OKP');
      expect(publicKey.kty).toBe('OKP');
    });
  });
});
