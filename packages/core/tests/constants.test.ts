import { describe, expect, it } from 'vitest';
import {
  DEFAULT_ALGORITHM,
  DEFAULT_CLOCK_TOLERANCE,
  DNS_RECORD_PREFIX,
  KB_JWT_TYPE,
  SD_JWT_TYPE,
  SUPPORTED_ALGORITHMS,
  WELL_KNOWN_PATH,
} from '../src/constants.js';

describe('constants', () => {
  describe('DEFAULT_ALGORITHM', () => {
    it('should be EdDSA', () => {
      expect(DEFAULT_ALGORITHM).toBe('EdDSA');
    });
  });

  describe('DEFAULT_CLOCK_TOLERANCE', () => {
    it('should be 60 seconds', () => {
      expect(DEFAULT_CLOCK_TOLERANCE).toBe(60);
    });
  });

  describe('DNS_RECORD_PREFIX', () => {
    it('should be _email-verification', () => {
      expect(DNS_RECORD_PREFIX).toBe('_email-verification');
    });
  });

  describe('WELL_KNOWN_PATH', () => {
    it('should be /.well-known/email-verification', () => {
      expect(WELL_KNOWN_PATH).toBe('/.well-known/email-verification');
    });
  });

  describe('SD_JWT_TYPE', () => {
    it('should be evp+sd-jwt', () => {
      expect(SD_JWT_TYPE).toBe('evp+sd-jwt');
    });
  });

  describe('KB_JWT_TYPE', () => {
    it('should be kb+jwt', () => {
      expect(KB_JWT_TYPE).toBe('kb+jwt');
    });
  });

  describe('SUPPORTED_ALGORITHMS', () => {
    it('should include EdDSA', () => {
      expect(SUPPORTED_ALGORITHMS).toContain('EdDSA');
    });

    it('should include ES256', () => {
      expect(SUPPORTED_ALGORITHMS).toContain('ES256');
    });

    it('should include ES384', () => {
      expect(SUPPORTED_ALGORITHMS).toContain('ES384');
    });

    it('should include RS256', () => {
      expect(SUPPORTED_ALGORITHMS).toContain('RS256');
    });

    it('should have 4 algorithms', () => {
      expect(SUPPORTED_ALGORITHMS).toHaveLength(4);
    });

    it('should be a readonly array', () => {
      expect(Array.isArray(SUPPORTED_ALGORITHMS)).toBe(true);
    });
  });
});
