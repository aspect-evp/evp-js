import { describe, expect, it } from 'vitest';
import { EVPError } from '../src/errors.js';
import {
  base64url,
  base64urlDecode,
  decodeJWTHeader,
  decodeJWTPayload,
  getCurrentTimestamp,
  getEmailDomain,
  isTimestampValid,
  isValidEmail,
  parseSDJWTKB,
  sha256,
} from '../src/utils.js';

describe('parseSDJWTKB', () => {
  // Create a mock SD-JWT+KB token
  // Format: header.payload.signature~kb-header.kb-payload.kb-signature
  const mockHeader = base64url(new TextEncoder().encode('{"alg":"EdDSA"}'));
  const mockPayload = base64url(new TextEncoder().encode('{"iss":"test"}'));
  const mockSignature = 'mock-signature';
  const mockSdJwt = `${mockHeader}.${mockPayload}.${mockSignature}`;

  const mockKbHeader = base64url(new TextEncoder().encode('{"typ":"kb+jwt"}'));
  const mockKbPayload = base64url(new TextEncoder().encode('{"aud":"https://rp.com"}'));
  const mockKbSignature = 'kb-signature';
  const mockKbJwt = `${mockKbHeader}.${mockKbPayload}.${mockKbSignature}`;

  it('should parse SD-JWT with KB-JWT', () => {
    const token = `${mockSdJwt}~${mockKbJwt}`;
    const result = parseSDJWTKB(token);

    expect(result.sdJwt).toBe(`${mockSdJwt}~`);
    expect(result.kbJwt).toBe(mockKbJwt);
    expect(result.sdJwtForHash).toBe(`${mockSdJwt}~`);
  });

  it('should parse SD-JWT without KB-JWT', () => {
    const token = `${mockSdJwt}~`;
    const result = parseSDJWTKB(token);

    expect(result.sdJwt).toBe(`${mockSdJwt}~`);
    expect(result.kbJwt).toBeNull();
    expect(result.sdJwtForHash).toBe(`${mockSdJwt}~`);
  });

  it('should throw for empty string', () => {
    expect(() => parseSDJWTKB('')).toThrow(EVPError);
    expect(() => parseSDJWTKB('')).toThrow('Token must be a non-empty string');
  });

  it('should throw for missing ~ delimiter', () => {
    expect(() => parseSDJWTKB(mockSdJwt)).toThrow(EVPError);
    expect(() => parseSDJWTKB(mockSdJwt)).toThrow('missing ~ delimiter');
  });

  it('should throw for invalid SD-JWT structure', () => {
    expect(() => parseSDJWTKB('invalid~')).toThrow(EVPError);
    expect(() => parseSDJWTKB('invalid~')).toThrow('header.payload.signature');
  });

  it('should throw for invalid KB-JWT structure', () => {
    expect(() => parseSDJWTKB(`${mockSdJwt}~invalid`)).toThrow(EVPError);
    expect(() => parseSDJWTKB(`${mockSdJwt}~invalid`)).toThrow('KB-JWT');
  });

  it('should throw for null input', () => {
    expect(() => parseSDJWTKB(null as unknown as string)).toThrow(EVPError);
  });
});

describe('getEmailDomain', () => {
  it('should extract domain from simple email', () => {
    expect(getEmailDomain('user@gmail.com')).toBe('gmail.com');
  });

  it('should extract domain from subdomain email', () => {
    expect(getEmailDomain('admin@mail.company.co.uk')).toBe('mail.company.co.uk');
  });

  it('should lowercase the domain', () => {
    expect(getEmailDomain('user@GMAIL.COM')).toBe('gmail.com');
  });

  it('should handle plus addressing', () => {
    expect(getEmailDomain('user+tag@example.com')).toBe('example.com');
  });

  it('should throw for empty string', () => {
    expect(() => getEmailDomain('')).toThrow(EVPError);
    expect(() => getEmailDomain('')).toThrow('non-empty string');
  });

  it('should throw for email without @', () => {
    expect(() => getEmailDomain('invalid')).toThrow(EVPError);
    expect(() => getEmailDomain('invalid')).toThrow('Invalid email format');
  });

  it('should throw for email starting with @', () => {
    expect(() => getEmailDomain('@example.com')).toThrow(EVPError);
  });

  it('should throw for email ending with @', () => {
    expect(() => getEmailDomain('user@')).toThrow(EVPError);
  });

  it('should reject whitespace in the domain', () => {
    expect(() => getEmailDomain('user@example .com')).toThrow('Invalid email domain');
  });

  it('should throw for null input', () => {
    expect(() => getEmailDomain(null as unknown as string)).toThrow(EVPError);
  });
});

describe('isValidEmail', () => {
  it('should return true for valid simple email', () => {
    expect(isValidEmail('user@example.com')).toBe(true);
  });

  it('should return true for email with subdomain', () => {
    expect(isValidEmail('user@mail.example.com')).toBe(true);
  });

  it('should return true for email with plus addressing', () => {
    expect(isValidEmail('user+tag@example.com')).toBe(true);
  });

  it('should return true for email with dots in local part', () => {
    expect(isValidEmail('first.last@example.com')).toBe(true);
  });

  it('should return false for empty string', () => {
    expect(isValidEmail('')).toBe(false);
  });

  it('should return false for email without @', () => {
    expect(isValidEmail('invalid')).toBe(false);
  });

  it('should return false for email without domain', () => {
    expect(isValidEmail('user@')).toBe(false);
  });

  it('should return false for email without TLD', () => {
    expect(isValidEmail('user@example')).toBe(false);
  });

  it('should return false for email with spaces', () => {
    expect(isValidEmail('user @example.com')).toBe(false);
  });

  it('should return false for null', () => {
    expect(isValidEmail(null as unknown as string)).toBe(false);
  });

  it('should return false for undefined', () => {
    expect(isValidEmail(undefined as unknown as string)).toBe(false);
  });
});

describe('sha256', () => {
  it('should hash string correctly', async () => {
    // Known SHA-256 hash of "hello world" in base64url
    const result = await sha256('hello world');
    expect(result).toBe('uU0nuZNNPgilLlLX2n2r-sSE7-N6U4DukIj3rOLvzek');
  });

  it('should hash empty string', async () => {
    const result = await sha256('');
    // SHA-256 of empty string
    expect(result).toBe('47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU');
  });

  it('should produce different hashes for different inputs', async () => {
    const hash1 = await sha256('hello');
    const hash2 = await sha256('world');
    expect(hash1).not.toBe(hash2);
  });

  it('should produce same hash for same input', async () => {
    const hash1 = await sha256('test');
    const hash2 = await sha256('test');
    expect(hash1).toBe(hash2);
  });
});

describe('base64url', () => {
  it('should encode simple data', () => {
    const data = new Uint8Array([1, 2, 3]);
    const result = base64url(data);
    expect(result).toBe('AQID');
  });

  it('should not include padding', () => {
    const data = new Uint8Array([1]);
    const result = base64url(data);
    expect(result).not.toContain('=');
  });

  it('should use URL-safe characters', () => {
    // This byte sequence would produce + and / in standard base64
    const data = new Uint8Array([251, 255]);
    const result = base64url(data);
    expect(result).not.toContain('+');
    expect(result).not.toContain('/');
  });

  it('should encode empty array', () => {
    const data = new Uint8Array([]);
    const result = base64url(data);
    expect(result).toBe('');
  });
});

describe('base64urlDecode', () => {
  it('should decode simple data', () => {
    const result = base64urlDecode('AQID');
    expect(Array.from(result)).toEqual([1, 2, 3]);
  });

  it('should handle missing padding', () => {
    const result = base64urlDecode('AQ');
    expect(Array.from(result)).toEqual([1]);
  });

  it('should handle URL-safe characters', () => {
    // Encode then decode should round-trip
    const original = new Uint8Array([251, 255]);
    const encoded = base64url(original);
    const decoded = base64urlDecode(encoded);
    expect(Array.from(decoded)).toEqual(Array.from(original));
  });

  it('should decode empty string', () => {
    const result = base64urlDecode('');
    expect(result.length).toBe(0);
  });
});

describe('base64url round-trip', () => {
  it('should encode and decode correctly', () => {
    const original = new Uint8Array([0, 128, 255, 1, 2, 3, 4, 5]);
    const encoded = base64url(original);
    const decoded = base64urlDecode(encoded);
    expect(Array.from(decoded)).toEqual(Array.from(original));
  });
});

describe('decodeJWTPayload', () => {
  it('should decode valid JSON payload', () => {
    const payload = { iss: 'test', email: 'user@example.com' };
    const encoded = base64url(new TextEncoder().encode(JSON.stringify(payload)));
    const result = decodeJWTPayload<{ iss: string; email: string }>(encoded);
    expect(result).toEqual(payload);
  });

  it('should throw for invalid base64', () => {
    expect(() => decodeJWTPayload('!!invalid!!')).toThrow(EVPError);
    expect(() => decodeJWTPayload('!!invalid!!')).toThrow('Failed to decode JWT payload');
  });

  it('should throw for invalid JSON', () => {
    const encoded = base64url(new TextEncoder().encode('not json'));
    expect(() => decodeJWTPayload(encoded)).toThrow(EVPError);
  });
});

describe('decodeJWTHeader', () => {
  it('should decode valid JSON header', () => {
    const header = { alg: 'EdDSA', typ: 'JWT' };
    const encoded = base64url(new TextEncoder().encode(JSON.stringify(header)));
    const result = decodeJWTHeader<{ alg: string; typ: string }>(encoded);
    expect(result).toEqual(header);
  });

  it('should throw for invalid header', () => {
    expect(() => decodeJWTHeader('!!invalid!!')).toThrow(EVPError);
    expect(() => decodeJWTHeader('!!invalid!!')).toThrow('Failed to decode JWT header');
  });
});

describe('getCurrentTimestamp', () => {
  it('should return current time in seconds', () => {
    const before = Math.floor(Date.now() / 1000);
    const result = getCurrentTimestamp();
    const after = Math.floor(Date.now() / 1000);

    expect(result).toBeGreaterThanOrEqual(before);
    expect(result).toBeLessThanOrEqual(after);
  });

  it('should return integer', () => {
    const result = getCurrentTimestamp();
    expect(Number.isInteger(result)).toBe(true);
  });
});

describe('isTimestampValid', () => {
  it('should return true for current timestamp', () => {
    const now = getCurrentTimestamp();
    expect(isTimestampValid(now)).toBe(true);
  });

  it('should return true for timestamp within tolerance', () => {
    const now = getCurrentTimestamp();
    expect(isTimestampValid(now - 30, 60)).toBe(true);
    expect(isTimestampValid(now + 30, 60)).toBe(true);
  });

  it('should return false for timestamp outside tolerance', () => {
    const now = getCurrentTimestamp();
    expect(isTimestampValid(now - 120, 60)).toBe(false);
    expect(isTimestampValid(now + 120, 60)).toBe(false);
  });

  it('should use default tolerance of 60 seconds', () => {
    const now = getCurrentTimestamp();
    expect(isTimestampValid(now - 59)).toBe(true);
    expect(isTimestampValid(now - 61)).toBe(false);
  });

  it('should respect custom tolerance', () => {
    const now = getCurrentTimestamp();
    expect(isTimestampValid(now - 100, 120)).toBe(true);
    expect(isTimestampValid(now - 100, 60)).toBe(false);
  });
});
