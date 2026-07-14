import { describe, expect, it } from 'vitest';
import { EVPError, getErrorMessage, isEVPError, toEVPError } from '../src/errors.js';

describe('EVPError', () => {
  describe('constructor', () => {
    it('should create error with code only', () => {
      const error = new EVPError('invalid_token');
      expect(error.code).toBe('invalid_token');
      expect(error.description).toBeUndefined();
      expect(error.message).toBe('invalid_token');
      expect(error.name).toBe('EVPError');
    });

    it('should create error with code and description', () => {
      const error = new EVPError('invalid_request', 'Missing required field');
      expect(error.code).toBe('invalid_request');
      expect(error.description).toBe('Missing required field');
      expect(error.message).toBe('invalid_request: Missing required field');
    });

    it('should be an instance of Error', () => {
      const error = new EVPError('server_error');
      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(EVPError);
    });

    it('should work when V8 stack capture is unavailable', () => {
      const original = Error.captureStackTrace;
      Object.defineProperty(Error, 'captureStackTrace', {
        configurable: true,
        value: undefined,
      });
      try {
        expect(new EVPError('invalid_request')).toBeInstanceOf(Error);
      } finally {
        Object.defineProperty(Error, 'captureStackTrace', {
          configurable: true,
          value: original,
        });
      }
    });

    it('should support all error codes', () => {
      const codes = [
        'invalid_request',
        'invalid_token',
        'invalid_signature',
        'authentication_required',
        'private_email_not_supported',
        'invalid_directed_email',
        'server_error',
      ] as const;
      for (const code of codes) {
        const error = new EVPError(code);
        expect(error.code).toBe(code);
      }
    });
  });

  describe('toJSON', () => {
    it('should return object with error code only when no description', () => {
      const error = new EVPError('invalid_token');
      const json = error.toJSON();
      expect(json).toEqual({ error: 'invalid_token' });
      expect(json.error_description).toBeUndefined();
    });

    it('should return object with error code and description', () => {
      const error = new EVPError('invalid_request', 'Token expired');
      const json = error.toJSON();
      expect(json).toEqual({
        error: 'invalid_request',
        error_description: 'Token expired',
      });
    });

    it('should be JSON serializable', () => {
      const error = new EVPError('server_error', 'Internal error');
      const jsonString = JSON.stringify(error.toJSON());
      const parsed = JSON.parse(jsonString);
      expect(parsed.error).toBe('server_error');
      expect(parsed.error_description).toBe('Internal error');
    });
  });

  describe('getHttpStatus', () => {
    it('should return 401 for authentication_required', () => {
      const error = new EVPError('authentication_required');
      expect(error.getHttpStatus()).toBe(401);
    });

    it('should return 400 for invalid_request', () => {
      const error = new EVPError('invalid_request');
      expect(error.getHttpStatus()).toBe(400);
    });

    it('should return 400 for invalid_token', () => {
      const error = new EVPError('invalid_token');
      expect(error.getHttpStatus()).toBe(400);
    });

    it.each([
      'invalid_signature',
      'private_email_not_supported',
      'invalid_directed_email',
    ] as const)('should return 400 for %s', (code) => {
      expect(new EVPError(code).getHttpStatus()).toBe(400);
    });

    it('should return 500 for server_error', () => {
      const error = new EVPError('server_error');
      expect(error.getHttpStatus()).toBe(500);
    });

    it('should fail closed for an unknown runtime error code', () => {
      const error = new EVPError('future_error' as never);
      expect(error.getHttpStatus()).toBe(400);
    });
  });
});

describe('getErrorMessage', () => {
  it('normalizes Error and non-Error values', () => {
    expect(getErrorMessage(new Error('failure'))).toBe('failure');
    expect(getErrorMessage('failure')).toBe('failure');
  });
});

describe('isEVPError', () => {
  it('should return true for EVPError instances', () => {
    const error = new EVPError('invalid_token');
    expect(isEVPError(error)).toBe(true);
  });

  it('should return false for regular Error instances', () => {
    const error = new Error('test');
    expect(isEVPError(error)).toBe(false);
  });

  it('should return false for null', () => {
    expect(isEVPError(null)).toBe(false);
  });

  it('should return false for undefined', () => {
    expect(isEVPError(undefined)).toBe(false);
  });

  it('should return false for plain objects', () => {
    const obj = { code: 'invalid_token', message: 'test' };
    expect(isEVPError(obj)).toBe(false);
  });

  it('should return false for strings', () => {
    expect(isEVPError('invalid_token')).toBe(false);
  });
});

describe('toEVPError', () => {
  it('should return same EVPError if already EVPError', () => {
    const original = new EVPError('invalid_token', 'test');
    const result = toEVPError(original);
    expect(result).toBe(original);
  });

  it('should wrap regular Error in EVPError', () => {
    const original = new Error('Something went wrong');
    const result = toEVPError(original);
    expect(result).toBeInstanceOf(EVPError);
    expect(result.code).toBe('server_error');
    expect(result.description).toBe('Something went wrong');
  });

  it('should wrap string in EVPError', () => {
    const result = toEVPError('Something went wrong');
    expect(result).toBeInstanceOf(EVPError);
    expect(result.code).toBe('server_error');
    expect(result.description).toBe('Something went wrong');
  });

  it('should wrap number in EVPError', () => {
    const result = toEVPError(42);
    expect(result).toBeInstanceOf(EVPError);
    expect(result.code).toBe('server_error');
    expect(result.description).toBe('42');
  });

  it('should wrap null in EVPError', () => {
    const result = toEVPError(null);
    expect(result).toBeInstanceOf(EVPError);
    expect(result.code).toBe('server_error');
    expect(result.description).toBe('null');
  });
});
