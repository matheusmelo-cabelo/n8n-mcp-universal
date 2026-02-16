import { describe, it, expect } from 'vitest';
import { sanitizeLogData } from '../../../src/utils/security-utils';

describe('sanitizeLogData', () => {
  it('should pass through null and undefined', () => {
    expect(sanitizeLogData(null)).toBeNull();
    expect(sanitizeLogData(undefined)).toBeUndefined();
  });

  it('should pass through simple primitives', () => {
    expect(sanitizeLogData(123)).toBe(123);
    expect(sanitizeLogData('hello')).toBe('hello');
    expect(sanitizeLogData(true)).toBe(true);
  });

  it('should redact sensitive keys in objects', () => {
    const input = {
      username: 'user1',
      password: 'mysecretpassword',
      apiKey: 'sk-1234567890abcdef123456', // Length > 20
    };
    const expected = {
      username: 'user1',
      password: '***REDACTED***',
      apiKey: 'sk-...456 (REDACTED)',
    };
    expect(sanitizeLogData(input)).toEqual(expected);
  });

  it('should redact sensitive keys in nested objects', () => {
    const input = {
      user: {
        name: 'John',
        // 'credentials' is a sensitive key, so the whole object is redacted
        credentials: {
          token: 'secret_token_value',
        },
        // 'data' is not sensitive, so we recurse
        data: {
          token: 'secret_token_value_longer_than_20_chars',
        }
      },
    };
    const expected = {
      user: {
        name: 'John',
        credentials: '***REDACTED***',
        data: {
          token: 'sec...ars (REDACTED)',
        }
      },
    };
    expect(sanitizeLogData(input)).toEqual(expected);
  });

  it('should redact sensitive keys in arrays of objects', () => {
    const input = [
      { id: 1, secret: 'hidden1' },
      { id: 2, secret: 'hidden2' },
    ];
    const expected = [
      { id: 1, secret: '***REDACTED***' },
      { id: 2, secret: '***REDACTED***' },
    ];
    expect(sanitizeLogData(input)).toEqual(expected);
  });

  it('should redact JSON strings containing sensitive data', () => {
    const input = JSON.stringify({
      apiKey: '1234567890abcdef1234567890',
      data: 'public',
    });
    // The function returns a stringified JSON of the sanitized object
    const result = sanitizeLogData(input);
    const parsed = JSON.parse(result);

    expect(parsed.apiKey).toBe('123...890 (REDACTED)');
    expect(parsed.data).toBe('public');
  });

  it('should handle case insensitive keys', () => {
    const input = {
      APIKEY: 'secret',
      PassWord: 'secret',
    };
    const expected = {
      APIKEY: '***REDACTED***',
      PassWord: '***REDACTED***',
    };
    expect(sanitizeLogData(input)).toEqual(expected);
  });

  it('should handle suffix matching', () => {
    const input = {
      google_api_key: 'secret_google_key_very_long', // Length > 20
      my_secret_token: 'secret_token_123', // Length < 20
    };
    const expected = {
      google_api_key: 'sec...ong (REDACTED)',
      my_secret_token: '***REDACTED***',
    };
    expect(sanitizeLogData(input)).toEqual(expected);
  });
});
