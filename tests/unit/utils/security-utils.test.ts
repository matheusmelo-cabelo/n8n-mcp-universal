
import { describe, it, expect } from 'vitest';
import { sanitizeHeaders } from '../../../src/utils/security-utils';

describe('sanitizeHeaders', () => {
  it('should return null if headers are null', () => {
    expect(sanitizeHeaders(null)).toBeNull();
  });

  it('should return undefined if headers are undefined', () => {
    expect(sanitizeHeaders(undefined)).toBeUndefined();
  });

  it('should redact Authorization header', () => {
    const headers = {
      'Authorization': 'Bearer secret-token',
      'Content-Type': 'application/json'
    };
    const sanitized = sanitizeHeaders(headers);
    expect(sanitized['Authorization']).toBe('***REDACTED***');
    expect(sanitized['Content-Type']).toBe('application/json');
  });

  it('should redact x-n8n-key header', () => {
    const headers = {
      'x-n8n-key': 'secret-key',
      'User-Agent': 'n8n-client'
    };
    const sanitized = sanitizeHeaders(headers);
    expect(sanitized['x-n8n-key']).toBe('***REDACTED***');
    expect(sanitized['User-Agent']).toBe('n8n-client');
  });

  it('should be case-insensitive for header keys', () => {
    const headers = {
      'authorization': 'Bearer secret',
      'X-N8N-KEY': 'secret-key',
      'Cookie': 'session=123'
    };
    const sanitized = sanitizeHeaders(headers);
    expect(sanitized['authorization']).toBe('***REDACTED***');
    expect(sanitized['X-N8N-KEY']).toBe('***REDACTED***');
    expect(sanitized['Cookie']).toBe('***REDACTED***');
  });

  it('should handle cookie and set-cookie headers', () => {
    const headers = {
      'cookie': 'session=123',
      'set-cookie': 'session=456; Path=/',
      'Accept': 'application/json'
    };
    const sanitized = sanitizeHeaders(headers);
    expect(sanitized['cookie']).toBe('***REDACTED***');
    expect(sanitized['set-cookie']).toBe('***REDACTED***');
    expect(sanitized['Accept']).toBe('application/json');
  });

  it('should not mutate the original headers object', () => {
    const headers = {
      'Authorization': 'Bearer secret'
    };
    const sanitized = sanitizeHeaders(headers);
    expect(sanitized['Authorization']).toBe('***REDACTED***');
    expect(headers['Authorization']).toBe('Bearer secret');
  });
});
