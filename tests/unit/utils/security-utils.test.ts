import { describe, it, expect } from 'vitest';
import { sanitizeHeaders, sanitizeBody } from '../../../src/utils/security-utils';

describe('Security Utils', () => {
  describe('sanitizeHeaders', () => {
    it('should redact sensitive headers', () => {
      const headers = {
        'content-type': 'application/json',
        'authorization': 'Bearer secret-token',
        'x-n8n-key': 'n8n-api-key',
        'cookie': 'session=123',
        'set-cookie': ['session=456'],
        'user-agent': 'n8n-mcp-client',
      };

      const sanitized = sanitizeHeaders(headers);

      expect(sanitized['content-type']).toBe('application/json');
      expect(sanitized['authorization']).toBe('[REDACTED]');
      expect(sanitized['x-n8n-key']).toBe('[REDACTED]');
      expect(sanitized['cookie']).toBe('[REDACTED]');
      expect(sanitized['set-cookie']).toBe('[REDACTED]');
      expect(sanitized['user-agent']).toBe('n8n-mcp-client');
    });

    it('should handle headers with different casing', () => {
      const headers: any = {
        'Authorization': 'Bearer secret',
        'X-API-Key': 'key',
      };

      const sanitized = sanitizeHeaders(headers);

      expect(sanitized['Authorization']).toBe('[REDACTED]');
      expect(sanitized['X-API-Key']).toBe('[REDACTED]');
    });
  });

  describe('sanitizeBody', () => {
    it('should redact sensitive keys in object', () => {
      const body = {
        username: 'admin',
        password: 'supersecretpassword',
        token: 'abcdef',
        apiKey: '12345',
        clientSecret: 'secret',
        apiSecret: 'secret2',
        nested: {
          privateKey: 'pk',
          publicInfo: 'visible',
        },
      };

      const sanitized = sanitizeBody(body);

      expect(sanitized.username).toBe('admin');
      expect(sanitized.password).toBe('[REDACTED]');
      expect(sanitized.token).toBe('[REDACTED]');
      expect(sanitized.apiKey).toBe('[REDACTED]');
      expect(sanitized.clientSecret).toBe('[REDACTED]');
      expect(sanitized.apiSecret).toBe('[REDACTED]');
      expect(sanitized.nested.privateKey).toBe('[REDACTED]');
      expect(sanitized.nested.publicInfo).toBe('visible');
    });

    it('should redact sensitive keys in array of objects', () => {
      const body = [
        { id: 1, secret: 's1' },
        { id: 2, accessToken: 't2' },
      ];

      const sanitized = sanitizeBody(body);

      expect(sanitized[0].id).toBe(1);
      expect(sanitized[0].secret).toBe('[REDACTED]');
      expect(sanitized[1].id).toBe(2);
      expect(sanitized[1].accessToken).toBe('[REDACTED]');
    });

    it('should handle regex matches correctly', () => {
        const body = {
            access_token: '123',
            my_private_key: 'key', // Should NOT be redacted if strict regex used, unless matches /private[-_]?key/i
            // /private[-_]?key/i matches "private_key" substring in "my_private_key"?
            // JS regex .test() finds substring by default unless anchored.
            // My patterns are NOT anchored unless specified.
            // So /private[-_]?key/i matches "my_private_key".
            nonSensitiveKey: 'safe' // strict match ^key$ used now
        };

        const sanitized = sanitizeBody(body);
        expect(sanitized.access_token).toBe('[REDACTED]');
        expect(sanitized.my_private_key).toBe('[REDACTED]');
        expect(sanitized.nonSensitiveKey).toBe('safe');
    });

    it('should NOT redact safe words that contain sensitive substrings if patterns are specific', () => {
       const body = {
           keyboard: 'typewriter',
           broken: 'glass',
           secretary: 'person',
           key_id: '123'
       };

       const sanitized = sanitizeBody(body);
       expect(sanitized.keyboard).toBe('typewriter');
       expect(sanitized.broken).toBe('glass');
       expect(sanitized.secretary).toBe('person');
       expect(sanitized.key_id).toBe('123'); // Should be safe now
    });
  });
});
