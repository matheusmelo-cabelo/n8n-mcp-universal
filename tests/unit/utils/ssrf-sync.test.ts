import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { validateUrlSync, SecurityMode } from '../../../src/utils/url-validator-sync';

/**
 * Unit tests for synchronous SSRF validation
 *
 * These tests verify the static analysis capabilities of validateUrlSync
 * which are used for initial configuration validation.
 */
describe('validateUrlSync', () => {
  // Test cloud metadata blocking (always blocked in all modes)
  describe('Cloud Metadata Protection (All Modes)', () => {
    const metadataUrls = [
      'http://169.254.169.254/latest/meta-data',
      'http://169.254.170.2/v2/metadata',
      'http://metadata.google.internal/computeMetadata/v1/',
      'http://100.100.100.200/latest/meta-data',
      'http://192.0.0.192/opc/v2/instance/'
    ];

    const modes: SecurityMode[] = ['strict', 'moderate', 'permissive'];

    modes.forEach(mode => {
      it(`should block cloud metadata in ${mode} mode`, () => {
        for (const url of metadataUrls) {
          const result = validateUrlSync(url, mode);
          expect(result.valid, `Failed to block ${url} in ${mode} mode`).toBe(false);
          expect(result.reason).toContain('Cloud metadata');
        }
      });
    });
  });

  // Test Strict Mode (Default)
  describe('Strict Mode', () => {
    it('should block localhost', () => {
      const urls = [
        'http://localhost:3000',
        'http://127.0.0.1:8080',
        'http://[::1]:5678'
      ];

      for (const url of urls) {
        const result = validateUrlSync(url, 'strict');
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('Localhost');
      }
    });

    it('should block private IPs (direct check)', () => {
      const urls = [
        'http://10.0.0.1/api',
        'http://192.168.1.100/config',
        'http://172.16.0.1/webhook'
      ];

      for (const url of urls) {
        const result = validateUrlSync(url, 'strict');
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('Private IP');
      }
    });

    it('should allow public domains', () => {
      const urls = [
        'https://api.n8n.io',
        'http://example.com'
      ];

      for (const url of urls) {
        const result = validateUrlSync(url, 'strict');
        expect(result.valid).toBe(true);
      }
    });
  });

  // Test Moderate Mode
  describe('Moderate Mode', () => {
    it('should allow localhost', () => {
      const urls = [
        'http://localhost:3000',
        'http://127.0.0.1:8080',
        'http://[::1]:5678'
      ];

      for (const url of urls) {
        const result = validateUrlSync(url, 'moderate');
        expect(result.valid).toBe(true);
      }
    });

    it('should block private IPs', () => {
      const urls = [
        'http://10.0.0.1/api',
        'http://192.168.1.100/config'
      ];

      for (const url of urls) {
        const result = validateUrlSync(url, 'moderate');
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('Private IP');
      }
    });
  });

  // Test Permissive Mode
  describe('Permissive Mode', () => {
    it('should allow localhost', () => {
      const result = validateUrlSync('http://localhost:3000', 'permissive');
      expect(result.valid).toBe(true);
    });

    it('should allow private IPs', () => {
      const result = validateUrlSync('http://192.168.1.100', 'permissive');
      expect(result.valid).toBe(true);
    });

    it('should still block cloud metadata', () => {
      const result = validateUrlSync('http://169.254.169.254', 'permissive');
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Cloud metadata');
    });
  });

  // Test Edge Cases
  describe('Edge Cases', () => {
    it('should handle invalid URLs gracefully', () => {
      const result = validateUrlSync('not-a-url');
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Invalid URL format');
    });

    it('should block non-HTTP protocols', () => {
      const urls = [
        'file:///etc/passwd',
        'ftp://example.com',
        'gopher://site'
      ];

      for (const url of urls) {
        const result = validateUrlSync(url);
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('protocol');
      }
    });

    it('should default to strict mode if not specified', () => {
      // Localhost should be blocked in strict (default)
      const result = validateUrlSync('http://localhost:3000');
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Localhost');
    });
  });
});
