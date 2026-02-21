import { URL } from 'url';
import { lookup } from 'dns/promises';
import { logger } from './logger';
import {
  validateUrlSync,
  SecurityMode,
  CLOUD_METADATA,
  LOCALHOST_PATTERNS,
  PRIVATE_IP_RANGES
} from './url-validator-sync';

// Re-export types and function for backward compatibility
export { SecurityMode, validateUrlSync };

export class SSRFProtection {
  /**
   * Re-export synchronous validation for convenience
   */
  static validateUrlSync = validateUrlSync;

  /**
   * Validate webhook URL for SSRF protection with configurable security modes
   *
   * @param urlString - URL to validate
   * @returns Promise with validation result
   *
   * @security Uses DNS resolution to prevent DNS rebinding attacks
   *
   * @example
   * // Production (default strict mode)
   * const result = await SSRFProtection.validateWebhookUrl('http://localhost:5678');
   * // { valid: false, reason: 'Localhost not allowed' }
   *
   * @example
   * // Local development (moderate mode)
   * process.env.WEBHOOK_SECURITY_MODE = 'moderate';
   * const result = await SSRFProtection.validateWebhookUrl('http://localhost:5678');
   * // { valid: true }
   */
  static async validateWebhookUrl(urlString: string): Promise<{
    valid: boolean;
    reason?: string
  }> {
    try {
      const url = new URL(urlString);
      const mode: SecurityMode = (process.env.WEBHOOK_SECURITY_MODE || 'strict') as SecurityMode;

      // Step 1: Must be HTTP/HTTPS (all modes)
      if (!['http:', 'https:'].includes(url.protocol)) {
        return { valid: false, reason: 'Invalid protocol. Only HTTP/HTTPS allowed.' };
      }

      // Get hostname and strip IPv6 brackets if present
      let hostname = url.hostname.toLowerCase();
      // Remove IPv6 brackets for consistent comparison
      if (hostname.startsWith('[') && hostname.endsWith(']')) {
        hostname = hostname.slice(1, -1);
      }

      // Step 2: ALWAYS block cloud metadata endpoints (all modes)
      if (CLOUD_METADATA.has(hostname)) {
        logger.warn('SSRF blocked: Cloud metadata endpoint', { hostname, mode });
        return { valid: false, reason: 'Cloud metadata endpoint blocked' };
      }

      // Step 3: Resolve DNS to get actual IP address
      // This prevents DNS rebinding attacks where hostname resolves to different IPs
      let resolvedIP: string;
      try {
        const { address } = await lookup(hostname);
        resolvedIP = address;

        logger.debug('DNS resolved for SSRF check', { hostname, resolvedIP, mode });
      } catch (error) {
        logger.warn('DNS resolution failed for webhook URL', {
          hostname,
          error: error instanceof Error ? error.message : String(error)
        });
        return { valid: false, reason: 'DNS resolution failed' };
      }

      // Step 4: ALWAYS block cloud metadata IPs (all modes)
      if (CLOUD_METADATA.has(resolvedIP)) {
        logger.warn('SSRF blocked: Hostname resolves to cloud metadata IP', {
          hostname,
          resolvedIP,
          mode
        });
        return { valid: false, reason: 'Hostname resolves to cloud metadata endpoint' };
      }

      // Step 5: Mode-specific validation

      // MODE: permissive - Allow everything except cloud metadata
      if (mode === 'permissive') {
        logger.warn('SSRF protection in permissive mode (localhost and private IPs allowed)', {
          hostname,
          resolvedIP
        });
        return { valid: true };
      }

      // Check if target is localhost
      const isLocalhost = LOCALHOST_PATTERNS.has(hostname) ||
                        resolvedIP === '::1' ||
                        resolvedIP.startsWith('127.');

      // MODE: strict - Block localhost and private IPs
      if (mode === 'strict' && isLocalhost) {
        logger.warn('SSRF blocked: Localhost not allowed in strict mode', {
          hostname,
          resolvedIP
        });
        return { valid: false, reason: 'Localhost access is blocked in strict mode' };
      }

      // MODE: moderate - Allow localhost, block private IPs
      if (mode === 'moderate' && isLocalhost) {
        logger.info('Localhost webhook allowed (moderate mode)', { hostname, resolvedIP });
        return { valid: true };
      }

      // Step 6: Check private IPv4 ranges (strict & moderate modes)
      if (PRIVATE_IP_RANGES.some(regex => regex.test(resolvedIP))) {
        logger.warn('SSRF blocked: Private IP address', { hostname, resolvedIP, mode });
        return {
          valid: false,
          reason: mode === 'strict'
            ? 'Private IP addresses not allowed'
            : 'Private IP addresses not allowed (use WEBHOOK_SECURITY_MODE=permissive if needed)'
        };
      }

      // Step 7: IPv6 private address check (strict & moderate modes)
      if (resolvedIP === '::1' ||         // Loopback
          resolvedIP === '::' ||          // Unspecified address
          resolvedIP.startsWith('fe80:') || // Link-local
          resolvedIP.startsWith('fc00:') || // Unique local (fc00::/7)
          resolvedIP.startsWith('fd00:') || // Unique local (fd00::/8)
          resolvedIP.startsWith('::ffff:')) { // IPv4-mapped IPv6
        logger.warn('SSRF blocked: IPv6 private address', {
          hostname,
          resolvedIP,
          mode
        });
        return { valid: false, reason: 'IPv6 private address not allowed' };
      }

      return { valid: true };
    } catch (error) {
      return { valid: false, reason: 'Invalid URL format' };
    }
  }
}
