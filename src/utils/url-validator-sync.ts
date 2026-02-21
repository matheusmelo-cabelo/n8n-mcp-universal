import { URL } from 'url';

/**
 * Security mode type
 */
export type SecurityMode = 'strict' | 'moderate' | 'permissive';

// Cloud metadata endpoints (ALWAYS blocked in all modes)
export const CLOUD_METADATA = new Set([
  // AWS/Azure
  '169.254.169.254', // AWS/Azure metadata
  '169.254.170.2',   // AWS ECS metadata
  // Google Cloud
  'metadata.google.internal', // GCP metadata
  'metadata',
  // Alibaba Cloud
  '100.100.100.200', // Alibaba Cloud metadata
  // Oracle Cloud
  '192.0.0.192',     // Oracle Cloud metadata
]);

// Localhost patterns
export const LOCALHOST_PATTERNS = new Set([
  'localhost',
  '127.0.0.1',
  '::1',
  '0.0.0.0',
  'localhost.localdomain',
]);

// Private IP ranges (regex for IPv4)
export const PRIVATE_IP_RANGES = [
  /^10\./,                          // 10.0.0.0/8
  /^192\.168\./,                    // 192.168.0.0/16
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // 172.16.0.0/12
  /^169\.254\./,                    // 169.254.0.0/16 (Link-local)
  /^127\./,                         // 127.0.0.0/8 (Loopback)
  /^0\./,                           // 0.0.0.0/8 (Invalid)
];

/**
 * Synchronous validation for URLs (no DNS resolution)
 * Used for initial config validation where async is not possible
 *
 * @param urlString - URL to validate
 * @param modeOverride - Optional security mode override
 * @returns Validation result
 */
export function validateUrlSync(urlString: string, modeOverride?: SecurityMode): {
  valid: boolean;
  reason?: string
} {
  try {
    const url = new URL(urlString);
    // Default to strict if no mode provided (same as validateWebhookUrl default)
    // Callers should provide specific mode if needed (e.g. N8N_API_SECURITY_MODE)
    const mode: SecurityMode = modeOverride || 'strict';

    // Step 1: Must be HTTP/HTTPS (all modes)
    if (!['http:', 'https:'].includes(url.protocol)) {
      return { valid: false, reason: 'Invalid protocol. Only HTTP/HTTPS allowed.' };
    }

    // Get hostname and strip IPv6 brackets if present
    let hostname = url.hostname.toLowerCase();
    if (hostname.startsWith('[') && hostname.endsWith(']')) {
      hostname = hostname.slice(1, -1);
    }

    // Step 2: ALWAYS block cloud metadata endpoints (all modes)
    if (CLOUD_METADATA.has(hostname)) {
      return { valid: false, reason: 'Cloud metadata endpoint blocked' };
    }

    // Step 3: Mode-specific validation

    // MODE: permissive - Allow everything except cloud metadata
    if (mode === 'permissive') {
      return { valid: true };
    }

    // Check if target is localhost
    const isLocalhost = LOCALHOST_PATTERNS.has(hostname) ||
                      hostname === '::1' ||
                      hostname.startsWith('127.');

    // MODE: strict - Block localhost and private IPs
    if (mode === 'strict' && isLocalhost) {
      return { valid: false, reason: 'Localhost access is blocked in strict mode' };
    }

    // MODE: moderate - Allow localhost
    if (mode === 'moderate' && isLocalhost) {
      return { valid: true };
    }

    // Step 4: Check private IPv4 ranges (regex check on hostname)
    // Note: Without DNS resolution, we can only check if the hostname ITSELF is a private IP
    if (PRIVATE_IP_RANGES.some(regex => regex.test(hostname))) {
      return {
        valid: false,
        reason: mode === 'strict'
          ? 'Private IP addresses not allowed'
          : 'Private IP addresses not allowed (use N8N_API_SECURITY_MODE=permissive if needed)'
      };
    }

    // Step 5: IPv6 private address check
    if (hostname === '::1' ||         // Loopback
        hostname === '::' ||          // Unspecified address
        hostname.startsWith('fe80:') || // Link-local
        hostname.startsWith('fc00:') || // Unique local (fc00::/7)
        hostname.startsWith('fd00:') || // Unique local (fd00::/8)
        hostname.startsWith('::ffff:')) { // IPv4-mapped IPv6
      return { valid: false, reason: 'IPv6 private address not allowed' };
    }

    return { valid: true };
  } catch (error) {
    return { valid: false, reason: 'Invalid URL format' };
  }
}
