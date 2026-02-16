/**
 * Security utilities for n8n-mcp
 * Centralized location for security-related helper functions
 */

/**
 * List of sensitive keys that should be redacted in logs
 * Based on common security best practices and n8n-specific fields
 */
const SENSITIVE_KEYS = new Set([
  'password',
  'pass',
  'passwd',
  'apikey',
  'api_key',
  'accesstoken',
  'access_token',
  'auth',
  'authentication',
  'authorization',
  'token',
  'secret',
  'clientsecret',
  'client_secret',
  'key',
  'credential',
  'credentials',
  'cookie',
  'privatekey',
  'private_key',
  'connectionstring',
  'connection_string',
]);

/**
 * Sanitize data for logging by redacting sensitive keys
 *
 * @param data The data to sanitize (object, array, or primitive)
 * @returns Sanitized data safe for logging
 */
export function sanitizeLogData(data: any): any {
  if (data === null || data === undefined) {
    return data;
  }

  // Handle primitives
  if (typeof data !== 'object' && typeof data !== 'string') {
    return data;
  }

  if (typeof data === 'string') {
    // If string is a JSON representation, try to parse and sanitize
    // This handles cases where JSON is stringified before logging
    try {
      // Only try to parse if it looks like JSON object/array
      const trimmed = data.trim();
      if ((trimmed.startsWith('{') && trimmed.endsWith('}')) ||
          (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
        const parsed = JSON.parse(data);
        if (typeof parsed === 'object' && parsed !== null) {
          return JSON.stringify(sanitizeLogData(parsed));
        }
      }
    } catch (e) {
      // Not valid JSON, ignore error and treat as regular string
    }
    return data;
  }

  if (Array.isArray(data)) {
    return data.map(item => sanitizeLogData(item));
  }

  // Handle objects
  if (typeof data === 'object') {
    // Handle Date objects
    if (data instanceof Date) {
      return data;
    }

    // Handle Error objects
    if (data instanceof Error) {
      return {
        name: data.name,
        message: data.message,
        stack: data.stack,
        ...sanitizeLogData({...data}) // Sanitize any additional properties
      };
    }

    const sanitized: any = {};
    for (const key of Object.keys(data)) {
      const value = data[key];
      const lowerKey = key.toLowerCase();

      // Check if key is sensitive
      // We check for exact matches and suffix matches (e.g., 'google_api_key')
      const isSensitive = SENSITIVE_KEYS.has(lowerKey) ||
                          lowerKey.endsWith('token') ||
                          lowerKey.endsWith('key') ||
                          lowerKey.endsWith('secret') ||
                          lowerKey.endsWith('password');

      if (isSensitive) {
        // Redact the value but keep the key to indicate presence
        if (value === null || value === undefined) {
          sanitized[key] = value;
        } else if (typeof value === 'string') {
          if (value.length > 20) {
            // Keep first 3 and last 3 chars for debugging long tokens
            sanitized[key] = `${value.substring(0, 3)}...${value.substring(value.length - 3)} (REDACTED)`;
          } else {
            sanitized[key] = '***REDACTED***';
          }
        } else {
          sanitized[key] = '***REDACTED***';
        }
      } else {
        // Recursively sanitize non-sensitive fields
        sanitized[key] = sanitizeLogData(value);
      }
    }
    return sanitized;
  }

  return data;
}
