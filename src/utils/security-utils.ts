
/**
 * Security utilities
 */

/**
 * Sanitize headers for logging
 * Redacts sensitive headers like Authorization and Cookies
 *
 * @param headers - The headers object to sanitize
 * @returns A copy of the headers with sensitive values redacted
 */
export function sanitizeHeaders(headers: any): any {
  if (!headers) return headers;

  // Clone to avoid mutating original
  const sanitized = { ...headers };

  // List of sensitive headers (lowercase)
  const sensitiveKeys = [
    'authorization',
    'x-n8n-key',
    'cookie',
    'set-cookie',
    'x-api-key',
    'proxy-authorization'
  ];

  for (const key of Object.keys(sanitized)) {
    if (sensitiveKeys.includes(key.toLowerCase())) {
      sanitized[key] = '***REDACTED***';
    }
  }

  return sanitized;
}
