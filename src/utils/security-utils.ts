import { IncomingHttpHeaders } from 'http';

/**
 * List of sensitive headers that should be redacted in logs
 */
const SENSITIVE_HEADERS = [
  'authorization',
  'cookie',
  'set-cookie',
  'x-n8n-key',
  'x-api-key',
  'x-auth-token',
  'api-key',
  'apikey'
];

/**
 * Regex patterns for sensitive body keys.
 * These are matched against the lowercased key.
 */
const SENSITIVE_KEY_PATTERNS = [
  /password/i,
  /client[-_]?secret/i,
  /api[-_]?key/i,
  /api[-_]?secret/i,
  /access[-_]?token/i,
  /refresh[-_]?token/i,
  /auth[-_]?token/i,
  /session[-_]?token/i,
  /^token$/i,      // exact match "token"
  /^secret$/i,     // exact match "secret"
  /^key$/i,        // exact match "key"
  /private[-_]?key/i,
  /secret[-_]?key/i,
  /shared[-_]?secret/i,
  /authorization/i,
  /cookie/i
];

/**
 * Sanitize HTTP headers for logging
 * Redacts sensitive headers with [REDACTED]
 */
export function sanitizeHeaders(headers: IncomingHttpHeaders): Record<string, unknown> {
  const sanitized: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(headers)) {
    if (SENSITIVE_HEADERS.includes(key.toLowerCase())) {
      sanitized[key] = '[REDACTED]';
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
}

/**
 * Sanitize request body for logging
 * Recursively redacts sensitive keys
 */
export function sanitizeBody(body: any): any {
  if (!body) return body;

  // Handle non-object types
  if (typeof body !== 'object') return body;

  // Handle arrays
  if (Array.isArray(body)) {
    return body.map(item => sanitizeBody(item));
  }

  // Handle objects
  const sanitized: any = {};

  for (const [key, value] of Object.entries(body)) {
    const keyLower = key.toLowerCase();

    // Check if key is sensitive using regex patterns
    const isSensitive = SENSITIVE_KEY_PATTERNS.some(pattern => pattern.test(keyLower));

    if (isSensitive) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizeBody(value);
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
}
