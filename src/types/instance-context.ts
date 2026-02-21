/**
 * Instance Context for flexible configuration support
 *
 * Allows the n8n-mcp engine to accept instance-specific configuration
 * at runtime, enabling flexible deployment scenarios while maintaining
 * backward compatibility with environment-based configuration.
 */

import { validateUrlSync, SecurityMode } from '../utils/url-validator-sync';

export interface InstanceContext {
  /**
   * Instance-specific n8n API configuration
   * When provided, these override environment variables
   */
  n8nApiUrl?: string;
  n8nApiKey?: string;
  n8nApiTimeout?: number;
  n8nApiMaxRetries?: number;

  /**
   * Instance identification
   * Used for session management and logging
   */
  instanceId?: string;
  sessionId?: string;

  /**
   * Extensible metadata for future use
   * Allows passing additional configuration without interface changes
   */
  metadata?: Record<string, any>;
}

/**
 * Validate API key format (basic check for non-empty string)
 */
function isValidApiKey(key: string): boolean {
  // API key should be non-empty and not contain obvious placeholder values
  return key.length > 0 &&
         !key.toLowerCase().includes('your_api_key') &&
         !key.toLowerCase().includes('placeholder') &&
         !key.toLowerCase().includes('example');
}

/**
 * Type guard to check if an object is an InstanceContext
 */
export function isInstanceContext(obj: any): obj is InstanceContext {
  if (!obj || typeof obj !== 'object') return false;

  // Check for known properties with validation
  const hasValidUrl = obj.n8nApiUrl === undefined ||
    (typeof obj.n8nApiUrl === 'string' && validateUrlSync(obj.n8nApiUrl, 'permissive').valid);

  const hasValidKey = obj.n8nApiKey === undefined ||
    (typeof obj.n8nApiKey === 'string' && isValidApiKey(obj.n8nApiKey));

  const hasValidTimeout = obj.n8nApiTimeout === undefined ||
    (typeof obj.n8nApiTimeout === 'number' && obj.n8nApiTimeout > 0);

  const hasValidRetries = obj.n8nApiMaxRetries === undefined ||
    (typeof obj.n8nApiMaxRetries === 'number' && obj.n8nApiMaxRetries >= 0);

  const hasValidInstanceId = obj.instanceId === undefined || typeof obj.instanceId === 'string';
  const hasValidSessionId = obj.sessionId === undefined || typeof obj.sessionId === 'string';
  const hasValidMetadata = obj.metadata === undefined ||
    (typeof obj.metadata === 'object' && obj.metadata !== null);

  return hasValidUrl && hasValidKey && hasValidTimeout && hasValidRetries &&
         hasValidInstanceId && hasValidSessionId && hasValidMetadata;
}

/**
 * Validate and sanitize InstanceContext
 * Provides field-specific error messages for better debugging
 */
export function validateInstanceContext(context: InstanceContext): {
  valid: boolean;
  errors?: string[]
} {
  const errors: string[] = [];

  // Validate URL if provided (even empty string should be validated)
  if (context.n8nApiUrl !== undefined) {
    if (context.n8nApiUrl === '') {
      errors.push(`Invalid n8nApiUrl: empty string - URL is required when field is provided`);
    } else {
      // Use permissive mode by default for API URL unless N8N_API_SECURITY_MODE is set
      // This supports local deployments (localhost/private IPs) while blocking cloud metadata
      const mode = (process.env.N8N_API_SECURITY_MODE || 'permissive') as SecurityMode;
      const validation = validateUrlSync(context.n8nApiUrl, mode);

      if (!validation.valid) {
        errors.push(`Invalid n8nApiUrl: ${validation.reason || 'Invalid URL'}`);
      }
    }
  }

  // Validate API key if provided
  if (context.n8nApiKey !== undefined) {
    if (context.n8nApiKey === '') {
      errors.push(`Invalid n8nApiKey: empty string - API key is required when field is provided`);
    } else if (!isValidApiKey(context.n8nApiKey)) {
      // Provide specific reason for API key invalidity
      if (context.n8nApiKey.toLowerCase().includes('your_api_key')) {
        errors.push(`Invalid n8nApiKey: contains placeholder 'your_api_key' - Please provide actual API key`);
      } else if (context.n8nApiKey.toLowerCase().includes('placeholder')) {
        errors.push(`Invalid n8nApiKey: contains placeholder text - Please provide actual API key`);
      } else if (context.n8nApiKey.toLowerCase().includes('example')) {
        errors.push(`Invalid n8nApiKey: contains example text - Please provide actual API key`);
      } else {
        errors.push(`Invalid n8nApiKey: format validation failed - Ensure key is valid`);
      }
    }
  }

  // Validate timeout
  if (context.n8nApiTimeout !== undefined) {
    if (typeof context.n8nApiTimeout !== 'number') {
      errors.push(`Invalid n8nApiTimeout: ${context.n8nApiTimeout} - Must be a number, got ${typeof context.n8nApiTimeout}`);
    } else if (context.n8nApiTimeout <= 0) {
      errors.push(`Invalid n8nApiTimeout: ${context.n8nApiTimeout} - Must be positive (greater than 0)`);
    } else if (!isFinite(context.n8nApiTimeout)) {
      errors.push(`Invalid n8nApiTimeout: ${context.n8nApiTimeout} - Must be a finite number (not Infinity or NaN)`);
    }
  }

  // Validate retries
  if (context.n8nApiMaxRetries !== undefined) {
    if (typeof context.n8nApiMaxRetries !== 'number') {
      errors.push(`Invalid n8nApiMaxRetries: ${context.n8nApiMaxRetries} - Must be a number, got ${typeof context.n8nApiMaxRetries}`);
    } else if (context.n8nApiMaxRetries < 0) {
      errors.push(`Invalid n8nApiMaxRetries: ${context.n8nApiMaxRetries} - Must be non-negative (0 or greater)`);
    } else if (!isFinite(context.n8nApiMaxRetries)) {
      errors.push(`Invalid n8nApiMaxRetries: ${context.n8nApiMaxRetries} - Must be a finite number (not Infinity or NaN)`);
    }
  }

  return {
    valid: errors.length === 0,
    errors: errors.length > 0 ? errors : undefined
  };
}
