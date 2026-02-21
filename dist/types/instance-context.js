"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isInstanceContext = isInstanceContext;
exports.validateInstanceContext = validateInstanceContext;
const url_validator_sync_1 = require("../utils/url-validator-sync");
function isValidApiKey(key) {
    return key.length > 0 &&
        !key.toLowerCase().includes('your_api_key') &&
        !key.toLowerCase().includes('placeholder') &&
        !key.toLowerCase().includes('example');
}
function isInstanceContext(obj) {
    if (!obj || typeof obj !== 'object')
        return false;
    const hasValidUrl = obj.n8nApiUrl === undefined ||
        (typeof obj.n8nApiUrl === 'string' && (0, url_validator_sync_1.validateUrlSync)(obj.n8nApiUrl, 'permissive').valid);
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
function validateInstanceContext(context) {
    const errors = [];
    if (context.n8nApiUrl !== undefined) {
        if (context.n8nApiUrl === '') {
            errors.push(`Invalid n8nApiUrl: empty string - URL is required when field is provided`);
        }
        else {
            const mode = (process.env.N8N_API_SECURITY_MODE || 'permissive');
            const validation = (0, url_validator_sync_1.validateUrlSync)(context.n8nApiUrl, mode);
            if (!validation.valid) {
                errors.push(`Invalid n8nApiUrl: ${validation.reason || 'Invalid URL'}`);
            }
        }
    }
    if (context.n8nApiKey !== undefined) {
        if (context.n8nApiKey === '') {
            errors.push(`Invalid n8nApiKey: empty string - API key is required when field is provided`);
        }
        else if (!isValidApiKey(context.n8nApiKey)) {
            if (context.n8nApiKey.toLowerCase().includes('your_api_key')) {
                errors.push(`Invalid n8nApiKey: contains placeholder 'your_api_key' - Please provide actual API key`);
            }
            else if (context.n8nApiKey.toLowerCase().includes('placeholder')) {
                errors.push(`Invalid n8nApiKey: contains placeholder text - Please provide actual API key`);
            }
            else if (context.n8nApiKey.toLowerCase().includes('example')) {
                errors.push(`Invalid n8nApiKey: contains example text - Please provide actual API key`);
            }
            else {
                errors.push(`Invalid n8nApiKey: format validation failed - Ensure key is valid`);
            }
        }
    }
    if (context.n8nApiTimeout !== undefined) {
        if (typeof context.n8nApiTimeout !== 'number') {
            errors.push(`Invalid n8nApiTimeout: ${context.n8nApiTimeout} - Must be a number, got ${typeof context.n8nApiTimeout}`);
        }
        else if (context.n8nApiTimeout <= 0) {
            errors.push(`Invalid n8nApiTimeout: ${context.n8nApiTimeout} - Must be positive (greater than 0)`);
        }
        else if (!isFinite(context.n8nApiTimeout)) {
            errors.push(`Invalid n8nApiTimeout: ${context.n8nApiTimeout} - Must be a finite number (not Infinity or NaN)`);
        }
    }
    if (context.n8nApiMaxRetries !== undefined) {
        if (typeof context.n8nApiMaxRetries !== 'number') {
            errors.push(`Invalid n8nApiMaxRetries: ${context.n8nApiMaxRetries} - Must be a number, got ${typeof context.n8nApiMaxRetries}`);
        }
        else if (context.n8nApiMaxRetries < 0) {
            errors.push(`Invalid n8nApiMaxRetries: ${context.n8nApiMaxRetries} - Must be non-negative (0 or greater)`);
        }
        else if (!isFinite(context.n8nApiMaxRetries)) {
            errors.push(`Invalid n8nApiMaxRetries: ${context.n8nApiMaxRetries} - Must be a finite number (not Infinity or NaN)`);
        }
    }
    return {
        valid: errors.length === 0,
        errors: errors.length > 0 ? errors : undefined
    };
}
//# sourceMappingURL=instance-context.js.map