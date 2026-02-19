import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import { N8nApiClient } from '../../../src/services/n8n-api-client';
import { SSRFProtection } from '../../../src/utils/ssrf-protection';
import MockAdapter from 'axios-mock-adapter';

// Mock SSRFProtection
vi.mock('../../../src/utils/ssrf-protection', () => ({
  SSRFProtection: {
    validateWebhookUrl: vi.fn(),
  },
}));

describe('N8nApiClient SSRF Protection', () => {
  beforeEach(() => {
    // Reset mocks
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should allow request when validateBaseUrl is false', async () => {
    const client = new N8nApiClient({
      baseUrl: 'http://localhost:5678',
      apiKey: 'test',
      validateBaseUrl: false
    });

    // Mock the axios instance inside client
    const mock = new MockAdapter((client as any).client);
    mock.onGet('/workflows').reply(200, { data: [] });

    await client.listWorkflows();

    // Verify SSRFProtection was NOT called
    expect(SSRFProtection.validateWebhookUrl).not.toHaveBeenCalled();
  });

  it('should block request when validateBaseUrl is true and URL is invalid', async () => {
    // Mock SSRFProtection to fail
    (SSRFProtection.validateWebhookUrl as any).mockResolvedValue({
      valid: false,
      reason: 'Localhost not allowed'
    });

    const client = new N8nApiClient({
      baseUrl: 'http://localhost:5678',
      apiKey: 'test',
      validateBaseUrl: true
    });

    // Mock the axios instance inside client
    const mock = new MockAdapter((client as any).client);
    mock.onGet('/workflows').reply(200, { data: [] });

    await expect(client.listWorkflows()).rejects.toThrow('SSRF protection');

    // Verify SSRFProtection was called with strict mode
    expect(SSRFProtection.validateWebhookUrl).toHaveBeenCalledWith(
      'http://localhost:5678',
      'strict'
    );
  });

  it('should allow request when validateBaseUrl is true and URL is valid', async () => {
    // Mock SSRFProtection to pass
    (SSRFProtection.validateWebhookUrl as any).mockResolvedValue({ valid: true });

    const client = new N8nApiClient({
      baseUrl: 'https://n8n.example.com',
      apiKey: 'test',
      validateBaseUrl: true
    });

    // Mock the axios instance inside client
    const mock = new MockAdapter((client as any).client);
    mock.onGet('/workflows').reply(200, { data: [] });

    await client.listWorkflows();

    // Verify SSRFProtection was called
    expect(SSRFProtection.validateWebhookUrl).toHaveBeenCalledWith(
      'https://n8n.example.com',
      'strict'
    );
  });

  it('should cache validation result', async () => {
    (SSRFProtection.validateWebhookUrl as any).mockResolvedValue({ valid: true });

    const client = new N8nApiClient({
      baseUrl: 'https://n8n.example.com',
      apiKey: 'test',
      validateBaseUrl: true
    });

    const mock = new MockAdapter((client as any).client);
    mock.onGet('/workflows').reply(200, { data: [] });

    // First request
    await client.listWorkflows();

    // Second request
    await client.listWorkflows();

    // Verify SSRFProtection was called ONLY ONCE
    expect(SSRFProtection.validateWebhookUrl).toHaveBeenCalledTimes(1);
  });
});
