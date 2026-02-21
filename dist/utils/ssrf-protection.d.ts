import { validateUrlSync, SecurityMode } from './url-validator-sync';
export { SecurityMode, validateUrlSync };
export declare class SSRFProtection {
    static validateUrlSync: typeof validateUrlSync;
    static validateWebhookUrl(urlString: string): Promise<{
        valid: boolean;
        reason?: string;
    }>;
}
//# sourceMappingURL=ssrf-protection.d.ts.map