/// <reference types="node" />
import type { IncomingMessage, ServerResponse } from 'http';
/**
 * Solid Audit Auto Logger
 * -----------------------
 * Logs every real POD access as DPV PersonalDataHandling
 */
export declare class SolidAuditAutoLogger {
    handle(req: IncomingMessage, res: ServerResponse, next: () => Promise<void>): Promise<void>;
    private isPodRequest;
    private extractWebId;
    private extractClientId;
    private extractResourcePath;
    /**
     * Map resource path → DPV personal data
     * Example:
     *  /private/identity/nik → NationalIdentificationNumber
     */
    private resolveDPV;
    private writeAuditLog;
    private webIdToPodRoot;
    private buildTTL;
}
