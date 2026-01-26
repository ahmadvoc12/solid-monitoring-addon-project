"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuditAutologger = void 0;
class AuditAutologger {
    logBasePath;
    constructor(logBasePath) {
        this.logBasePath = logBasePath;
    }
    async handle(request) {
        const webId = request.headers.authorization ??
            request.headers['solid-webid'] ??
            'anonymous';
        console.log('[DPV-AUDIT]', {
            method: request.method,
            url: request.url,
            webId,
            logBasePath: this.logBasePath,
            time: new Date().toISOString(),
        });
        // ⚠️ WAJIB lanjutkan pipeline
        return request.next();
    }
}
exports.AuditAutologger = AuditAutologger;
//# sourceMappingURL=solid-audit-autologger.js.map