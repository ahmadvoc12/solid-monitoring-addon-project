"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SolidAuditAutoLogger = void 0;
const uuid_1 = require("uuid");
const fs_1 = require("fs");
const path_1 = __importDefault(require("path"));
/**
 * Solid Audit Auto Logger
 * -----------------------
 * Logs every real POD access as DPV PersonalDataHandling
 */
class SolidAuditAutoLogger {
    async handle(req, res, next) {
        try {
            // Only audit real data access
            if (!this.isPodRequest(req)) {
                await next();
                return;
            }
            const webId = this.extractWebId(req);
            const clientId = this.extractClientId(req);
            if (!webId || !clientId) {
                await next();
                return;
            }
            const resourcePath = this.extractResourcePath(req);
            const dpvMapping = await this.resolveDPV(resourcePath);
            // No personal data = still log (NonPersonalData)
            const timestamp = new Date().toISOString();
            await this.writeAuditLog({
                webId,
                clientId,
                resourcePath,
                method: req.method || 'GET',
                dpvData: dpvMapping,
                timestamp,
            });
        }
        catch (err) {
            // ❗ Audit must NEVER block the request
            console.error('[AUDIT] logging failed:', err);
        }
        await next();
    }
    /* ================= HELPERS ================= */
    isPodRequest(req) {
        return !!req.url && !req.url.startsWith('/.account');
    }
    extractWebId(req) {
        // CSS attaches WebID here
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return req.auth?.webId ?? null;
    }
    extractClientId(req) {
        // DPoP / OIDC client id
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return req.auth?.clientId ?? null;
    }
    extractResourcePath(req) {
        return req.url?.split('?')[0] ?? '/';
    }
    /**
     * Map resource path → DPV personal data
     * Example:
     *  /private/identity/nik → NationalIdentificationNumber
     */
    async resolveDPV(resource) {
        const mappings = {
            '/private/identity/nik': ['dpv-pd:NationalIdentificationNumber'],
            '/private/health/blood': ['dpv-pd:BloodType'],
        };
        return mappings[resource] ?? [];
    }
    /* ================= LOG WRITER ================= */
    async writeAuditLog(input) {
        const podRoot = this.webIdToPodRoot(input.webId);
        const logDir = path_1.default.join(podRoot, 'private/audit/access');
        await fs_1.promises.mkdir(logDir, { recursive: true });
        const logId = `log-${(0, uuid_1.v4)()}`;
        const filePath = path_1.default.join(logDir, `${logId}.ttl`);
        const ttl = this.buildTTL(logId, input);
        await fs_1.promises.writeFile(filePath, ttl, 'utf8');
    }
    webIdToPodRoot(webId) {
        return webId.replace(/\/profile\/card#me$/, '/');
    }
    /* ================= RDF ================= */
    buildTTL(id, a) {
        const personalData = a.dpvData.length > 0
            ? a.dpvData.join(', ')
            : 'dpv:NonPersonalData';
        return `
@prefix dpv:    <https://www.w3.org/ns/dpv#> .
@prefix dpv-pd: <https://www.w3.org/ns/dpv/pd#> .
@prefix dct:    <http://purl.org/dc/terms/> .
@prefix ex:     <https://example.org/solid/audit#> .

ex:${id}
  a dpv:PersonalDataHandling ;
  dpv:hasDataSubject <${a.webId}> ;
  dpv:hasDataController <${a.clientId}> ;
  dpv:hasProcessing dpv:Access ;
  dpv:hasPersonalData ${personalData} ;
  dpv:hasLegalBasis dpv:ExplicitConsent ;
  ex:httpMethod "${a.method}" ;
  ex:resource "${a.resourcePath}" ;
  dct:created "${a.timestamp}"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
`;
    }
}
exports.SolidAuditAutoLogger = SolidAuditAutoLogger;
//# sourceMappingURL=solid-audit-autologger.js.map