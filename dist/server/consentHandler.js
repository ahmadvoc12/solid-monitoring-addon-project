"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.handleConsentSuccess = void 0;
const autoAclBase_1 = require("./autoAclBase");
const podPath_1 = require("./utils/podPath");
async function handleConsentSuccess(req) {
    // ✅ ambil data dari session secara aman
    const userWebId = req.session?.webId;
    const appWebId = req.session?.appWebId;
    if (!userWebId) {
        throw new Error("[CONSENT] Missing user WebID in session");
    }
    if (!appWebId) {
        throw new Error("[CONSENT] Missing app WebID in session");
    }
    // ✅ derive pod root secara dinamis (TIDAK hardcode)
    const podRootPath = (0, podPath_1.getPodRootPathFromWebId)(userWebId);
    // 🔐 generate /base/.acl
    await (0, autoAclBase_1.ensureBaseAcl)({
        podRootPath,
        ownerWebId: userWebId,
        appWebId
    });
    console.info("[CONSENT] Base ACL generated", { podRootPath, owner: userWebId, app: appWebId });
}
exports.handleConsentSuccess = handleConsentSuccess;
//# sourceMappingURL=consentHandler.js.map