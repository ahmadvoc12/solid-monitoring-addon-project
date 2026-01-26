"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ensureBaseAcl = void 0;
const promises_1 = require("fs/promises");
const path_1 = __importDefault(require("path"));
async function ensureBaseAcl({ podRootPath, ownerWebId, appWebId }) {
    const baseDir = path_1.default.join(podRootPath, "base");
    const aclFile = path_1.default.join(baseDir, ".acl");
    await (0, promises_1.mkdir)(baseDir, { recursive: true });
    const aclTurtle = `
@prefix acl: <http://www.w3.org/ns/auth/acl#>.
@prefix foaf: <http://xmlns.com/foaf/0.1/>.

<#owner>
  a acl:Authorization;
  acl:agent <${ownerWebId}>;
  acl:accessTo <./>;
  acl:default <./>;
  acl:mode acl:Read, acl:Write, acl:Control.

<#authorized-app>
  a acl:Authorization;
  acl:agent <${appWebId}>;
  acl:accessTo <./>;
  acl:default <./>;
  acl:mode acl:Read, acl:Write.
`.trim();
    await (0, promises_1.writeFile)(aclFile, aclTurtle, "utf8");
    console.info("[AUTO-ACL] /base/.acl generated", { podRootPath, appWebId });
}
exports.ensureBaseAcl = ensureBaseAcl;
//# sourceMappingURL=autoAclBase.js.map