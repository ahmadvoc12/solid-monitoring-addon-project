"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getPodRootPathFromWebId = void 0;
const path_1 = __importDefault(require("path"));
function getPodRootPathFromWebId(webId) {
    if (!process.env.CSS_ROOT_FILE_PATH) {
        throw new Error("CSS_ROOT_FILE_PATH is not set");
    }
    // contoh: http://host/podname/profile/card#me
    const match = webId.match(/https?:\/\/[^/]+\/([^/]+)\//);
    if (!match) {
        throw new Error(`Cannot extract pod name from WebID: ${webId}`);
    }
    const podName = match[1];
    return path_1.default.join(process.env.CSS_ROOT_FILE_PATH, podName);
}
exports.getPodRootPathFromWebId = getPodRootPathFromWebId;
//# sourceMappingURL=podPath.js.map