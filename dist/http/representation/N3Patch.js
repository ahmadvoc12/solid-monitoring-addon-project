"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isN3Patch = void 0;
function isN3Patch(patch) {
    return Array.isArray(patch.deletes) &&
        Array.isArray(patch.inserts) &&
        Array.isArray(patch.conditions);
}
exports.isN3Patch = isN3Patch;
//# sourceMappingURL=N3Patch.js.map