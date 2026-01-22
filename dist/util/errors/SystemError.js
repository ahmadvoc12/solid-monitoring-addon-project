"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isSystemError = void 0;
function isSystemError(error) {
    return Boolean(error.code && error.syscall);
}
exports.isSystemError = isSystemError;
//# sourceMappingURL=SystemError.js.map