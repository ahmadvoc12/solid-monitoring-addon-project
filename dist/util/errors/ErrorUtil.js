"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createErrorMessage = exports.isError = void 0;
const node_util_1 = require("node:util");
/**
 * Checks if the input is an {@link Error}.
 */
function isError(error) {
    return node_util_1.types.isNativeError(error) ||
        (Boolean(error) &&
            typeof error.name === 'string' &&
            typeof error.message === 'string' &&
            (typeof error.stack === 'undefined' || typeof error.stack === 'string'));
}
exports.isError = isError;
/**
 * Creates a string representing the error message of this object.
 */
function createErrorMessage(error) {
    return isError(error) ? error.message : `Unknown error: ${error}`;
}
exports.createErrorMessage = createErrorMessage;
//# sourceMappingURL=ErrorUtil.js.map