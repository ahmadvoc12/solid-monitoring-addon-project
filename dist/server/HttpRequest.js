"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isHttpRequest = void 0;
/**
 * Checks if the given stream is an HttpRequest.
 */
function isHttpRequest(stream) {
    const req = stream;
    return typeof req.socket === 'object' && typeof req.url === 'string' && typeof req.method === 'string';
}
exports.isHttpRequest = isHttpRequest;
//# sourceMappingURL=HttpRequest.js.map