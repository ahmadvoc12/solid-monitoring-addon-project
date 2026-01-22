"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.monitoringMiddleware = void 0;
const monitoringState_1 = require("../../monitoring/monitoringState");
async function monitoringMiddleware(req, res, next) {
    const clientId = req.oidc?.client?.client_id;
    if (clientId && (0, monitoringState_1.isMonitoringEnabled)(clientId)) {
        // extract accessed resource & predicate
    }
    next();
}
exports.monitoringMiddleware = monitoringMiddleware;
//# sourceMappingURL=monitoringMiddleware.js.map