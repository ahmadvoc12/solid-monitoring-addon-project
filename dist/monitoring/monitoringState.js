"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isMonitoringEnabled = exports.disableMonitoring = exports.enableMonitoring = void 0;
const monitoringState = new Map();
function enableMonitoring(clientId) {
    monitoringState.set(clientId, true);
}
exports.enableMonitoring = enableMonitoring;
function disableMonitoring(clientId) {
    monitoringState.set(clientId, false);
}
exports.disableMonitoring = disableMonitoring;
function isMonitoringEnabled(clientId) {
    return monitoringState.get(clientId) === true;
}
exports.isMonitoringEnabled = isMonitoringEnabled;
//# sourceMappingURL=monitoringState.js.map