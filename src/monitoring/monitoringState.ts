const monitoringState = new Map<string, boolean>();

export function enableMonitoring(clientId: string) {
  monitoringState.set(clientId, true);
}

export function disableMonitoring(clientId: string) {
  monitoringState.set(clientId, false);
}

export function isMonitoringEnabled(clientId: string): boolean {
  return monitoringState.get(clientId) === true;
}
