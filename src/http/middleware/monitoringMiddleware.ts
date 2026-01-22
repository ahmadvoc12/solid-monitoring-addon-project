import { isMonitoringEnabled } from '../../monitoring/monitoringState';

export async function monitoringMiddleware(req, res, next) {
  const clientId = req.oidc?.client?.client_id;
  if (clientId && isMonitoringEnabled(clientId)) {
    // extract accessed resource & predicate
  }
  next();
}
