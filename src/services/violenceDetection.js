import { isViolenceMonitoringEnabled } from "./monitoringService";
import { logViolenceEvent } from "./violenceLogger";

export async function runViolenceDetection(context) {

  const enabled = await isViolenceMonitoringEnabled();
  if (!enabled) return;

  // contoh pelanggaran
  await logViolenceEvent({
    eventName: "PROFILE_ACCESS_VIOLATION",
    functionName: "readUserProfile",
    violationNote: "Access performed despite explicit user denial",
    consent: false,
    actualAccess: true
  });
}
