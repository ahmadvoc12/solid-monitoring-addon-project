import { getFile } from "@inrupt/solid-client";
import { getDefaultSession } from "@inrupt/solid-client-authn-browser";

const session = getDefaultSession();

export async function isViolenceMonitoringEnabled() {
  const podBase = session.info.webId.replace("/profile/card#me", "");
  const fileUrl = `${podBase}/private/settings/violence-monitoring.ttl`;

  try {
    const file = await getFile(fileUrl, { fetch: session.fetch });
    const text = await file.text();

    return text.includes('ex:enabled "true"');
  } catch {
    // default aman
    return false;
  }
}
