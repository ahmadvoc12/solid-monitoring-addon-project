import { overwriteFile } from "@inrupt/solid-client";
import { getDefaultSession } from "@inrupt/solid-client-authn-browser";

const session = getDefaultSession();

export default function ViolenceToggle() {

  async function setMonitoring(enabled) {
    const podBase = session.info.webId.replace("/profile/card#me", "");

    const ttl = `
@prefix ex: <https://example.org/monitoring#>.
@prefix xsd: <http://www.w3.org/2001/XMLSchema#>.

ex:ViolenceMonitoring
    ex:enabled "${enabled}"^^xsd:boolean ;
    ex:lastUpdated "${new Date().toISOString()}"^^xsd:dateTime .
`;

    await overwriteFile(
      `${podBase}/private/settings/violence-monitoring.ttl`,
      new Blob([ttl], { type: "text/turtle" }),
      { fetch: session.fetch }
    );
  }

  return (
    <label>
      <input
        type="checkbox"
        onChange={(e) => setMonitoring(e.target.checked)}
      />
      Enable Violence Monitoring
    </label>
  );
}
