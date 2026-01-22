import { getFile, overwriteFile } from "@inrupt/solid-client";
import { getDefaultSession } from "@inrupt/solid-client-authn-browser";

const session = getDefaultSession();

export async function logViolenceEvent({
  eventName,
  functionName,
  violationNote,
  consent,
  actualAccess
}) {
  const podBase = session.info.webId.replace("/profile/card#me", "");
  const logUrl = `${podBase}/private/logs/violence-events.ttl`;

  const eventId = crypto.randomUUID();
  const now = new Date().toISOString();
  const origin = window.location.origin;

  const entry = `
@prefix schema: <https://schema.org/>.
@prefix dct: <http://purl.org/dc/terms/>.
@prefix ex: <urn:uuid:>.

ex:${eventId}
    a schema:SecurityEvent ;
    schema:name "${eventName}" ;
    schema:application "Solid Health Diary PoC" ;
    schema:agent "Solid Health Diary PoC" ;
    schema:about <${session.info.webId}> ;
    schema:target <${session.info.webId}> ;
    schema:function "${functionName}" ;
    schema:purpose "" ;
    schema:userConsent ${consent} ;
    schema:actualAccess ${actualAccess} ;
    schema:violationNote "${violationNote}" ;
    schema:origin <${origin}> ;
    dct:created "${now}"^^xsd:dateTime .
`;

  try {
    const existing = await getFile(logUrl, { fetch: session.fetch });
    const text = await existing.text();

    await overwriteFile(
      logUrl,
      new Blob([text + "\n" + entry], { type: "text/turtle" }),
      { fetch: session.fetch }
    );
  } catch {
    // file belum ada → buat baru
    await overwriteFile(
      logUrl,
      new Blob([entry], { type: "text/turtle" }),
      { fetch: session.fetch }
    );
  }
}
