import { useEffect } from "react";
import { getDefaultSession } from "@inrupt/solid-client-authn-browser";
import { ensureMonitoringFile } from "./services/ensureMonitoringFile";

const session = getDefaultSession();

function App() {

  useEffect(() => {
    if (session.info.isLoggedIn) {
      ensureMonitoringFile();
    }
  }, []);

  return (
    <>
      {/* UI kamu */}
    </>
  );
}

export default App;
