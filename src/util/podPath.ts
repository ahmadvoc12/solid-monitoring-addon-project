import path from "path";

export function getPodRootPathFromWebId(webId: string): string {
  if (!process.env.CSS_ROOT_FILE_PATH) {
    throw new Error("CSS_ROOT_FILE_PATH is not set");
  }

  // contoh: http://host/podname/profile/card#me
  const match = webId.match(/https?:\/\/[^/]+\/([^/]+)\//);

  if (!match) {
    throw new Error(`Cannot extract pod name from WebID: ${webId}`);
  }

  const podName = match[1];

  return path.join(process.env.CSS_ROOT_FILE_PATH, podName);
}
