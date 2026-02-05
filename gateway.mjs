import http from "http";
import fs from "fs/promises";
import path from "path";
import { URL } from "url";
import { spawn } from "child_process";

/* ===============================
   CONFIG
================================ */
const GATEWAY_PORT = 3000;     // SESUAI RAILWAY
const CSS_PORT = 4000;         // INTERNAL
const PUBLIC_BASE_URL = "https://solid-monitoring-addon-project-production.up.railway.app";

const DATA_ROOT = path.resolve(process.cwd(), ".data");
const AUDIT_PATH = "private/audit/access";
const AUDIT_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];

/* ===============================
   START COMMUNITY SOLID SERVER
================================ */
spawn(
  "node",
  [
    "./bin/server.js",
    "-c", "config/file.json",
    "-f", DATA_ROOT,
    "-p", String(CSS_PORT),
    "--baseUrl", PUBLIC_BASE_URL
  ],
  { stdio: "inherit" }
);

/* ===============================
   UTIL
================================ */
const detectPod = pathname =>
  pathname.split("/").filter(Boolean)[0] || null;

const extractAppName = pathname => {
  const seg = pathname.split("/").filter(Boolean);
  const idx = seg.indexOf("public");
  return idx !== -1 && seg[idx + 1] ? seg[idx + 1] : "unknown-app";
};

/* ===============================
   FILTERS
================================ */
const isAuthenticated = h => !!h.authorization;
const isProfile = p => p.includes("/profile/card");
const isSystem = p =>
  p.startsWith("/.well-known") ||
  p.startsWith("/.oidc") ||
  p.startsWith("/.account") ||
  p.endsWith(".acl") ||
  p.includes("/private/audit/");
const isBrowserNav = h =>
  h["sec-fetch-mode"] === "navigate" ||
  h["sec-fetch-dest"] === "document";
const isApp = h =>
  h["sec-fetch-site"] === "cross-site" ||
  (!!h.authorization && !h["sec-fetch-site"]);
const isRdf = h =>
  (h["content-type"] || "").match(/turtle|ld\+json|rdf\+xml/i);

/* ===============================
   DEDUP
================================ */
const seen = new Set();
function isRepeated(auth, pathname) {
  const key = `${auth || "anon"}::${pathname}`;
  if (seen.has(key)) return true;
  seen.add(key);
  return false;
}

/* ===============================
   AUDIT FILE PREP
================================ */
async function ensureAuditLog(pod) {
  const dir = path.join(DATA_ROOT, pod, AUDIT_PATH);
  const file = path.join(dir, "log.ttl");

  await fs.mkdir(dir, { recursive: true });
  try {
    await fs.access(file);
  } catch {
    await fs.writeFile(
      file,
`@prefix dpv: <https://w3id.org/dpv#> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix ex: <https://example.org/solid/audit#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

`
    );
  }
  return file;
}

/* ===============================
   AUDIT WRITER (AKTIF)
================================ */
async function writeAudit({ pod, method, rdf, resource, pathname }) {
  if (!pod) return;

  const logFile = await ensureAuditLog(pod);
  const id = `log-${Date.now()}`;
  const now = new Date().toISOString();
  const appName = extractAppName(pathname);

  const ttl = `
ex:${id}
  a dpv:PersonalDataHandling ;
  dpv:hasProcessing ${method === "GET" ? "dpv:Access" : "dpv:Create"} ;
  dpv:hasResource <${resource}> ;
  ex:accessedByApp "${appName}" ;
  dct:created "${now}"^^xsd:dateTime .
`;

  await fs.appendFile(logFile, ttl);

  console.log(
    "🧾 AUDIT →",
    method,
    resource
  );
}

/* ===============================
   GATEWAY SERVER
================================ */
http.createServer(async (req, res) => {
  const { method, url, headers } = req;

  /* 🚑 HEALTHCHECK */
  if (method === "GET" && (url === "/" || url === "/health")) {
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end("OK");
  }

  /* ✅ PROXY .account LANGSUNG */
  if (url.startsWith("/.account")) {
    const proxy = http.request(
      {
        hostname: "localhost",
        port: CSS_PORT,
        path: url,
        method,
        headers
      },
      pres => {
        res.writeHead(pres.statusCode, pres.headers);
        pres.pipe(res);
      }
    );
    req.pipe(proxy);
    return;
  }

  /* ===============================
     NORMAL REQUEST
  ============================== */
  const target = new URL(url, `http://localhost:${CSS_PORT}`);
  const pod = detectPod(target.pathname);

  let body = "";
  for await (const c of req) body += c;

  const fHeaders = { ...headers };
  delete fHeaders["content-length"];

  const proxy = http.request(
    {
      hostname: "localhost",
      port: CSS_PORT,
      path: url,
      method,
      headers: fHeaders
    },
    async pres => {
      let resp = "";
      for await (const c of pres) resp += c;

      const shouldAudit =
        AUDIT_METHODS.includes(method) &&
        isAuthenticated(headers) &&
        isRdf(pres.headers) &&
        isApp(headers) &&
        !isProfile(target.pathname) &&
        !isSystem(target.pathname) &&
        !isBrowserNav(headers) &&
        !(method === "GET" && isRepeated(headers.authorization, target.pathname));

      if (shouldAudit) {
        await writeAudit({
          pod,
          method,
          rdf: method === "GET" ? resp : body,
          resource: `${PUBLIC_BASE_URL}${target.pathname}`,
          pathname: target.pathname
        });
      }

      res.writeHead(pres.statusCode, pres.headers);
      res.end(resp);
    }
  );

  if (body) proxy.write(body);
  proxy.end();

}).listen(GATEWAY_PORT, () => {
  console.log(`✅ Solid Gateway running on port ${GATEWAY_PORT}`);
});
