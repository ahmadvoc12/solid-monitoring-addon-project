import http from "http";
import fs from "fs/promises";
import path from "path";
import { URL } from "url";
import { spawn } from "child_process";

/* ===============================
   CONFIG (RAILWAY FINAL)
================================ */
const PUBLIC_PORT = process.env.PORT || 3000; // 🚨 HARUS 3000
const CSS_PORT = 3001;                        // internal only

const BASE_URL =
  process.env.BASE_URL ||
  "https://solid-monitoring-addon-project-production.up.railway.app";

const DATA_ROOT = path.resolve(process.cwd(), ".data");
const AUDIT_PATH = "private/audit/access";
const AUDIT_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];

/* ===============================
   START SOLID CSS (INTERNAL)
================================ */
spawn(
  "node",
  [
    "./bin/server.js",
    "-c", "config/file.json",
    "-f", DATA_ROOT,
    "-p", String(CSS_PORT),
    "--baseUrl", BASE_URL
  ],
  { stdio: "inherit" }
);

/* ===============================
   UTIL
================================ */
const detectPod = pathname =>
  pathname.split("/").filter(Boolean)[0] || null;

const isSystemPath = p =>
  p.startsWith("/.well-known") ||
  p.startsWith("/.oidc") ||
  p.startsWith("/.account") ||
  p.endsWith(".acl") ||
  p.includes("/private/audit/");

const looksLikeRdf = (headers, body) => {
  const ct = headers["content-type"] || "";
  return (
    ct.includes("turtle") ||
    ct.includes("rdf") ||
    ct.includes("ld+json") ||
    body.includes("@prefix") ||
    body.includes("dpv:")
  );
};

/* ===============================
   DEDUP
================================ */
const seen = new Set();
const isRepeated = path => {
  if (seen.has(path)) return true;
  seen.add(path);
  return false;
};

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
@prefix schema: <https://schema.org/> .

`
    );
  }

  return file;
}

/* ===============================
   AUDIT WRITER (SIMPLE & STABLE)
================================ */
async function writeAudit({ pod, pathName }) {
  if (!pod) return;

  const file = await ensureAuditLog(pod);
  const id = `log-${Date.now()}`;

  await fs.appendFile(
    file,
`
ex:${id}
  a dpv:PersonalDataHandling ;
  dpv:hasProcessing dpv:Access ;
  dpv:hasResource <${BASE_URL}${pathName}> ;
  dct:created "${new Date().toISOString()}"^^xsd:dateTime .
`
  );

  console.log("🧾 AUDIT LOGGED →", pod, pathName);
}

/* ===============================
   GATEWAY SERVER (PUBLIC)
================================ */
http.createServer(async (req, res) => {
  const { method, url } = req;

  if (url === "/" || url === "/health") {
    res.writeHead(200);
    res.end("OK");
    return;
  }

  const target = new URL(url, `http://localhost:${CSS_PORT}`);
  const pod = detectPod(target.pathname);

  const proxy = http.request(
    {
      hostname: "localhost",
      port: CSS_PORT,
      path: url,
      method,
      headers: req.headers
    },
    async pres => {
      let body = "";
      for await (const c of pres) body += c;

      const shouldAudit =
        AUDIT_METHODS.includes(method) &&
        target.pathname.includes("/pod/") &&
        !isSystemPath(target.pathname) &&
        looksLikeRdf(pres.headers, body) &&
        !(method === "GET" && isRepeated(target.pathname));

      if (shouldAudit) {
        await writeAudit({
          pod,
          pathName: target.pathname
        });
      }

      res.writeHead(pres.statusCode, pres.headers);
      res.end(body);
    }
  );

  proxy.end();
}).listen(PUBLIC_PORT, "0.0.0.0", () => {
  console.log(`✅ Solid Gateway PUBLIC @ ${BASE_URL}`);
  console.log(`🔒 Solid CSS INTERNAL @ http://localhost:${CSS_PORT}`);
});
