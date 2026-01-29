import http from "http";
import fs from "fs/promises";
import path from "path";
import { URL } from "url";
import { spawn } from "child_process";

/* ===============================
   CONFIG (RAILWAY CORRECT)
================================ */
// Railway expose PUBLIC PORT = 3000
const GATEWAY_PORT = Number(process.env.PORT) || 3000;

// CSS HARUS INTERNAL (JANGAN 3000)
const CSS_PORT = 3001;

const BASE_URL =
  process.env.BASE_URL || `http://localhost:${GATEWAY_PORT}`;

const DATA_ROOT = path.resolve(process.cwd(), ".data");
const AUDIT_PATH = "private/audit/access";
const AUDIT_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];

/* ===============================
   START SOLID CSS (INTERNAL ONLY)
================================ */
spawn(
  "node",
  [
    "./bin/server.js",
    "-c", "config/file.json",
    "-f", DATA_ROOT,
    "-p", String(CSS_PORT),   // 🔒 INTERNAL 3001
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
   DEDUP (RESOURCE-LEVEL)
================================ */
const seen = new Set();
const isRepeated = pathname => {
  if (seen.has(pathname)) return true;
  seen.add(pathname);
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
   RDF EXTRACTION
================================ */
function extractPersonalData(rdf) {
  const result = {
    personalData: [],
    values: [],
    sensitive: false
  };

  if (!rdf) return result;

  rdf.match(/dpv:[A-Za-z]+/g)?.forEach(x => {
    if (!result.personalData.includes(x)) {
      result.personalData.push(x);
    }
  });

  const blood = rdf.match(/schema:bloodType\s+"([^"]+)"/);
  if (blood) result.values.push(blood[1]);

  const nid = rdf.match(/schema:identifier\s+"([^"]+)"/);
  if (nid) result.values.push(nid[1]);

  result.sensitive = result.personalData.some(p =>
    p.includes("Blood") || p.includes("Identification")
  );

  return result;
}

/* ===============================
   AUDIT WRITER
================================ */
async function writeAudit({ pod, method, rdf, pathName }) {
  if (!pod) return;

  const logFile = await ensureAuditLog(pod);
  const parsed = extractPersonalData(rdf);

  const id = `log-${Date.now()}`;
  const now = new Date().toISOString();

  let ttl = `
ex:${id}
  a dpv:PersonalDataHandling ;
  dpv:hasProcessing dpv:Access ;
  dpv:hasResource <${BASE_URL}${pathName}> ;
`;

  parsed.personalData.forEach(p =>
    ttl += `  dpv:hasPersonalData dpv:${p.replace("dpv:", "")} ;\n`
  );

  parsed.values.forEach(v =>
    ttl += `  ex:hasDataValue "${v}" ;\n`
  );

  ttl += `
  ex:processingType "${
    parsed.sensitive ? "SensitiveDataAccess" : "DataAccess"
  }" ;
  dct:created "${now}"^^xsd:dateTime .
`;

  await fs.appendFile(logFile, ttl);

  console.log("🧾 AUDIT LOGGED →", pod, pathName);
}

/* ===============================
   GATEWAY SERVER (PUBLIC)
================================ */
http.createServer(async (req, res) => {
  const { method, url } = req;

  // HEALTHCHECK (RAILWAY)
  if (url === "/" || url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok" }));
    return;
  }

  const target = new URL(url, `http://localhost:${CSS_PORT}`);
  const pod = detectPod(target.pathname);

  let body = "";
  for await (const c of req) body += c;

  const proxy = http.request(
    {
      hostname: "localhost",
      port: CSS_PORT,
      path: url,
      method,
      headers: req.headers
    },
    async pres => {
      let resp = "";
      for await (const c of pres) resp += c;

      const shouldAudit =
        AUDIT_METHODS.includes(method) &&
        target.pathname.includes("/pod/") &&
        !isSystemPath(target.pathname) &&
        looksLikeRdf(pres.headers, resp) &&
        !(method === "GET" && isRepeated(target.pathname));

      if (shouldAudit) {
        await writeAudit({
          pod,
          method,
          rdf: resp,
          pathName: target.pathname
        });
      }

      res.writeHead(pres.statusCode, pres.headers);
      res.end(resp);
    }
  );

  if (body) proxy.write(body);
  proxy.end();

}).listen(GATEWAY_PORT, "0.0.0.0", () => {
  console.log(`✅ Solid Gateway PUBLIC @ ${BASE_URL}`);
  console.log(`🔒 Solid CSS INTERNAL @ http://localhost:${CSS_PORT}`);
});
