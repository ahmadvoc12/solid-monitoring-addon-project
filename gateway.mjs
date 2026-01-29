import http from "http";
import fs from "fs/promises";
import path from "path";
import { URL } from "url";
import { spawn } from "child_process";

/* ===============================
   CONFIG (RAILWAY SAFE)
================================ */
const GATEWAY_PORT = process.env.PORT || 8080;   // 🔥 WAJIB
const CSS_PORT = 3000;                           // internal only
const BASE_URL =
  process.env.BASE_URL || `http://localhost:${GATEWAY_PORT}`;

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
    "--baseUrl", BASE_URL        // 🔥 PUBLIC BASE URL
  ],
  { stdio: "inherit" }
);

/* ===============================
   UTIL
================================ */
const detectPod = pathname =>
  pathname.split("/").filter(Boolean)[0] || null;

/* ===============================
   REQUEST FILTERS
================================ */
const isAuthenticated = h => !!h.authorization;

const isProfile = p => p.includes("/profile/card");

const isSystem = p =>
  p.startsWith("/.well-known") ||
  p.startsWith("/.oidc") ||
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
   DEDUP (token + resource)
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
@prefix schema: <https://schema.org/> .

`
    );
  }

  return file;
}

/* ===============================
   RDF EXTRACTION (VALUE SAFE)
================================ */
function extractPersonalData(rdf) {
  const result = {
    personalData: [],
    dataCategories: [],
    values: [],
    sensitive: false
  };

  if (!rdf || typeof rdf !== "string") return result;

  // dpv:hasPersonalData
  rdf.match(/dpv:hasPersonalData\s+([^;]+);/g)
    ?.forEach(block => {
      block.match(/dpv:[A-Za-z0-9]+/g)
        ?.forEach(iri => {
          if (!result.personalData.includes(iri)) {
            result.personalData.push(iri);
          }
        });
    });

  // dpv:hasDataCategory
  rdf.match(/dpv:hasDataCategory\s+([^;]+);/g)
    ?.forEach(block => {
      block.match(/dpv:[A-Za-z0-9]+/g)
        ?.forEach(cat => {
          if (!result.dataCategories.includes(cat)) {
            result.dataCategories.push(cat);
          }
        });
    });

  // REAL DATA VALUES ONLY (NO TIME)
  const blood = rdf.match(/schema:bloodType\s+"([^"]+)"/);
  if (blood) result.values.push(blood[1]);

  const nid = rdf.match(/schema:identifier\s+"([^"]+)"/);
  if (nid) result.values.push(nid[1]);

  result.sensitive = result.dataCategories.some(c =>
    c.includes("HighlySensitive") ||
    c.includes("SpecialCategory")
  );

  return result;
}

/* ===============================
   AUDIT WRITER (PUBLIC URL)
================================ */
async function writeAudit({ pod, method, rdf, resourcePath }) {
  if (!pod) return;

  const logFile = await ensureAuditLog(pod);
  const parsed = extractPersonalData(rdf);

  const id = `log-${Date.now()}`;
  const now = new Date().toISOString();

  let ttl = `
ex:${id}
  a dpv:PersonalDataHandling ;
  dpv:hasProcessing ${method === "GET" ? "dpv:Access" : "dpv:Create"} ;
  dpv:hasResource <${BASE_URL}${resourcePath}> ;
`;

  parsed.personalData.forEach(iri => {
    ttl += `  dpv:hasPersonalData ${iri} ;\n`;
  });

  parsed.dataCategories.forEach(cat => {
    ttl += `  dpv:hasDataCategory ${cat} ;\n`;
  });

  parsed.values.forEach(v => {
    ttl += `  ex:hasDataValue "${v}" ;\n`;
  });

  ttl += `
  ex:processingType "${
    parsed.sensitive
      ? "SensitiveDataAccess"
      : parsed.personalData.length > 0
      ? "PersonalDataAccess"
      : "NonPersonalDataAccess"
  }" ;
  dct:created "${now}"^^xsd:dateTime .
`;

  await fs.appendFile(logFile, ttl);

  console.log(
    "🧾 AUDIT →",
    pod,
    parsed.sensitive
      ? "🔴 SENSITIVE"
      : parsed.personalData.length > 0
      ? "🟡 PERSONAL"
      : "🟢 NON-PERSONAL"
  );
}

/* ===============================
   GATEWAY SERVER (PUBLIC)
================================ */
http.createServer(async (req, res) => {
  const { method, url, headers } = req;
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
      headers
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
          resourcePath: target.pathname
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
