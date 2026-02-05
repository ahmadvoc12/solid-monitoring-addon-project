import http from "http";
import fs from "fs/promises";
import path from "path";
import { URL } from "url";
import { spawn } from "child_process";

/* ===============================
   CONFIG
================================ */
// Railway injects PORT (8080, dll)
const GATEWAY_PORT = process.env.PORT || 3000;

// Internal CSS only (JANGAN DIEKSPOS)
const CSS_PORT = 4000;

// Domain publik Railway
const PUBLIC_BASE_URL = "https://solid-monitoring-addon-project-production.up.railway.app";

const DATA_ROOT = path.resolve(process.cwd(), ".data");
const AUDIT_PATH = "private/audit/access";
const AUDIT_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];

/* ===============================
   RESOURCE → DPV SCHEMA MAP
================================ */
const RESOURCE_SCHEMA = {
  "health-records": {
    personal: "dpv:HealthData",
    category: "dpv:SpecialCategoryPersonalData",
    sensitive: true
  }
};

/* ===============================
   FIELD → DPV SCHEMA MAP
================================ */
const FIELD_SCHEMA = {
  "https://schema.org/bloodType": {
    personal: "dpv:HealthData",
    category: "dpv:SpecialCategoryPersonalData",
    sensitive: true
  },
  "schema:bloodType": {
    personal: "dpv:HealthData",
    category: "dpv:SpecialCategoryPersonalData",
    sensitive: true
  }
};

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
const sleep = ms => new Promise(r => setTimeout(r, ms));
const detectPod = pathname => pathname.split("/").filter(Boolean)[0] || null;

const extractAppName = pathname => {
  const seg = pathname.split("/").filter(Boolean);
  const idx = seg.indexOf("public");
  return idx !== -1 && seg[idx + 1] ? seg[idx + 1] : "unknown-app";
};

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
  try { await fs.access(file); }
  catch {
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
   EXTRACT PERSONAL DATA
================================ */
function extractPersonalData(rdf, pathname) {
  const result = {
    personalData: [],
    dataCategories: [],
    fields: [],
    values: [],
    sensitive: false
  };

  const app = extractAppName(pathname);
  const resourceSchema = RESOURCE_SCHEMA[app];
  if (resourceSchema) {
    result.personalData.push(resourceSchema.personal);
    result.dataCategories.push(resourceSchema.category);
    result.sensitive = true;
  }

  if (!rdf || typeof rdf !== "string") return result;

  rdf.match(/([a-zA-Z0-9:_-]+)\s+"([^"]+)"/g)?.forEach(m => {
    const [, field, value] = m.match(/(.+?)\s+"(.+)"/);
    if (field.startsWith("dc:") || field.startsWith("dct:")) return;

    result.fields.push(field);
    result.values.push(value);

    const fschema = FIELD_SCHEMA[field];
    if (fschema) {
      result.personalData.push(fschema.personal);
      result.dataCategories.push(fschema.category);
      result.sensitive = true;
    }
  });

  rdf.match(/<https?:\/\/[^>]+>\s+"([^"]+)"/g)?.forEach(m => {
    const [, iri, value] = m.match(/<(https?:\/\/[^>]+)>\s+"([^"]+)"/);
    result.fields.push(iri);
    result.values.push(value);

    const fschema = FIELD_SCHEMA[iri];
    if (fschema) {
      result.personalData.push(fschema.personal);
      result.dataCategories.push(fschema.category);
      result.sensitive = true;
    }
  });

  return result;
}

/* ===============================
   AUDIT WRITER
================================ */
async function writeAudit({ pod, method, rdf, resource, pathname }) {
  if (!pod) return;

  const logFile = await ensureAuditLog(pod);
  const parsed = extractPersonalData(rdf, pathname);

  const id = `log-${Date.now()}`;
  const now = new Date().toISOString();
  const appName = extractAppName(pathname);

  let ttl = `
ex:${id}
  a dpv:PersonalDataHandling ;
  dpv:hasProcessing ${method === "GET" ? "dpv:Access" : "dpv:Create"} ;
  dpv:hasResource <${resource}> ;
  ex:accessedByApp "${appName}" ;
`;

  parsed.personalData.forEach(p => ttl += `  dpv:hasPersonalData ${p} ;\n`);
  parsed.dataCategories.forEach(c => ttl += `  dpv:hasDataCategory ${c} ;\n`);

  parsed.fields.forEach((f, i) => {
    ttl += `  ex:hasDataField "${f}" ;\n`;
    ttl += `  ex:hasDataValue "${parsed.values[i]}" ;\n`;
  });

  ttl += `  dct:created "${now}"^^xsd:dateTime .\n`;
  await fs.appendFile(logFile, ttl);
}

/* ===============================
   GATEWAY SERVER
================================ */
(async () => {
  // ⏳ Tunggu CSS siap (PENTING)
  await sleep(4000);

  http.createServer(async (req, res) => {
    const { method, url, headers } = req;

    /* 🚑 RAILWAY HEALTHCHECK */
    if (method === "GET" && (url === "/" || url === "/health")) {
      res.writeHead(200, { "Content-Type": "text/plain" });
      return res.end("OK");
    }

    /* 🚫 BLOCK INTERNAL SOLID ACCOUNT */
    if (url.startsWith("/.account")) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      return res.end("Not available via gateway");
    }

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
        headers: {
          ...fHeaders,
          "x-forwarded-host": headers.host,
          "x-forwarded-proto": "https"
        }
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
  })
  .listen(GATEWAY_PORT, () => {
    console.log(`✅ Solid Gateway running on port ${GATEWAY_PORT}`);
  });
})();
