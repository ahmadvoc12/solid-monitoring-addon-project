import http from "http";
import fs from "fs/promises";
import path from "path";
import { URL } from "url";
import { spawn } from "child_process";

/* ===============================
   CONFIG
================================ */
const GATEWAY_PORT = 3001;
const CSS_PORT = 3000;

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
   FIELD → DPV SCHEMA MAP (🔥 NEW & CRITICAL)
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
   START SOLID CSS
================================ */
spawn(
  "node",
  [
    "./bin/server.js",
    "-c", "config/file.json",
    "-f", DATA_ROOT,
    "-p", String(CSS_PORT),
    "--baseUrl", `http://localhost:${GATEWAY_PORT}`
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
   EXTRACT PERSONAL DATA (FIELD-AWARE)
================================ */
function extractPersonalData(rdf, pathname) {
  const result = {
    personalData: [],
    dataCategories: [],
    fields: [],
    values: [],
    sensitive: false
  };

  /* 1️⃣ RESOURCE-LEVEL */
  const app = extractAppName(pathname);
  const resourceSchema = RESOURCE_SCHEMA[app];

  if (resourceSchema) {
    result.personalData.push(resourceSchema.personal);
    result.dataCategories.push(resourceSchema.category);
    result.sensitive = resourceSchema.sensitive;
  }

  if (!rdf || typeof rdf !== "string") return result;

  /* 2️⃣ PREFIXED predicate */
  rdf.match(/([a-zA-Z0-9:_-]+)\s+"([^"]+)"/g)
    ?.forEach(m => {
      const [, field, value] = m.match(/(.+?)\s+"(.+)"/);

      if (field.startsWith("dc:") || field.startsWith("dct:")) return;

      result.fields.push(field);
      result.values.push(value);

      // 🔥 FIELD-LEVEL SENSITIVITY ESCALATION
      const fschema = FIELD_SCHEMA[field];
      if (fschema) {
        result.personalData.push(fschema.personal);
        result.dataCategories.push(fschema.category);
        result.sensitive = true;
      }
    });

  /* 3️⃣ FULL IRI predicate */
  rdf.match(/<https?:\/\/[^>]+>\s+"([^"]+)"/g)
    ?.forEach(m => {
      const [, iri, value] =
        m.match(/<(https?:\/\/[^>]+)>\s+"([^"]+)"/);

      result.fields.push(iri);
      result.values.push(value);

      // 🔥 FIELD-LEVEL SENSITIVITY ESCALATION
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
   AUDIT WRITER (FINAL)
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

  parsed.personalData.forEach(p =>
    ttl += `  dpv:hasPersonalData ${p} ;\n`
  );

  parsed.dataCategories.forEach(c =>
    ttl += `  dpv:hasDataCategory ${c} ;\n`
  );

  parsed.fields.forEach((f, i) => {
    ttl += `  ex:hasDataField "${f}" ;\n`;
    ttl += `  ex:hasDataValue "${parsed.values[i]}" ;\n`;
  });

  ttl += `
  dct:created "${now}"^^xsd:dateTime .
`;

  await fs.appendFile(logFile, ttl);

  console.log(
    "🧾 AUDIT →",
    appName,
    parsed.sensitive ? "🔴 SENSITIVE" : "🟢 NORMAL"
  );
}

/* ===============================
   GATEWAY SERVER
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
          resource: `http://localhost:${GATEWAY_PORT}${target.pathname}`,
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
  console.log(`✅ Solid Gateway @ http://localhost:${GATEWAY_PORT}`);
});
