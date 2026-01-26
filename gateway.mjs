import http from "http";
import fs from "fs/promises";
import path from "path";
import { URL } from "url";
import { spawn } from "child_process";

/* ===============================
   CONFIG (RAILWAY SAFE)
================================ */
const GATEWAY_PORT = process.env.PORT || 3001; // Railway injects PORT
const CSS_PORT = process.env.CSS_PORT || 3000;

const DATA_ROOT = path.resolve(".data");
const AUDIT_SUBPATH = "private/audit/access";

const AUDIT_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];

/* ===============================
   START SOLID CSS
================================ */
spawn(
  "node",
  [
    "./bin/server.js",
    "-c",
    "config/file.json",
    "-f",
    "./.data",
    "-p",
    String(CSS_PORT),
    "--baseUrl",
    `http://localhost:${GATEWAY_PORT}`
  ],
  { stdio: "inherit" }
);

/* ===============================
   UTIL
================================ */
function detectPod(pathname) {
  const seg = pathname.split("/").filter(Boolean);
  return seg.length ? seg[0] : null;
}

function isAuditResource(pathname) {
  return pathname.includes("/private/audit/");
}

/* ===============================
   ENSURE AUDIT LOG
================================ */
async function ensureAuditLog(pod) {
  const dir = path.join(DATA_ROOT, pod, AUDIT_SUBPATH);
  const file = path.join(dir, "log.ttl");

  await fs.mkdir(dir, { recursive: true });

  try {
    await fs.access(file);
  } catch {
    await fs.writeFile(
      file,
      `@prefix dpv: <https://www.w3.org/ns/dpv#> .
@prefix dpv-pd: <https://www.w3.org/ns/dpv/pd#> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix ex: <https://example.org/solid/audit#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

`
    );
    console.log("📝 Created audit log:", file);
  }

  return file;
}

/* ===============================
   SENSITIVE DETECTION (TTL BASED)
================================ */
function detectSensitiveFromTtl(ttl) {
  if (!ttl || typeof ttl !== "string") return null;

  const found = [];

  if (
    ttl.includes("dpv#hasPersonalData") &&
    ttl.includes("dpv/pd#NationalIdentificationNumber")
  ) {
    found.push({
      iri: "<https://www.w3.org/ns/dpv/pd#NationalIdentificationNumber>",
      category: "dpv:HighlySensitivePersonalData"
    });
  }

  if (
    ttl.includes("dpv#hasPersonalData") &&
    ttl.includes("dpv/pd#BloodType")
  ) {
    found.push({
      iri: "<https://www.w3.org/ns/dpv/pd#BloodType>",
      category: "dpv:SpecialCategoryPersonalData"
    });
  }

  return found.length ? found : null;
}

/* ===============================
   AUDIT WRITER
================================ */
async function writeAudit({ pod, method, pathname, headers, resourceBody }) {
  if (!pod) return;
  if (isAuditResource(pathname)) return; // 🔥 STOP LOOP

  const sensitive = detectSensitiveFromTtl(resourceBody);
  const logFile = await ensureAuditLog(pod);

  const id = `log-${Date.now()}`;
  const now = new Date().toISOString();

  const controller =
    headers.origin ||
    headers.referer ||
    "urn:unknown:app";

  const processing =
    method === "GET" ? "dpv:Access" : "dpv:Create";

  let ttl = `
ex:${id}
  a dpv:PersonalDataHandling ;
  dpv:hasDataController <${controller}> ;
  dpv:hasProcessing ${processing} ;
`;

  if (sensitive) {
    for (const s of sensitive) {
      ttl += `  dpv:hasPersonalData ${s.iri} ;\n`;
      ttl += `  dpv:hasDataCategory ${s.category} ;\n`;
    }
    ttl += `  ex:processingType "SensitiveDataAccess" ;\n`;
  } else {
    ttl += `  ex:processingType "NormalDataAccess" ;\n`;
  }

  ttl += `  dct:created "${now}"^^xsd:dateTime .\n`;

  await fs.appendFile(logFile, ttl);

  console.log(
    `🧾 AUDIT: ${pod}`,
    sensitive ? "🔴 SENSITIVE ACCESS" : "🟢 NORMAL ACCESS"
  );
}

/* ===============================
   GATEWAY SERVER
================================ */
http
  .createServer(async (req, res) => {
    const { method, url, headers } = req;

    if (method === "OPTIONS") {
      res.writeHead(204);
      return res.end();
    }

    const targetUrl = new URL(url, `http://localhost:${CSS_PORT}`);
    const pathname = targetUrl.pathname;

    console.log("➡️ GATEWAY HIT:", method, pathname);

    const pod = detectPod(pathname);

    let requestBody = "";
    for await (const chunk of req) requestBody += chunk.toString();

    const proxyReq = http.request(
      {
        hostname: "localhost",
        port: CSS_PORT,
        path: url,
        method,
        headers: {
          ...headers,
          host: `localhost:${GATEWAY_PORT}`
        }
      },
      async proxyRes => {
        let responseBody = "";
        for await (const chunk of proxyRes) responseBody += chunk.toString();

        if (AUDIT_METHODS.includes(method)) {
          await writeAudit({
            pod,
            method,
            pathname,
            headers,
            resourceBody: method === "GET" ? responseBody : requestBody
          }).catch(console.error);
        }

        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        res.end(responseBody);
      }
    );

    if (requestBody) proxyReq.write(requestBody);
    proxyReq.end();
  })
  .listen(GATEWAY_PORT, () => {
    console.log(`✅ Solid Gateway @ http://localhost:${GATEWAY_PORT}`);
    console.log(`🔁 Solid CSS Internal @ http://localhost:${CSS_PORT}`);
  });
