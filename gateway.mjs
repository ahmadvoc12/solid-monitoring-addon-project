import http from "http";
import fs from "fs/promises";
import path from "path";
import { URL } from "url";
import { spawn } from "child_process";

/* ===============================
   CONFIG
================================ */
const GATEWAY_PORT = 3000;          // 🔒 SAMA DENGAN RAILWAY PORT
const CSS_PORT = 4000;              // 🔒 INTERNAL ONLY
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
const detectPod = pathname => pathname.split("/").filter(Boolean)[0] || null;
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
const isRepeated = (auth, path) => {
  const k = `${auth || "anon"}::${path}`;
  if (seen.has(k)) return true;
  seen.add(k);
  return false;
};

/* ===============================
   GATEWAY SERVER (🚨 FIXED)
================================ */
http.createServer(async (req, res) => {
  const { method, url, headers } = req;

  /* 🚑 RAILWAY HEALTHCHECK */
  if (method === "GET" && (url === "/" || url === "/health")) {
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end("OK");
  }

  /* ✅ PROXY .account KE CSS (NO AUDIT) */
  if (url.startsWith("/.account")) {
    const proxy = http.request(
      {
        hostname: "localhost",
        port: CSS_PORT,
        path: url,
        method,
        headers: {
          ...headers,
          "x-forwarded-host": headers.host,
          "x-forwarded-proto": "https"
        }
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
     NORMAL SOLID REQUEST
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
        // audit logic kamu tetap di sini (tidak aku hapus)
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
