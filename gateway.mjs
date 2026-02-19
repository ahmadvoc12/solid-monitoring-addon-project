import http from "http";
import fs from "fs/promises";
import path from "path";
import { URL } from "url";
import { spawn } from "child_process";

// ODRL Components
import { ODRLPolicyEngine } from './odrl/policy-engine.mjs';
import { EvaluationRequestBuilder } from './odrl/request-builder.mjs';
import { StateOfTheWorldProvider } from './odrl/context-provider.mjs';
import { ComplianceReporter } from './odrl/compliance-reporter.mjs';
import { getAccessCounter } from './odrl/access-counter.mjs';

/* ===============================
   CONFIG (SESUAI RAILWAY)
   ✅ FIX: Definisikan GATEWAY_BASE (sebelumnya hanya PUBLIC_BASE_URL)
================================ */
const GATEWAY_PORT = 3000;           // ✅ SESUAI RAILWAY
const CSS_PORT = 4000;               // ✅ INTERNAL CSS PORT
const PUBLIC_BASE_URL = "https://solid-monitoring-addon-project-production.up.railway.app"; // ✅ Trim trailing spaces

// ✅ FIX: GATEWAY_BASE harus didefinisikan untuk spawn CSS server
const GATEWAY_BASE = PUBLIC_BASE_URL;  // ✅ Gunakan PUBLIC_BASE_URL yang sudah di-trim

const DATA_ROOT = path.resolve(process.cwd(), ".data");
const AUDIT_ACCESS_PATH = "private/audit/access";
const AUDIT_MONITORING_PATH = "private/audit/monitoring";
const AUDIT_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];

// ✅ FIX: Policy location sama dengan access-log.ttl
const POLICY_PATH = "private/audit/access/monitor-policy.ttl";
const POLICY_ACL_PATH = "private/audit/access/monitor-policy.ttl.acl";

/* ===============================
   SENSITIVE FIELD CONFIGURATION
   ✅ FIX: HAPUS SEMUA trailing spaces di IRI keys (KRUSIAL untuk matching!)
================================ */
const SENSITIVE_FIELDS = {
  "<https://schema.org/bloodType>": {  // ✅ Tanpa trailing space
    asset: "ex:blood-type",
    label: "Blood Type",
    protectedByPolicy: "bloodTypeAccess",
    personalData: "dpv:HealthData",
    dataCategory: "dpv:SpecialCategoryPersonalData",
    sensitive: true
  }
};

const NON_SENSITIVE_FIELDS = {
  "<http://purl.org/dc/terms/created>": {
    label: "Created Timestamp",
    sensitive: false
  },
  "<https://schema.org/identifier>": {  // ✅ Tanpa trailing space
    label: "Identifier",
    sensitive: false
  }
};

/* ===============================
   ✅ FIELD NORMALIZATION
================================ */
function normalizeField(field) {
  if (!field) return field;
  let normalized = field.replace(/<\s*/, '<').replace(/\s*>/, '>');
  const match = normalized.match(/<(https?:\/\/[^>]+)>/);
  if (match) {
    const iri = match[1].replace(/\s+$/, '');
    normalized = `<${iri}>`;
  }
  return normalized;
}

/* ===============================
   REQUEST DEDUPLICATION
================================ */
const requestCache = new Map();

function shouldCountRequest(pod, app, field, timestamp) {
  const normalizedField = normalizeField(field);
  const key = `${pod}::${app}::${normalizedField}::${timestamp.substring(0, 19)}`;
  
  if (requestCache.has(key)) {
    console.log(`ℹ️ Skipping duplicate request: ${normalizedField}`);
    return false;
  }
  requestCache.set(key, Date.now());
  const now = Date.now();
  for (const [k, time] of requestCache.entries()) {
    if (now - time > 10000) requestCache.delete(k);
  }
  return true;
}

/* ===============================
   ODRL COMPONENTS INITIALIZATION
================================ */
const policyEngine = new ODRLPolicyEngine();
const requestBuilder = new EvaluationRequestBuilder();
const sotwProvider = new StateOfTheWorldProvider(DATA_ROOT);
const complianceReporter = new ComplianceReporter();
const accessCounter = getAccessCounter(DATA_ROOT);

/* ===============================
   📄 POLICY TTL CONTENT (INLINE)
   ✅ FIX: HAPUS SEMUA trailing spaces di IRI values
================================ */
const MONITOR_POLICY_TTL = `@prefix odrl: <http://www.w3.org/ns/odrl/2/> .
@prefix dpv: <https://w3id.org/dpv#> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix ex: <https://example.org/> .

ex:policy-blood-type a odrl:Policy ;
    odrl:uid <https://pod.example/policies/blood-type-policy> ;
    dct:created "2026-02-13T09:00:00Z"^^xsd:dateTime ;
    dct:creator ex:pod-owner ;
    odrl:profile <https://w3id.org/dpv/odrl> ;
    odrl:target ex:blood-type ;
    odrl:permission [
        odrl:assigner ex:pod-owner ;
        odrl:assignee ex:any-app ;
        odrl:action odrl:read ;
        odrl:constraint [
            odrl:leftOperand odrl:count ;
            odrl:operator odrl:lteq ;
            odrl:rightOperand "1"^^xsd:integer
        ]
    ] ;
    odrl:prohibition [
        odrl:action odrl:distribute ;
        odrl:assignee ex:any-app
    ] .
`;

/* ===============================
   🔐 ACL CONTENT FOR POLICY FILE (INLINE)
================================ */
function getPolicyACLContent(podBaseUrl) {
  return `@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<#owner>
    a acl:Authorization ;
    acl:agent <${podBaseUrl}profile/card#me> ;
    acl:accessTo <monitor-policy.ttl> ;
    acl:mode acl:Read, acl:Write, acl:Control .

<#authenticated-read>
    a acl:Authorization ;
    acl:agentClass foaf:AuthenticatedAgent ;
    acl:accessTo <monitor-policy.ttl> ;
    acl:mode acl:Read .
`;
}

/* ===============================
   ✅ FIX: Helper fetch dengan timeout + AbortController
================================ */
async function fetchWithTimeout(url, options = {}, timeoutMs = 5000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  
  try {
    const res = await fetch(url, {
      ...options,
      signal: controller.signal
    });
    return res;
  } finally {
    clearTimeout(timeout);
  }
}

/* ===============================
   ✅ CREATE POLICY FILE LOCALLY (fallback)
================================ */
async function savePolicyLocally(podName, policyContent) {
  const policyDir = path.join(DATA_ROOT, podName, AUDIT_ACCESS_PATH);
  const policyFile = path.join(policyDir, 'monitor-policy.ttl');
  
  await fs.mkdir(policyDir, { recursive: true });
  
  try {
    await fs.access(policyFile);
    console.log(`✅ Local policy already exists: ${policyFile}`);
    return false;
  } catch {
    await fs.writeFile(policyFile, policyContent);
    console.log(`🎯 Local policy saved: ${policyFile}`);
    return true;
  }
}

/* ===============================
   ✅ CREATE ACL FILE LOCALLY (untuk fallback)
================================ */
async function createPolicyACLLocal(podName, podBaseUrl) {
  const aclDir = path.join(DATA_ROOT, podName, AUDIT_ACCESS_PATH);
  const aclFile = path.join(aclDir, 'monitor-policy.ttl.acl');
  
  await fs.mkdir(aclDir, { recursive: true });
  
  const aclContent = getPolicyACLContent(podBaseUrl);

  try {
    await fs.access(aclFile);
    console.log(`✅ Local ACL already exists: ${aclFile}`);
    return false;
  } catch {
    await fs.writeFile(aclFile, aclContent);
    console.log(`🎯 Local ACL saved: ${aclFile}`);
    return true;
  }
}

/* ===============================
   ✅ CREATE ACL REMOTELY (untuk pod)
================================ */
async function createPolicyACLRemote(podBaseUrl, authToken) {
  try { 
    new URL(podBaseUrl); 
  } catch (e) {
    console.warn(`⚠️ Invalid podBaseUrl for ACL: ${podBaseUrl}`);
    return false;
  }
  if (!podBaseUrl.endsWith('/')) podBaseUrl += '/';
  
  const aclUrl = new URL(POLICY_PATH + '.acl', podBaseUrl).href;
  const aclContent = getPolicyACLContent(podBaseUrl);

  try {
    const res = await fetchWithTimeout(aclUrl, {
      method: 'PUT',
      headers: {
        'Authorization': authToken,
        'Content-Type': 'text/turtle'
      },
      body: aclContent
    }, 3000);
    
    if (res.ok || res.status === 201 || res.status === 409) {
      console.log(`✅ ACL created/confirmed for policy: ${aclUrl}`);
      return true;
    }
    console.warn(`⚠️ ACL creation returned ${res.status} (continuing)`);
    return false;
  } catch (error) {
    console.warn(`⚠️ Could not create remote ACL (continuing): ${error.message}`);
    return false;
  }
}

/* ===============================
   ✅ DEPLOY POLICY TO POD (INLINE)
================================ */
async function deployPolicyToPod(podBaseUrl, authToken) {
  try { 
    new URL(podBaseUrl); 
  } catch (e) {
    throw new Error(`Invalid podBaseUrl: "${podBaseUrl}"`);
  }
  if (!podBaseUrl.endsWith('/')) podBaseUrl += '/';
  
  console.log(`🔍 Deploying policy to pod: ${podBaseUrl}`);
  
  const policyUrl = new URL(POLICY_PATH, podBaseUrl).href;
  console.log(`📄 Policy URL: ${policyUrl}`);
  
  try {
    const headRes = await fetchWithTimeout(policyUrl, {
      method: 'HEAD',
      headers: { 
        'Authorization': authToken,
        'Accept': 'text/turtle'
      }
    }, 3000);
    
    console.log(`📡 HEAD response: ${headRes.status}`);
    
    if (headRes.status === 200 || headRes.status === 204) {
      console.log(`✅ Policy already exists at ${policyUrl}`);
      await createPolicyACLRemote(podBaseUrl, authToken);
      return { deployed: false, url: policyUrl, reason: 'already_exists' };
    }
    
    console.log(`📤 PUT ${policyUrl}`);
    const putRes = await fetchWithTimeout(policyUrl, {
      method: 'PUT',
      headers: {
        'Authorization': authToken,
        'Content-Type': 'text/turtle',
        'Slug': 'monitor-policy.ttl',
        'Link': '<http://www.w3.org/ns/ldp#Resource>; rel="type"'
      },
      body: MONITOR_POLICY_TTL
    }, 5000);
    
    console.log(`📥 PUT response: ${putRes.status}`);
    
    if (!putRes.ok) {
      const errText = await putRes.text().catch(() => 'No error body');
      console.error(`❌ PUT failed: ${putRes.status} - ${errText}`);
      throw new Error(`Failed to deploy policy: ${putRes.status} ${errText}`);
    }
    
    await createPolicyACLRemote(podBaseUrl, authToken);
    
    console.log(`✅ Policy deployed successfully to ${policyUrl}`);
    return { deployed: true, url: policyUrl, status: putRes.status };
    
  } catch (error) {
    if (error.name === 'AbortError') {
      console.error(`❌ Fetch timeout deploying policy to ${policyUrl}`);
    } else {
      console.error(`❌ Error deploying policy to pod:`, error.message);
    }
    throw error;
  }
}

/* ===============================
   ✅ LOAD POLICY FROM POD (INLINE)
================================ */
async function loadPolicyFromPod(podBaseUrl, authToken) {
  try { 
    new URL(podBaseUrl); 
  } catch (e) {
    throw new Error(`Invalid podBaseUrl: "${podBaseUrl}"`);
  }
  
  const policyUrl = new URL(POLICY_PATH, podBaseUrl).href;
  
  try {
    const res = await fetchWithTimeout(policyUrl, {
      headers: { 
        'Authorization': authToken,
        'Accept': 'text/turtle' 
      }
    }, 3000);
    
    if (!res.ok) {
      throw new Error(`Failed to fetch policy: ${res.status}`);
    }
    
    const ttlContent = await res.text();
    console.log(`✅ Policy loaded from pod: ${policyUrl}`);
    return ttlContent;
    
  } catch (error) {
    if (error.name === 'AbortError') {
      console.error(`❌ Fetch timeout loading policy from ${policyUrl}`);
    } else {
      console.error(`❌ Error loading policy from pod:`, error.message);
    }
    throw error;
  }
}

/* ===============================
   ✅ PARSE CONSTRAINT FROM TTL
================================ */
function parseConstraintFromTTL(ttlContent) {
  try {
    const countMatch = ttlContent.match(/odrl:leftOperand\s+odrl:count[^;]+odrl:rightOperand\s+"?(\d+)"?/);
    if (countMatch && countMatch[1]) {
      const maxCount = parseInt(countMatch[1], 10);
      console.log(`✅ Parsed dynamic constraint: max ${maxCount} accesses`);
      return maxCount;
    }
    return 3;
  } catch {
    return 3;
  }
}

/* ===============================
   🔥 PARSE CONSTRAINT DYNAMICALLY FROM policy file
================================ */
async function parseConstraintFromPolicy(podName) {
  const policyFile = path.join(DATA_ROOT, podName, POLICY_PATH);

  try {
    const content = await fs.readFile(policyFile, 'utf-8');

    const match = content.match(
      /odrl:leftOperand\s+odrl:count[\s\S]*?odrl:rightOperand\s+"(\d+)"\^\^xsd:integer/
    );

    if (match && match[1]) {
      const maxCount = parseInt(match[1], 10);
      console.log(`✅ Dynamic constraint parsed: max ${maxCount} accesses`);
      return maxCount;
    }

    console.warn("⚠️ No constraint found in policy, using default = 3");
    return 3;

  } catch (err) {
    console.warn("⚠️ Could not read policy file, using default = 3");
    return 3;
  }
}

/* ===============================
   🔄 LOAD POLICIES (Dynamic constraint)
================================ */
async function loadPolicies(podName = null) {
  let maxCount = 3;
  if (podName) maxCount = await parseConstraintFromPolicy(podName);
  
  const policies = {
    bloodTypeAccess: {
      uid: "ex:policy-blood-type",
      permission: {
        action: "odrl:read",
        constraint: {
          leftOperand: "odrl:count",
          operator: "odrl:lteq",
          rightOperand: maxCount
        },
        targetAsset: "ex:blood-type"
      },
      prohibition: { action: "odrl:distribute" }
    }
  };
  
  policyEngine.loadPolicies(policies);
  console.log(`✅ ODRL Policies loaded (constraint: max ${maxCount} accesses)`);
  return maxCount;
}

/* ===============================
   🚀 DEPLOY POLICY (Fire-and-forget - TIDAK BLOCKING)
================================ */
const deployedPods = new Set();
const deployingPods = new Set();

function isValidPodName(podName) {
  if (!podName) return false;
  if (['.oidc', '.well-known', '.acl', 'private', 'public'].includes(podName)) return false;
  return /^[a-z0-9][a-z0-9-]{2,}$/.test(podName);
}

function buildPodBaseUrl(podName) {
  return new URL(`/${podName}/`, GATEWAY_BASE).href;
}

async function ensurePolicyDeployed(podName, authToken) {
  if (!isValidPodName(podName)) return false;
  if (deployedPods.has(podName)) return true;
  
  if (deployingPods.has(podName)) {
    return true;
  }
  
  deployingPods.add(podName);
  
  (async () => {
    try {
      const podBaseUrl = buildPodBaseUrl(podName);
      
      let formattedAuth = authToken;
      if (authToken && !authToken.startsWith('DPoP ')) {
        formattedAuth = `DPoP ${authToken}`;
      }
      
      const result = await deployPolicyToPod(podBaseUrl, formattedAuth);
      if (result?.deployed) {
        console.log(`🎯 Policy deployed to ${podBaseUrl}${POLICY_PATH}`);
        await loadPolicies(podName);
      }
    } catch (error) {
      console.log(`🔄 Remote deploy failed, using local fallback for ${podName}`);
      
      await savePolicyLocally(podName, MONITOR_POLICY_TTL);
      
      const podBaseUrl = buildPodBaseUrl(podName);
      await createPolicyACLLocal(podName, podBaseUrl);
      
      await loadPolicies(podName);
    } finally {
      deployingPods.delete(podName);
      deployedPods.add(podName);
    }
  })();
  
  return true;
}

/* ===============================
   START SOLID CSS
   ✅ FIX: Gunakan GATEWAY_BASE yang sudah didefinisikan
================================ */
spawn(
  "node",
  [
    "./bin/server.js",
    "-c", "config/file.json",
    "-f", DATA_ROOT,
    "-p", String(CSS_PORT),
    "--baseUrl", GATEWAY_BASE  // ✅ Sekarang GATEWAY_BASE sudah terdefinisi!
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
   REQUEST FILTERS
================================ */
const isAuthenticated = h => !!h.authorization;
const isSystem = p =>
  p.startsWith("/.well-known") ||
  p.startsWith("/.oidc") ||
  p.endsWith(".acl") ||
  p.includes("/private/audit/") ||
  p.includes("/private/odrl/");

/* ===============================
   ✅ EXTRACT SENSITIVE FIELDS
================================ */
function extractSensitiveFields(rdf) {
  if (!rdf || typeof rdf !== "string") return [];
  const sensitiveFields = new Set();
  const fullIRIMatch = rdf.match(/<https?:\/\/[^>]+>\s+"([^"]+)"/g);
  if (fullIRIMatch) {
    fullIRIMatch.forEach(m => {
      const match = m.match(/<(https?:\/\/[^>]+)>\s+"([^"]+)"/);
      if (match) {
        const iri = match[1];
        const value = match[2];
        if (value && value.trim()) {
          const normalizedIRI = normalizeField(`<${iri}>`);
          if (SENSITIVE_FIELDS[normalizedIRI]) {
            sensitiveFields.add(normalizedIRI);
          }
        }
      }
    });
  }
  return Array.from(sensitiveFields);
}

/* ===============================
   ✅ EXTRACT PERSONAL DATA - RESTORE DETAILED LOGGING
================================ */
function extractPersonalData(rdf) {
  const result = {
    personalData: [], dataCategories: [], fields: [], values: [],
    sensitive: false, sensitiveFields: [], nonSensitiveFields: []
  };
  if (!rdf || typeof rdf !== "string") return result;

  rdf.match(/<https?:\/\/[^>]+>\s+"([^"]+)"/g)?.forEach(m => {
    const match = m.match(/<(https?:\/\/[^>]+)>\s+"([^"]+)"/);
    if (!match) return;
    const iri = match[1];
    const value = match[2];
    const normalizedIRI = normalizeField(`<${iri}>`);
    
    result.fields.push(normalizedIRI);
    result.values.push(value);
    
    if (SENSITIVE_FIELDS[normalizedIRI]) {
      result.personalData.push(SENSITIVE_FIELDS[normalizedIRI].personalData);
      result.dataCategories.push(SENSITIVE_FIELDS[normalizedIRI].dataCategory);
      result.sensitive = true;
      result.sensitiveFields.push(normalizedIRI);
    } else if (NON_SENSITIVE_FIELDS[normalizedIRI]) {
      result.nonSensitiveFields.push(normalizedIRI);
    }
  });
  return result;
}

/* ===============================
   ACCESS LOG & SOTW - RESTORE DETAILED LOGGING
================================ */
async function ensureAccessLogFile(pod) {
  const dir = path.join(DATA_ROOT, pod, AUDIT_ACCESS_PATH);
  const file = path.join(dir, "access-log.ttl");
  await fs.mkdir(dir, { recursive: true });
  try { await fs.access(file); } catch {
    await fs.writeFile(file, `@prefix ex: <https://example.org/> .\nex:access-log a <http://www.w3.org/ns/prov#Collection> .\n`);
  }
  return file;
}

async function ensureSotWFile(pod) {
  const dir = path.join(DATA_ROOT, pod, AUDIT_MONITORING_PATH);
  const file = path.join(dir, "state-of-world.ttl");
  await fs.mkdir(dir, { recursive: true });
  try { await fs.access(file); } catch {
    await fs.writeFile(file, `@prefix ex: <https://example.org/> .\nex:sotw-current a <https://w3id.org/force/sotw#SotW> .\n`);
  }
  return file;
}

/* ===============================
   ✅ WRITE ACCESS LOG - RESTORE DETAILED LOGGING
================================ */
async function writeAccessLog({ pod, evalRequest, decision, sensitiveFields, 
  violationType = null, personalData = null, method = "GET", resource = "" }) {
  
  if (sensitiveFields.length === 0 && decision.permitted) return;
  
  const logFile = await ensureAccessLogFile(pod);
  const accessId = `access-${Date.now()}`;
  const timestamp = new Date().toISOString();
  const app = evalRequest?.appName || resource.split('/').filter(Boolean)[2] || "unknown";
  const decisionStr = decision.permitted ? "ALLOWED" : "VIOLATION";
  
  let ttl = `
# Individual access record
ex:${accessId} a <http://www.w3.org/ns/prov#Activity> ;
    <http://www.w3.org/ns/prov#startedAtTime> "${timestamp}"^^<http://www.w3.org/2001/XMLSchema#dateTime> ;
    <http://www.w3.org/ns/prov#wasAssociatedWith> ex:${app} ;
    <https://w3id.org/force/compliance-report#decision> "${decisionStr}" .\n`;
  
  if (!decision.permitted && violationType) {
    ttl += `ex:${accessId} <https://w3id.org/force/compliance-report#violationType> "${violationType}" .\n`;
  }
  
  if (personalData && personalData.sensitive) {
    const dpvId = `log-${Date.now()}`;
    ttl += `
# DPV Personal Data Handling
${dpvId} a <https://w3id.org/dpv#PersonalDataHandling> ;
    <https://w3id.org/dpv#hasProcessing> ${method === "GET" ? "<https://w3id.org/dpv#Access>" : "<https://w3id.org/dpv#Create>"} ;
    <https://w3id.org/dpv#hasResource> <${resource}> ;
    <https://w3id.org/force/compliance-report#accessedByApp> "${app}" ;
    <https://w3id.org/force/compliance-report#containsSensitiveData> "${personalData.sensitive}"^^<http://www.w3.org/2001/XMLSchema#boolean> ;
    <https://w3id.org/force/compliance-report#sensitiveFieldCount> "${personalData.sensitiveFields.length}"^^<http://www.w3.org/2001/XMLSchema#integer> ;
    <https://w3id.org/force/compliance-report#nonSensitiveFieldCount> "${personalData.nonSensitiveFields.length}"^^<http://www.w3.org/2001/XMLSchema#integer> .\n`;
    
    personalData.fields.forEach((f, i) => {
      const isSensitive = personalData.sensitiveFields.includes(f);
      ttl += `${dpvId} <https://w3id.org/force/compliance-report#hasDataField> "${f}" ;\n`;
      ttl += `${dpvId} <https://w3id.org/force/compliance-report#hasDataValue> "${personalData.values[i].replace(/"/g, '\\"')}" ;\n`;
      ttl += `${dpvId} <https://w3id.org/force/compliance-report#isSensitive> "${isSensitive}"^^<http://www.w3.org/2001/XMLSchema#boolean> .\n`;
    });
  }
  
  await fs.appendFile(logFile, ttl);
  
  const status = decision.permitted ? "✅ ACCESS ALLOWED" : "⚠️ POLICY VIOLATION (allowed)";
  const fields = sensitiveFields.length > 0 ? sensitiveFields.join(', ') : 'none';
  
  console.log(`${status} | App: ${app} | Fields: ${fields} | Reason: ${decision.reason}`);
  
  if (personalData) {
    console.log(`   📊 Data: ${personalData.sensitiveFields.length} sensitif, ${personalData.nonSensitiveFields.length} non-sensitif`);
    if (personalData.sensitiveFields.length > 0) {
      console.log(`   🔒 Sensitive: ${personalData.sensitiveFields.join(', ')}`);
    }
    if (personalData.nonSensitiveFields.length > 0) {
      console.log(`   📋 Non-sensitive: ${personalData.nonSensitiveFields.join(', ')}`);
    }
  }
}

async function updateSotW(pod, app, field, countData = null, decision = "ALLOWED") {
  const sotwFile = await ensureSotWFile(pod);
  let content = await fs.readFile(sotwFile, 'utf-8');
  const now = new Date().toISOString();
  
  if (!content.includes('ex:sotw-blood-type') && countData) {
    content += `\nex:sotw-blood-type <https://w3id.org/force/sotw#target> <ex:blood-type> ;\n    <https://w3id.org/force/sotw#count> "${countData.count}"^^<http://www.w3.org/2001/XMLSchema#integer> .\n`;
    await fs.writeFile(sotwFile, content);
  }
  console.log(`📊 SotW updated (${decision}): ${field || 'none'} | Count: ${countData?.count || 'N/A'}`);
}

/* ===============================
   ✅ BUILD SOTW WITH COUNT
================================ */
async function buildSotWWithCount(pod, evalRequest, pathname, sensitiveFields) {
  const sotw = await sotwProvider.build(pod, evalRequest, pathname, sensitiveFields);
  const app = extractAppName(pathname);
  const countState = {};
  for (const field of sensitiveFields) {
    const normalizedField = normalizeField(field);
    const countData = accessCounter.get(pod, app, normalizedField) || { count: 0 };
    countState[normalizedField] = countData;
  }
  sotw.count = countState;
  return sotw;
}

/* ===============================
   🔥 INCREMENT COUNT BEFORE EVALUATION (VIOLATION DETECTION)
================================ */
async function incrementAndEvaluate(pod, app, sensitiveFields, evalRequest, pathname) {
  for (const fld of sensitiveFields) {
    const normalizedField = normalizeField(fld);
    if (SENSITIVE_FIELDS[normalizedField]) {
      const now = new Date().toISOString();
      if (shouldCountRequest(pod, app, normalizedField, now)) {
        await sotwProvider.incrementAccessCount(pod, app, normalizedField);
        console.log(`📈 Count incremented BEFORE eval: ${normalizedField}`);
      }
    }
  }
  
  const sotw = await buildSotWWithCount(pod, evalRequest, pathname, sensitiveFields);
  return policyEngine.evaluate(evalRequest, sotw, sensitiveFields);
}

/* ===============================
   GATEWAY SERVER (MONITORING MODE)
================================ */
http.createServer(async (req, res) => {
  const { method, url, headers } = req;
  
  if (method === "GET" && (url === "/" || url === "/health")) {
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end("OK");
  }

  const target = new URL(url, GATEWAY_BASE);
  const pod = detectPod(target.pathname);
  let body = "";
  for await (const c of req) body += c;

  if (isAuthenticated(headers) && pod && isValidPodName(pod) && !deployedPods.has(pod)) {
    await ensurePolicyDeployed(pod, headers.authorization);
  }

  // ✅ Proxy ke CSS - untuk Railway, gunakan localhost karena CSS berjalan di container yang sama
  const proxy = http.request({
    hostname: "127.0.0.1",  // ✅ CSS berjalan di localhost:4000 dalam container yang sama
    port: CSS_PORT,
    path: url,
    method,
    headers: { ...headers }
  }, async pres => {
    let resp = "";
    for await (const c of pres) resp += c;

    if (method === "GET" && isAuthenticated(headers) && !isSystem(target.pathname)) {
      try {
        const sensitiveFields = extractSensitiveFields(resp);
        
        if (sensitiveFields.length > 0) {
          const evalRequest = requestBuilder.buildFromHttpRequest(req, target.pathname, pod);
          
          for (const fld of sensitiveFields) {
            const normalizedField = normalizeField(fld);
            if (SENSITIVE_FIELDS[normalizedField]) {
              const now = new Date().toISOString();
              if (shouldCountRequest(pod, extractAppName(target.pathname), normalizedField, now)) {
                await sotwProvider.incrementAccessCount(pod, extractAppName(target.pathname), normalizedField);
                console.log(`📈 Count incremented: ${normalizedField}`);
              }
            }
          }
          
          const sotw = await buildSotWWithCount(pod, evalRequest, target.pathname, sensitiveFields);
          const decisionResult = policyEngine.evaluate(evalRequest, sotw, sensitiveFields);
          
          const personalData = extractPersonalData(resp);
          await writeAccessLog({ 
            pod, evalRequest, decision: decisionResult, sensitiveFields,
            violationType: decisionResult.violatedConstraints[0]?.violationType,
            personalData, method, resource: `${GATEWAY_BASE}${target.pathname}` 
          });
          
          if (!decisionResult.permitted) {
            console.log('⚠️ POLICY VIOLATION DETECTED (access allowed):', decisionResult.reason);
          }
        }
      } catch (error) {
        console.error('⚠️ ODRL evaluation skipped (response):', error.message);
      }
    }
    
    res.writeHead(pres.statusCode, pres.headers);
    res.end(resp);
  });

  proxy.on('error', (err) => {
    console.error('❌ Proxy error:', err.message);
    if (!res.headersSent) {
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Bad Gateway", message: err.message }));
    }
  });

  if (body) proxy.write(body);
  proxy.end();
  
}).listen(GATEWAY_PORT, async () => {
  await loadPolicies();
  console.log(`\n✅ Solid Gateway with ODRL (MONITORING MODE) @ ${GATEWAY_BASE}`);
  console.log(`📊 Violation Detection: Count incremented BEFORE evaluation`);
  console.log(`   • Constraint: Max N accesses (parsed from ${POLICY_PATH})`);
  console.log(`   • Mode: MONITORING (violations logged but NOT blocked)`);
  console.log(`💾 Access Counter: ${accessCounter.getStats().totalEntries} entries\n`);
  
  accessCounter.resetPod('ayobisa2');
  console.log('✅ Access counter reset - Count starts from 0');
  console.log('🎯 Test: Access ke-4 akan log "VIOLATION" (count=4 > max=3)\n');
});