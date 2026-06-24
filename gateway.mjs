import http from "http";
import fs from "fs/promises";
import path from "path";
import { URL } from "url";
import { spawn } from "child_process";

// ODRL Components (modular imports)
import { ODRLPolicyEngine } from './odrl/policy-engine.mjs';
import { EvaluationRequestBuilder } from './odrl/request-builder.mjs';
import { StateOfTheWorldProvider } from './odrl/context-provider.mjs';
import { ComplianceReporter } from './odrl/compliance-reporter.mjs';
import { getAccessCounter } from './odrl/access-counter.mjs';

/* ===============================
CONFIG (SESUAI RAILWAY)
================================ */
const GATEWAY_PORT = 3000;
const CSS_PORT = 4000;
const PUBLIC_BASE_URL = "https://solid-monitoring-addon-project-production.up.railway.app";
const GATEWAY_BASE = PUBLIC_BASE_URL;
const DATA_ROOT = path.resolve(process.cwd(), ".data");
const AUDIT_ACCESS_PATH = "private/audit/access";
const AUDIT_MONITORING_PATH = "private/audit/monitoring";
const AUDIT_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const POLICY_PATH = "private/audit/access/monitor-policy.ttl";
const POLICY_ACL_PATH = "private/audit/access/monitor-policy.ttl.acl";

/* ===============================
✅ GLOBAL CACHE: Track active policy IRIs per pod
================================ */
const activePolicyCache = new Map();

/* ===============================
✅ ACTION HIERARCHY & MAPPING (ODRL 2.2 Compliant)
================================ */
const ACTION_HIERARCHY = {
  'ex:read': 'odrl:use',
  'ex:create': 'odrl:use',
  'ex:update': 'odrl:use',
  'ex:delete': 'odrl:transfer',
  'odrl:use': null,
  'odrl:transfer': null,
};

function actionIncludedIn(actionA, actionB) {
  if (!actionA || !actionB) return false;
  let current = cleanIRI(actionA);
  const target = cleanIRI(actionB);
  if (current === target) return true;
  while (current && ACTION_HIERARCHY[current]) {
    const parent = cleanIRI(ACTION_HIERARCHY[current]);
    if (parent === target) return true;
    current = parent;
  }
  return false;
}

function httpMethodToOdrlAction(method, pathname = '', body = null) {
  const m = (method || 'GET').toUpperCase();
  if (m === 'POST') return 'ex:create';
  if (m === 'PUT' || m === 'PATCH') return 'ex:update';
  if (m === 'DELETE') return 'ex:delete';
  return 'ex:read';
}

function isActionAllowed(requestedAction, policyActions = [], prohibitions = []) {
  for (const prohibited of prohibitions) {
    if (actionIncludedIn(requestedAction, prohibited)) {
      return { allowed: false, reason: 'Action prohibited by policy' };
    }
  }
  const isPermitted = policyActions.some(pa => actionIncludedIn(requestedAction, pa));
  return {
    allowed: isPermitted,
    reason: isPermitted ? undefined : 'Action not permitted by policy'
  };
}

/* ===============================
✅ NEW: RECIPIENT & TEMPORAL CONSTRAINT EVALUATORS
================================ */

/**
 * Extract WebID from Solid-OIDC authorization header
 * Supports: DPoP token, Bearer token, or direct WebID
 */
function extractWebIdFromRequest(req) {
  const authHeader = req.headers?.authorization;
  if (!authHeader) return null;
  
  // Check for custom X-WebID header (for testing)
  const webIdHeader = req.headers?.['x-webid'];
  if (webIdHeader) return cleanIRI(webIdHeader);
  
  // Parse DPoP or Bearer token (simplified - in production use JWT decode)
  // For now, extract from token payload if available
  const tokenMatch = authHeader.match(/(?:DPoP|Bearer)\s+(.+)/i);
  if (tokenMatch?.[1]) {
    try {
      // Decode JWT payload (middle part)
      const parts = tokenMatch[1].split('.');
      if (parts.length === 3) {
        const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
        if (payload.webid) return cleanIRI(payload.webid);
        if (payload.sub) return cleanIRI(payload.sub);
      }
    } catch (e) {
      // Token decode failed, continue
    }
  }
  
  return null;
}

/**
 * ✅ Evaluate recipient constraint (odrl:assignee)
 * Returns { allowed: boolean, reason?: string }
 */
function evaluateRecipientConstraint(constraint, requesterWebId) {
  if (!constraint?.rightOperand) {
    return { allowed: true, reason: 'No recipient constraint' };
  }
  
  const allowedAssignee = cleanIRI(constraint.rightOperand);
  
  // If no WebID provided, reject
  if (!requesterWebId) {
    return { 
      allowed: false, 
      reason: `Recipient constraint requires WebID. Allowed: ${allowedAssignee}` 
    };
  }
  
  const cleanRequester = cleanIRI(requesterWebId);
  
  // Check if requester matches allowed assignee
  if (cleanRequester === allowedAssignee) {
    return { allowed: true, reason: 'Recipient authorized' };
  }
  
  // Check if allowed assignee is wildcard (any-app)
  if (allowedAssignee.includes('any-app') || allowedAssignee === '*') {
    return { allowed: true, reason: 'Wildcard recipient' };
  }
  
  return { 
    allowed: false, 
    reason: `Recipient violation: ${cleanRequester} not authorized. Allowed: ${allowedAssignee}` 
  };
}

/**
 * ✅ Evaluate temporal constraint (odrl:dateTime)
 * Returns { allowed: boolean, reason?: string }
 */
function evaluateTemporalConstraint(constraint) {
  if (!constraint?.rightOperand) {
    return { allowed: true, reason: 'No temporal constraint' };
  }
  
  const operator = cleanIRI(constraint.operator || 'odrl:lteq');
  let policyDate;
  
  try {
    policyDate = new Date(constraint.rightOperand);
    if (isNaN(policyDate.getTime())) {
      return { allowed: true, reason: 'Invalid temporal constraint date' };
    }
  } catch (e) {
    return { allowed: true, reason: 'Temporal constraint parse error' };
  }
  
  const now = new Date();
  
  if (operator === 'odrl:lteq' || operator.includes('lteq')) {
    // Valid UNTIL policyDate
    if (now <= policyDate) {
      return { allowed: true, reason: `Valid until ${policyDate.toISOString()}` };
    }
    return { 
      allowed: false, 
      reason: `Temporal violation: Access expired. Valid until ${policyDate.toISOString()}, now ${now.toISOString()}` 
    };
  }
  
  if (operator === 'odrl:gteq' || operator.includes('gteq')) {
    // Valid FROM policyDate
    if (now >= policyDate) {
      return { allowed: true, reason: `Valid from ${policyDate.toISOString()}` };
    }
    return { 
      allowed: false, 
      reason: `Temporal violation: Access not yet valid. Valid from ${policyDate.toISOString()}, now ${now.toISOString()}` 
    };
  }
  
  return { allowed: true, reason: 'Unknown temporal operator' };
}

/* ===============================
SENSITIVE FIELD CONFIGURATION
================================ */
const SENSITIVE_FIELDS = {
  "<https://schema.org/bloodType>": {
    asset: "https://schema.org/bloodType",
    assetLabel: "Blood Type",
    protectedByPolicy: "bloodTypeAccess",
    personalData: "dpv:HealthData",
    dataCategory: "dpv:SpecialCategoryPersonalData",
    sensitive: true
  },
  "<https://schema.org/identifier>": {
    asset: "https://schema.org/identifier",
    assetLabel: "Identifier",
    protectedByPolicy: "identityAccess",
    personalData: "dpv:PersonalIdentifier",
    dataCategory: "dpv:PersonalData",
    sensitive: true
  },
  "<https://schema.org/email>": {
    asset: "https://schema.org/email",
    assetLabel: "Email",
    protectedByPolicy: "emailAccess",
    personalData: "dpv:Contact",
    dataCategory: "dpv:IdentifyingPersonalData",
    sensitive: true
  },
  "<https://schema.org/name>": {
    asset: "https://schema.org/name",
    assetLabel: "Name",
    protectedByPolicy: "nameAccess",
    personalData: "dpv:IdentifyingPersonalData",
    dataCategory: "dpv:IdentifyingPersonalData",
    sensitive: false
  },
  "<https://schema.org/birthDate>": {
    asset: "https://schema.org/birthDate",
    assetLabel: "Birth Date",
    protectedByPolicy: "birthDateAccess",
    personalData: "dpv:Demographic",
    dataCategory: "dpv:SpecialCategoryPersonalData",
    sensitive: true
  }
};

const NON_SENSITIVE_FIELDS = {
  "<http://purl.org/dc/terms/created>": {
    label: "Created Timestamp",
    sensitive: false
  }
};

/* ===============================
✅ HELPER FUNCTIONS
================================ */
function cleanIRI(iri) {
  if (!iri || typeof iri !== 'string') return iri || '';
  return iri
    .replace(/\s+>/g, '>')
    .replace(/<\s+/g, '<')
    .replace(/\s+/g, ' ')
    .replace(/^<|>$/g, '')
    .trim();
}

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

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

function getFieldConfig(fieldIRI) {
  const normalized = normalizeField(fieldIRI);
  return SENSITIVE_FIELDS[normalized] || NON_SENSITIVE_FIELDS[normalized] || null;
}

function isSensitiveField(fieldIRI) {
  const config = getFieldConfig(fieldIRI);
  return config?.sensitive === true;
}

function sanitizeTurtleLiteral(str) {
  if (!str) return '';
  return str
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t');
}

function createPolicyAliasMapping(aliasResource, policyResource, uuid) {
  const cleanAlias = cleanIRI(aliasResource);
  const cleanPolicy = cleanIRI(policyResource);
  const cleanUUID = uuid?.replace(/^urn:uuid:/, '') || '';
  return `
${cleanAlias} a <https://w3id.org/force/compliance-report#PolicyAlias> ;
<https://w3id.org/force/compliance-report#mapsToPolicy> ${cleanPolicy} ;
<https://w3id.org/force/compliance-report#mapsToUUID> "${cleanUUID}"^^xsd:string .`;
}

/* ===============================
✅ UPDATED: POLICY METADATA PARSER - Multi-Constraint Support
================================ */
function parsePolicyMetadata(ttlContent) {
  try {
    const metadata = {
      resource: null,
      identifier: null,
      title: null,
      description: null,
      target: null,
      active: true,
      maxCount: 3,
      actions: ['ex:read'],
      prohibitions: ['odrl:distribute'],
      constraintApplicableActions: null,
      // ✅ NEW: Recipient constraint
      recipient: null,
      // ✅ NEW: Temporal constraint
      temporalValidUntil: null,
      temporalValidFrom: null,
    };
    
    // Extract resource
    const resourceMatch = ttlContent.match(/(ex:policy-[^\s;]+)\s+a\s+odrl:Policy/);
    if (resourceMatch?.[1]) metadata.resource = cleanIRI(resourceMatch[1]);
    
    // Extract identifier
    const idMatch = ttlContent.match(/dct:identifier\s+"(urn:uuid:[^"]+)"/);
    if (idMatch?.[1]) metadata.identifier = idMatch[1];
    
    // Extract title & description
    const titleMatch = ttlContent.match(/dct:title\s+"([^"]+)"/);
    if (titleMatch?.[1]) metadata.title = titleMatch[1];
    
    const descMatch = ttlContent.match(/dct:description\s+"([^"]+)"/);
    if (descMatch?.[1]) metadata.description = descMatch[1];
    
    // Extract target
    const targetMatch = ttlContent.match(/odrl:target\s+<([^>]+)>/);
    if (targetMatch?.[1]) metadata.target = cleanIRI(targetMatch[1]);
    
    // Extract policyActive
    const activeMatch = ttlContent.match(
      /<https:\/\/w3id\.org\/force\/compliance-report#policyActive\s*>?\s*("?[^"]+"?\^\^xsd:boolean|true|false)/i
    );
    if (activeMatch?.[1]) {
      const val = activeMatch[1]
        .replace(/"/g, '')
        .replace(/\^\^xsd:boolean/i, '')
        .trim()
        .toLowerCase();
      metadata.active = val === 'true';
    }
    
    // Extract actions from permission blocks
    const permissionBlocks = ttlContent.match(/odrl:permission\s+\[[^\]]+\]/gs) || [];
    const actions = new Set();
    
    permissionBlocks.forEach(block => {
      const actionMatches = block.match(/odrl:action\s+(odrl:[a-z]+|ex:[a-z-]+)/g) || [];
      actionMatches.forEach(match => {
        const action = match.split('odrl:action')[1]?.trim();
        if (action && !action.includes('odrl:distribute')) {
          actions.add(cleanIRI(action));
        }
      });
      
      // ✅ NEW: Extract recipient constraint (odrl:assignee)
      const recipientMatch = block.match(/odrl:leftOperand\s+odrl:assignee[\s\S]*?odrl:rightOperand\s+<?([^>\s;]+)>?/);
      if (recipientMatch?.[1]) {
        metadata.recipient = cleanIRI(recipientMatch[1]);
        console.log(`👤 Recipient constraint found: ${metadata.recipient}`);
      }
      
      // ✅ NEW: Extract temporal constraint (odrl:dateTime)
      const temporalMatch = block.match(/odrl:leftOperand\s+odrl:dateTime[\s\S]*?odrl:rightOperand\s+"?([^"\^]+)"?\^\^xsd:dateTime/);
      if (temporalMatch?.[1]) {
        const opMatch = block.match(/odrl:leftOperand\s+odrl:dateTime[\s\S]*?odrl:operator\s+(odrl:[a-z]+)/);
        const operator = opMatch?.[1] || 'odrl:lteq';
        if (operator.includes('lteq')) {
          metadata.temporalValidUntil = temporalMatch[1].trim();
          console.log(`📅 Temporal constraint (valid until): ${metadata.temporalValidUntil}`);
        } else if (operator.includes('gteq')) {
          metadata.temporalValidFrom = temporalMatch[1].trim();
          console.log(`📅 Temporal constraint (valid from): ${metadata.temporalValidFrom}`);
        }
      }
    });
    
    if (actions.size > 0) {
      metadata.actions = Array.from(actions);
    }
    
    // ✅ NEW: Extract prohibitions (extended: distribute, derive, transfer)
    const prohibitionBlocks = ttlContent.match(/odrl:prohibition\s+\[[^\]]+\]/gs) || [];
    const prohibitions = new Set(['odrl:distribute']); // default
    
    prohibitionBlocks.forEach(block => {
      const actionMatches = block.match(/odrl:action\s+(odrl:[a-z]+)/g) || [];
      actionMatches.forEach(match => {
        const action = match.split('odrl:action')[1]?.trim();
        if (action) prohibitions.add(cleanIRI(action));
      });
    });
    
    metadata.prohibitions = Array.from(prohibitions);
    
    // Extract constraint applicableActions
    const applicableActionsMatch = ttlContent.match(
      /<https:\/\/w3id\.org\/force\/compliance-report#applicableAction>\s+([^\s;]+)/g
    );
    if (applicableActionsMatch?.length > 0) {
      metadata.constraintApplicableActions = applicableActionsMatch
        .map(m => m.split('applicableAction>')[1]?.trim())
        .map(a => cleanIRI(a))
        .filter(Boolean);
    }
    
    // Extract maxCount
    const countMatch = ttlContent.match(
      /odrl:leftOperand\s+odrl:count[\s\S]*?odrl:rightOperand\s+"?(\d+)"?\^\^xsd:integer/
    );
    if (countMatch?.[1]) metadata.maxCount = parseInt(countMatch[1], 10);
    
    return metadata;
  } catch (error) {
    console.error(`❌ Error parsing policy meta`, error.message);
    return { active: true, maxCount: 3, actions: ['ex:read'], prohibitions: ['odrl:distribute'] };
  }
}

/* ===============================
REQUEST DEDUPLICATION
================================ */
const requestCache = new Map();
function shouldCountRequest(pod, app, field, action, timestamp) {
  const normalizedField = normalizeField(field);
  const normalizedAction = cleanIRI(action);
  const key = `${pod}::${app}::${normalizedField}::${normalizedAction}::${timestamp.substring(0, 19)}`;
  
  if (requestCache.has(key)) {
    console.log(`ℹ️ Skipping duplicate request: ${normalizedField} [${normalizedAction}]`);
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
📄 UPDATED: MULTI-POLICY TTL CONTENT (with recipient & temporal)
================================ */
const MONITOR_POLICIES_TTL = `@prefix odrl: <http://www.w3.org/ns/odrl/2/> .
@prefix dpv: <https://w3id.org/dpv#> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix ex: <https://example.org/> .
@prefix force: <https://w3id.org/force/compliance-report#> .

# ===== POLICY 1: Blood Type - Read Only with Recipient & Temporal =====
ex:policy-blood-type-4579e3c3af6546af9b28c6bf72890416 a odrl:Policy ;
    dct:identifier "urn:uuid:2c5c9cc0-c73e-4f78-8905-c08bd427866d" ;
    dct:title "Blood Type Access Limit Policy" ;
    dct:description "Policy with count, recipient, and temporal constraints" ;
    dct:created "2026-02-13T09:00:00Z"^^xsd:dateTime ;
    dct:creator ex:pod-owner ;
    odrl:profile <https://w3id.org/dpv/odrl> ;
    odrl:target <https://schema.org/bloodType> ;
    force:policyActive "true"^^xsd:boolean ;
    odrl:permission _:b752_n3-abc1-permission ;
    odrl:prohibition _:b752_n3-abc1-prohibition .

_:b752_n3-abc1-permission
    odrl:assigner ex:pod-owner ;
    odrl:assignee ex:any-app ;
    odrl:action ex:read ;
    odrl:constraint _:b752_n3-abc1-constraint-count, _:b752_n3-abc1-constraint-temporal .

_:b752_n3-abc1-prohibition
    odrl:assignee ex:any-app ;
    odrl:action odrl:distribute, odrl:derive, odrl:transfer .

_:b752_n3-abc1-constraint-count
    odrl:leftOperand odrl:count ;
    odrl:operator odrl:lteq ;
    odrl:rightOperand "1"^^xsd:integer .

_:b752_n3-abc1-constraint-temporal
    odrl:leftOperand odrl:dateTime ;
    odrl:operator odrl:lteq ;
    odrl:rightOperand "2027-12-31T23:59:59Z"^^xsd:dateTime .

# ===== POLICY 2: Identity - Read + Update with Recipient =====
ex:policy-identity-92c9be5f4abc4654972a93ccbac0082e a odrl:Policy ;
    dct:identifier "urn:uuid:bd7077e5-990b-4c24-87cb-ce3bbc96fd32" ;
    dct:title "Identity Access Limit Policy" ;
    dct:description "Policy with recipient constraint for specific app" ;
    dct:created "2026-02-13T09:00:00Z"^^xsd:dateTime ;
    dct:creator ex:pod-owner ;
    odrl:profile <https://w3id.org/dpv/odrl> ;
    odrl:target <https://schema.org/identifier> ;
    force:policyActive "true"^^xsd:boolean ;
    odrl:permission _:b752_n3-def2-permission ;
    odrl:prohibition _:b752_n3-def2-prohibition .

_:b752_n3-def2-permission
    odrl:assigner ex:pod-owner ;
    odrl:assignee ex:any-app ;
    odrl:action ex:read, ex:update ;
    odrl:constraint _:b752_n3-def2-constraint-count, _:b752_n3-def2-constraint-recipient .

_:b752_n3-def2-prohibition
    odrl:assignee ex:any-app ;
    odrl:action odrl:distribute, odrl:derive, odrl:transfer .

_:b752_n3-def2-constraint-count
    odrl:leftOperand odrl:count ;
    odrl:operator odrl:lteq ;
    odrl:rightOperand "3"^^xsd:integer ;
    force:applicableAction ex:read, ex:update .

_:b752_n3-def2-constraint-recipient
    odrl:leftOperand odrl:assignee ;
    odrl:operator odrl:eq ;
    odrl:rightOperand <https://healthcare-app.example.org/profile/card#me> .
`;

/* ===============================
🔐 ACL CONTENT FOR POLICY FILE
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
✅ HELPER: fetch dengan timeout
================================ */
async function fetchWithTimeout(url, options = {}, timeoutMs = 5000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(timeout);
  }
}

/* ===============================
✅ POLICY DEPLOYMENT FUNCTIONS (unchanged)
================================ */
async function savePolicyLocally(podName, policyContent) {
  const policyDir = path.join(DATA_ROOT, podName, AUDIT_ACCESS_PATH);
  const policyFile = path.join(policyDir, 'monitor-policy.ttl');
  await fs.mkdir(policyDir, { recursive: true });
  try {
    await fs.access(policyFile);
    return false;
  } catch {
    await fs.writeFile(policyFile, policyContent);
    console.log(`🎯 Local policy saved: ${policyFile}`);
    return true;
  }
}

async function createPolicyACLLocal(podName, podBaseUrl) {
  const aclDir = path.join(DATA_ROOT, podName, AUDIT_ACCESS_PATH);
  const aclFile = path.join(aclDir, 'monitor-policy.ttl.acl');
  await fs.mkdir(aclDir, { recursive: true });
  const aclContent = getPolicyACLContent(podBaseUrl);
  try {
    await fs.access(aclFile);
    return false;
  } catch {
    await fs.writeFile(aclFile, aclContent);
    return true;
  }
}

async function createPolicyACLRemote(podBaseUrl, authToken) {
  try { new URL(podBaseUrl); } catch (e) {
    return false;
  }
  if (!podBaseUrl.endsWith('/')) podBaseUrl += '/';
  const aclUrl = new URL(POLICY_PATH + '.acl', podBaseUrl).href;
  const aclContent = getPolicyACLContent(podBaseUrl);
  try {
    const res = await fetchWithTimeout(aclUrl, {
      method: 'PUT',
      headers: { 'Authorization': authToken, 'Content-Type': 'text/turtle' },
      body: aclContent
    }, 3000);
    return res.ok || res.status === 201 || res.status === 409;
  } catch (error) {
    return false;
  }
}

async function deployPolicyToPod(podBaseUrl, authToken) {
  try { new URL(podBaseUrl); } catch (e) {
    throw new Error(`Invalid podBaseUrl: "${podBaseUrl}"`);
  }
  if (!podBaseUrl.endsWith('/')) podBaseUrl += '/';
  const policyUrl = new URL(POLICY_PATH, podBaseUrl).href;
  
  try {
    const headRes = await fetchWithTimeout(policyUrl, {
      method: 'HEAD',
      headers: { 'Authorization': authToken, 'Accept': 'text/turtle' }
    }, 3000);
    
    if (headRes.status === 200 || headRes.status === 204) {
      await createPolicyACLRemote(podBaseUrl, authToken);
      return { deployed: false, url: policyUrl, reason: 'already_exists' };
    }
    
    const putRes = await fetchWithTimeout(policyUrl, {
      method: 'PUT',
      headers: {
        'Authorization': authToken,
        'Content-Type': 'text/turtle',
        'Slug': 'monitor-policy.ttl',
        'Link': '<http://www.w3.org/ns/ldp#Resource>; rel="type"'
      },
      body: MONITOR_POLICIES_TTL
    }, 5000);
    
    if (!putRes.ok) {
      throw new Error(`Failed to deploy policy: ${putRes.status}`);
    }
    
    await createPolicyACLRemote(podBaseUrl, authToken);
    return { deployed: true, url: policyUrl, status: putRes.status };
  } catch (error) {
    throw error;
  }
}

async function loadPolicyFromPod(podBaseUrl, authToken) {
  const policyUrl = new URL(POLICY_PATH, podBaseUrl).href;
  const res = await fetchWithTimeout(policyUrl, {
    headers: { 'Authorization': authToken, 'Accept': 'text/turtle' }
  }, 3000);
  if (!res.ok) throw new Error(`Failed to fetch policy: ${res.status}`);
  return await res.text();
}

/* ===============================
🔄 UPDATED: LOAD POLICIES - With Recipient & Temporal
================================ */
async function loadPolicies(podName = null, authToken = null, forceRefresh = false) {
  const now = Date.now();
  const cached = activePolicyCache.get(podName);
  
  if (cached && !forceRefresh && (now - cached.lastSync < 5 * 60 * 1000)) {
    policyEngine.loadPolicies(cached.policies);
    return cached.policies;
  }
  
  let policies = {};
  const activePolicyIRIs = new Set();
  
  if (podName) {
    const policyFile = path.join(DATA_ROOT, podName, POLICY_PATH);
    
    if ((forceRefresh || !cached || now - (cached?.lastSync || 0) > 5 * 60 * 1000) && authToken) {
      try {
        const podBaseUrl = buildPodBaseUrl(podName);
        const policyUrl = new URL(POLICY_PATH, podBaseUrl).href;
        const res = await fetchWithTimeout(policyUrl, {
          headers: { 'Authorization': authToken, 'Accept': 'text/turtle' }
        }, 2000);
        if (res.ok) {
          const remoteContent = await res.text();
          await fs.writeFile(policyFile, remoteContent);
        }
      } catch (e) {
        console.log(`ℹ️ Could not sync remote policy: ${e.message}`);
      }
    }
    
    try {
      const content = await fs.readFile(policyFile, 'utf-8');
      const policyBlocks = content.split(/(?=ex:policy-[^:;]+ a odrl:Policy)/).filter(b => b.trim());
      
      for (const block of policyBlocks) {
        const metadata = parsePolicyMetadata(block);
        
        if (!metadata.active) {
          console.log(`⏭️ Policy INACTIVE: ${metadata.title || metadata.target}`);
          continue;
        }
        
        const policyKey = `${metadata.target}Access`;
        policies[policyKey] = {
          resource: metadata.resource || `ex:policy-${metadata.target}`,
          identifier: metadata.identifier || `urn:uuid:${metadata.target}-default`,
          title: metadata.title || `${metadata.target} Policy`,
          targetIRI: metadata.target,
          active: metadata.active,
          actions: metadata.actions,
          prohibitions: metadata.prohibitions,
          // ✅ NEW: Store recipient & temporal constraints
          recipient: metadata.recipient,
          temporalValidUntil: metadata.temporalValidUntil,
          temporalValidFrom: metadata.temporalValidFrom,
          permission: {
            actions: metadata.actions,
            constraint: {
              leftOperand: "odrl:count",
              operator: "odrl:lteq",
              rightOperand: metadata.maxCount,
              applicableActions: metadata.constraintApplicableActions
            },
            targetAsset: metadata.target
          },
          prohibition: { actions: metadata.prohibitions }
        };
        
        if (metadata.target) activePolicyIRIs.add(cleanIRI(metadata.target));
        if (metadata.resource) activePolicyIRIs.add(cleanIRI(metadata.resource));
        
        console.log(`✅ Loaded ACTIVE policy: ${metadata.title}`);
        if (metadata.recipient) console.log(`   👤 Recipient: ${metadata.recipient}`);
        if (metadata.temporalValidUntil) console.log(`   📅 Valid until: ${metadata.temporalValidUntil}`);
        if (metadata.temporalValidFrom) console.log(`   📅 Valid from: ${metadata.temporalValidFrom}`);
      }
    } catch (err) {
      console.warn(`⚠️ Could not read policy file for ${podName}, using defaults`);
      policies = getDefaultPolicies();
      Object.values(policies).forEach(p => {
        if (p.targetIRI) activePolicyIRIs.add(cleanIRI(p.targetIRI));
        if (p.resource) activePolicyIRIs.add(cleanIRI(p.resource));
      });
    }
  } else {
    policies = getDefaultPolicies();
    Object.values(policies).forEach(p => {
      if (p.targetIRI) activePolicyIRIs.add(cleanIRI(p.targetIRI));
      if (p.resource) activePolicyIRIs.add(cleanIRI(p.resource));
    });
  }
  
  activePolicyCache.set(podName, {
    policies,
    activePolicyIRIs,
    lastSync: now
  });
  
  policyEngine.loadPolicies(policies);
  return policies;
}

function getDefaultPolicies() {
  return {
    bloodTypeAccess: {
      resource: "ex:policy-blood-type-default",
      identifier: "urn:uuid:2c5c9cc0-c73e-4f78-8905-c08bd427866d",
      title: "Blood Type Access Limit Policy",
      targetIRI: "https://schema.org/bloodType",
      active: true,
      actions: ['ex:read'],
      prohibitions: ['odrl:distribute', 'odrl:derive', 'odrl:transfer'],
      recipient: null, // any app
      temporalValidUntil: "2027-12-31T23:59:59Z",
      temporalValidFrom: null,
      permission: {
        actions: ['ex:read'],
        constraint: {
          leftOperand: "odrl:count",
          operator: "odrl:lteq",
          rightOperand: 1,
          applicableActions: ['ex:read']
        },
        targetAsset: "https://schema.org/bloodType"
      },
      prohibition: { actions: ['odrl:distribute', 'odrl:derive', 'odrl:transfer'] }
    },
    identityAccess: {
      resource: "ex:policy-identity-default",
      identifier: "urn:uuid:bd7077e5-990b-4c24-87cb-ce3bbc96fd32",
      title: "Identity Access Limit Policy",
      targetIRI: "https://schema.org/identifier",
      active: true,
      actions: ['ex:read', 'ex:update'],
      prohibitions: ['odrl:distribute', 'odrl:derive', 'odrl:transfer'],
      recipient: "https://healthcare-app.example.org/profile/card#me",
      temporalValidUntil: null,
      temporalValidFrom: null,
      permission: {
        actions: ['ex:read', 'ex:update'],
        constraint: {
          leftOperand: "odrl:count",
          operator: "odrl:lteq",
          rightOperand: 3,
          applicableActions: ['ex:read', 'ex:update']
        },
        targetAsset: "https://schema.org/identifier"
      },
      prohibition: { actions: ['odrl:distribute', 'odrl:derive', 'odrl:transfer'] }
    }
  };
}

/* ===============================
🚀 DEPLOY POLICY (unchanged)
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
  if (deployedPods.has(podName)) {
    loadPolicies(podName, authToken, false).catch(e => console.log(`ℹ️ Cache refresh skipped: ${e.message}`));
    return true;
  }
  if (deployingPods.has(podName)) return true;
  
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
        await loadPolicies(podName, formattedAuth, true);
      }
    } catch (error) {
      await savePolicyLocally(podName, MONITOR_POLICIES_TTL);
      const podBaseUrl = buildPodBaseUrl(podName);
      await createPolicyACLLocal(podName, podBaseUrl);
      await loadPolicies(podName, authToken, true);
    } finally {
      deployingPods.delete(podName);
      deployedPods.add(podName);
    }
  })();
  return true;
}

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
    "--baseUrl", GATEWAY_BASE
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
          if (isSensitiveField(normalizedIRI)) {
            sensitiveFields.add(normalizedIRI);
          }
        }
      }
    });
  }
  return Array.from(sensitiveFields);
}

/* ===============================
✅ EXTRACT PERSONAL DATA
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
ACCESS LOG & SOTW
================================ */
async function ensureAccessLogFile(pod) {
  const dir = path.join(DATA_ROOT, pod, AUDIT_ACCESS_PATH);
  const file = path.join(dir, "access-log.ttl");
  await fs.mkdir(dir, { recursive: true });
  try {
    await fs.access(file);
  } catch {
    await fs.writeFile(file, `@prefix ex: <https://example.org/> .
@prefix prov: <http://www.w3.org/ns/prov#> .
@prefix dpv: <https://w3id.org/dpv#> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix odrl: <http://www.w3.org/ns/odrl/2/> .
@prefix report: <https://w3id.org/force/compliance-report#> .

ex:access-log a prov:Collection .
`);
  }
  return file;
}

async function ensureSotWFile(pod) {
  const dir = path.join(DATA_ROOT, pod, AUDIT_MONITORING_PATH);
  const file = path.join(dir, "state-of-world.ttl");
  await fs.mkdir(dir, { recursive: true });
  try {
    await fs.access(file);
  } catch {
    const timestamp = new Date().toISOString();
    await fs.writeFile(file, `@prefix ex: <https://example.org/> .
@prefix sotw: <https://w3id.org/force/sotw#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix odrl: <http://www.w3.org/ns/odrl/2/> .
@prefix dct: <http://purl.org/dc/terms/> .

ex:sotw-current a sotw:SotW ;
    sotw:currentTime "${timestamp}"^^xsd:dateTime ;
    sotw:currentLocation <https://www.iso.org/obp/ui/#iso:code:3166:ID> ;
    sotw:count [
        a sotw:Count ;
        sotw:countValue "0"^^xsd:integer ;
        odrl:target <https://schema.org/bloodType> ;
        sotw:actionType "ex:read"
    ] ;
    sotw:count [
        a sotw:Count ;
        sotw:countValue "0"^^xsd:integer ;
        odrl:target <https://schema.org/identifier> ;
        sotw:actionType "ex:read"
    ] ;
    sotw:count [
        a sotw:Count ;
        sotw:countValue "0"^^xsd:integer ;
        odrl:target <https://schema.org/identifier> ;
        sotw:actionType "ex:update"
    ] .
`);
  }
  return file;
}

async function updateSotW(pod, app, field, countData = null, decision = "ALLOWED", requestedAction = 'ex:read') {
  const sotwFile = await ensureSotWFile(pod);
  let content = await fs.readFile(sotwFile, 'utf-8');
  const now = new Date().toISOString();
  let hasChanges = false;
  
  if (countData && field) {
    const cleanFieldIRI = cleanIRI(field);
    const cleanAction = cleanIRI(requestedAction);
    const escapedIRI = cleanFieldIRI.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    
    const countRegex = new RegExp(
      `(odrl:target\\s+${escapedIRI}\\s*;\\s*sotw:actionType\\s+"${cleanAction}"\\s*;\\s*sotw:countValue\\s+")[^"]+("^^xsd:integer)`,
      'g'
    );
    
    const match = content.match(countRegex);
    if (match) {
      const currentCountMatch = match[0].match(/sotw:countValue\s+"(\d+)"/);
      const currentCount = currentCountMatch?.[1];
      
      if (currentCount !== String(countData.count)) {
        content = content.replace(countRegex, `$1${countData.count}$2`);
        hasChanges = true;
      }
    } else {
      const countBlock = `
ex:sotw-current sotw:count [
    a sotw:Count ;
    sotw:countValue "${countData.count}"^^xsd:integer ;
    odrl:target ${cleanFieldIRI} ;
    sotw:actionType "${cleanAction}"
] .`;
      content += countBlock;
      hasChanges = true;
    }
  }
  
  if (hasChanges) {
    content = content.replace(
      /(sotw:currentTime\s+")[^"]+("^^xsd:dateTime)/,
      `$1${now}$2`
    );
    await fs.writeFile(sotwFile, content);
  }
}

/* ===============================
✅ UPDATED: WRITE ACCESS LOG - With Recipient & Temporal Violations
================================ */
async function writeAccessLog({ pod, evalRequest, decision, sensitiveFields,
  violationType = null, personalData = null, method = "GET", resource = "",
  policyMetadata = null, requestedAction = 'ex:read', requesterWebId = null,
  recipientViolation = null, temporalViolation = null }) {
  
  if (sensitiveFields.length === 0 && decision.permitted) return;
  
  const logFile = await ensureAccessLogFile(pod);
  const accessId = `access-${Date.now()}`;
  const timestamp = new Date().toISOString();
  const app = evalRequest?.appName || resource.split('/').filter(Boolean)[2] || "unknown";
  const decisionStr = decision.permitted ? "ALLOWED" : "VIOLATION";
  
  // ✅ Determine deontic state based on violation type
  let deonticState = decision.permitted ? "report:Fulfilled" : "report:Violated";
  let activationState = "report:Active";
  let attemptState = "report:Attempted";
  let performanceState = decision.permitted ? "report:Performed" : "report:NotPerformed";
  
  // ✅ Override for specific violation types
  if (recipientViolation) {
    deonticState = "report:Violated";
    performanceState = "report:NotPerformed";
  }
  if (temporalViolation) {
    deonticState = "report:Violated";
    performanceState = "report:NotPerformed";
  }
  
  // ROOT: Access Record (Compliance Report Model - Listing 6)
  let ttl = `# ===== ROOT: Access Record ${accessId} =====
ex:${accessId} a prov:Activity, <https://w3id.org/force/compliance-report#PermissionReport> ;
    prov:startedAtTime "${timestamp}"^^xsd:dateTime ;
    prov:wasAssociatedWith ex:${app} ;
    prov:used <${resource}> ;
    <https://w3id.org/force/compliance-report#decision> "${decisionStr}" ;
    <https://w3id.org/force/compliance-report#accessMethod> "${method}" ;
    <https://w3id.org/force/compliance-report#requestedAction> "${cleanIRI(requestedAction)}" ;
    <https://w3id.org/force/compliance-report#accessedResource> <${resource}> ;
    <https://w3id.org/force/compliance-report#activationState> ${activationState} ;
    <https://w3id.org/force/compliance-report#attemptState> ${attemptState} ;
    <https://w3id.org/force/compliance-report#performanceState> ${performanceState} ;
    <https://w3id.org/force/compliance-report#deonticState> ${deonticState} .
ex:access-log prov:hadMember ex:${accessId} .
`;

  // ✅ Add requester WebID if available
  if (requesterWebId) {
    ttl += `ex:${accessId} <https://w3id.org/force/compliance-report#requesterWebID> <${cleanIRI(requesterWebId)}> .
`;
  }

  // SUBGRAPH: Personal Data Handling
  if (personalData && personalData.sensitive) {
    const handlingBundleId = `handling-bundle-${Date.now()}`;
    ttl += `# ===== SUBGRAPH: Personal Data Handling =====
ex:${handlingBundleId} a prov:Bundle ;
    dct:title "Personal Data Handling Context" ;
    prov:wasGeneratedBy ex:${accessId} .
ex:${accessId} <https://w3id.org/force/compliance-report#hasHandlingBundle> ex:${handlingBundleId} .
ex:handling-${Date.now()} a dpv:PersonalDataHandling ;
    dpv:hasProcessing ${method === "GET" ? "dpv:Access" : "dpv:Create"} ;
    dpv:hasDataSubject ex:pod-owner ;
    <https://w3id.org/force/compliance-report#belongsToBundle> ex:${handlingBundleId} .
ex:${handlingBundleId} prov:hadMember ex:handling-${Date.now()} .
ex:${accessId} <https://w3id.org/force/compliance-report#hasPersonalDataHandling> ex:handling-${Date.now()} .
`;
  }

  // SUBGRAPH: Accessed Fields Bundle
  const fieldsBundleId = `fields-bundle-${Date.now()}`;
  ttl += `# ===== SUBGRAPH: Accessed Fields Collection =====
ex:${fieldsBundleId} a prov:Bundle ;
    dct:title "Accessed Data Fields" ;
    prov:wasGeneratedBy ex:${accessId} .
ex:${accessId} <https://w3id.org/force/compliance-report#hasFieldsBundle> ex:${fieldsBundleId} .
`;

  if (personalData?.fields?.length > 0) {
    personalData.fields.forEach((fieldIRI, idx) => {
      const fieldId = `field-${Date.now()}-${idx}`;
      const fieldValue = sanitizeTurtleLiteral(personalData.values[idx] || "");
      const isSensitive = personalData.sensitiveFields.includes(fieldIRI);
      const fieldConfig = getFieldConfig(fieldIRI);
      const fieldLabel = fieldConfig?.assetLabel || fieldConfig?.label || "Unknown Field";
      const dataCategory = fieldConfig?.dataCategory || "dpv:PersonalData";
      const personalDataType = fieldConfig?.personalData || "dpv:Data";
      const cleanFieldIRI = cleanIRI(fieldIRI);
      
      ttl += `# Field[${idx+1}]: ${fieldLabel}
ex:${fieldId} a <https://w3id.org/force/compliance-report#AccessedDataField> ;
    <https://w3id.org/force/compliance-report#fieldIRI> ${cleanFieldIRI} ;
    <https://w3id.org/force/compliance-report#fieldName> "${fieldLabel}" ;
    <https://w3id.org/force/compliance-report#fieldValue> "${fieldValue}" ;
    <https://w3id.org/force/compliance-report#isSensitive> "${isSensitive}"^^xsd:boolean ;
    <https://w3id.org/force/compliance-report#dataCategory> "${dataCategory}" ;
    <https://w3id.org/force/compliance-report#personalDataType> "${personalDataType}" ;
    <https://w3id.org/force/compliance-report#belongsToBundle> ex:${fieldsBundleId} ;
    prov:wasGeneratedBy ex:${accessId} .
ex:${fieldsBundleId} prov:hadMember ex:${fieldId} .
`;
    });
  }

  // SUBGRAPH: Policy Evaluation Context
  const policyBundleId = `policy-bundle-${Date.now()}`;
  const evaluatedPolicies = [];
  const cached = activePolicyCache.get(pod);
  const activePolicyIRIs = cached?.activePolicyIRIs || new Set();
  
  for (const field of sensitiveFields) {
    const fieldConfig = getFieldConfig(field);
    if (fieldConfig?.protectedByPolicy) {
      const policyKey = fieldConfig.protectedByPolicy;
      const policy = policyEngine.getPolicy?.(policyKey);
      
      if (!policy || !policy.active) continue;
      
      const targetIRI = cleanIRI(fieldConfig.asset);
      if (!activePolicyIRIs.has(targetIRI) && !activePolicyIRIs.has(cleanIRI(policy.resource || ''))) {
        continue;
      }
      
      const policyEvalId = `policy-eval-${Date.now()}-${evaluatedPolicies.length}`;
      const policyResource = cleanIRI(policy.resource || `ex:policy-${policyKey}`);
      const policyUUID = policy.identifier || '';
      const aliasResource = `ex:policy-${policyKey}-default`;
      const reasonClean = violationType || (decision.reason ? decision.reason.split(':')[0] : 'N/A');
      const targetAssetIRI = cleanIRI(fieldConfig.asset);
      
      ttl += `ex:${policyEvalId} a <https://w3id.org/force/compliance-report#PolicyEvaluation> ;
    <https://w3id.org/force/compliance-report#evaluatedPolicy> ${aliasResource} ;
    <https://w3id.org/force/compliance-report#evaluationResult> "${decisionStr}" ;
    <https://w3id.org/force/compliance-report#evaluationReason> "${reasonClean}" ;
    <https://w3id.org/force/compliance-report#targetAsset> <${targetAssetIRI}> ;
    <https://w3id.org/force/compliance-report#belongsToBundle> ex:${policyBundleId} .
ex:${policyBundleId} prov:hadMember ex:${policyEvalId} .
`;
      ttl += createPolicyAliasMapping(aliasResource, policyResource, policyUUID) + `
`;
      
      evaluatedPolicies.push({
        resource: policyResource,
        alias: aliasResource,
        identifier: policyUUID,
        title: policy.title,
        asset: fieldConfig.asset,
        assetLabel: fieldConfig.assetLabel,
        protectedByPolicy: fieldConfig.protectedByPolicy,
        active: policy.active,
        recipient: policy.recipient,
        temporalValidUntil: policy.temporalValidUntil
      });
    }
  }
  
  if (evaluatedPolicies.length > 0) {
    ttl = `# ===== SUBGRAPH: Policy Evaluation Context =====
ex:${policyBundleId} a prov:Bundle ;
    dct:title "ODRL Policy Evaluation" ;
    prov:wasGeneratedBy ex:${accessId} .
ex:${accessId} <https://w3id.org/force/compliance-report#hasPolicyBundle> ex:${policyBundleId} ;
    <https://w3id.org/force/compliance-report#rule> ${evaluatedPolicies.map(p => cleanIRI(p.resource)).join(', ')} .
` + ttl;
  }

  // ✅ SUBGRAPH: Violation Details (with recipient & temporal)
  const violationEntries = [];
  
  if (!decision.permitted) {
    // ✅ Recipient violation
    if (recipientViolation) {
      violationEntries.push({
        type: 'recipient',
        fieldIRI: recipientViolation.fieldIRI,
        policyAlias: recipientViolation.policyAlias,
        reason: recipientViolation.reason,
        requesterWebId: requesterWebId || 'unknown',
        allowedAssignee: recipientViolation.allowedAssignee
      });
    }
    
    // ✅ Temporal violation
    if (temporalViolation) {
      violationEntries.push({
        type: 'temporal',
        fieldIRI: temporalViolation.fieldIRI,
        policyAlias: temporalViolation.policyAlias,
        reason: temporalViolation.reason,
        currentTime: new Date().toISOString(),
        policyDate: temporalViolation.policyDate
      });
    }
    
    // Count violations
    for (const field of sensitiveFields) {
      const fieldConfig = getFieldConfig(field);
      if (fieldConfig) {
        const cleanFieldIRI = cleanIRI(field);
        const countData = accessCounter.get(pod, app, cleanFieldIRI, requestedAction) || { count: 0 };
        const observedCount = countData.count;
        const policy = policyEngine.getPolicy?.(fieldConfig.protectedByPolicy);
        const limit = policy?.permission?.constraint?.rightOperand || 3;
        
        if (!policy || !policy.active) continue;
        
        if (observedCount > limit) {
          violationEntries.push({
            type: 'count',
            fieldIRI: cleanFieldIRI,
            policyAlias: `ex:policy-${fieldConfig.protectedByPolicy}-default`,
            observedCount,
            limit,
            policyTitle: policy?.title || fieldConfig.protectedByPolicy,
            assetLabel: fieldConfig.assetLabel,
            actionType: requestedAction
          });
        }
      }
    }
  }
  
  if (violationEntries.length > 0) {
    const violationBundleId = `violation-bundle-${Date.now()}`;
    const violationId = `violation-${Date.now()}`;
    const violatedPolicyAliases = [...new Set(violationEntries.map(v => cleanIRI(v.policyAlias)))];
    
    ttl += `# ===== SUBGRAPH: Violation Details =====
ex:${violationBundleId} a prov:Bundle ;
    dct:title "Policy Violation Context" ;
    prov:wasGeneratedBy ex:${accessId} .
ex:${accessId} <https://w3id.org/force/compliance-report#hasViolationBundle> ex:${violationBundleId} .
ex:${violationId} a <https://w3id.org/force/compliance-report#PolicyViolation> ;
    <https://w3id.org/force/compliance-report#violationTimestamp> "${timestamp}"^^xsd:dateTime ;
    <https://w3id.org/force/compliance-report#belongsToBundle> ex:${violationBundleId} ;
    <https://w3id.org/force/compliance-report#violatedPolicy> ${violatedPolicyAliases.join(', ')} .
ex:${violationBundleId} prov:hadMember ex:${violationId} .
`;
    
    violationEntries.forEach((entry, idx) => {
      const fieldViolationId = `field-violation-${Date.now()}-${idx}`;
      const cleanPolicyAlias = cleanIRI(entry.policyAlias);
      
      ttl += `ex:${violationId} <https://w3id.org/force/compliance-report#hasFieldViolation> ex:${fieldViolationId} .
ex:${fieldViolationId} a <https://w3id.org/force/compliance-report#FieldViolation> ;
    <https://w3id.org/force/compliance-report#violatedField> ${cleanIRI(entry.fieldIRI)} ;
    <https://w3id.org/force/compliance-report#violatedPolicy> ${cleanPolicyAlias} ;
    <https://w3id.org/force/compliance-report#violationType> "${entry.type}" ;
    <https://w3id.org/force/compliance-report#violationReason> "${sanitizeTurtleLiteral(entry.reason)}"`;
      
      if (entry.type === 'count') {
        ttl += ` ;
    <https://w3id.org/force/compliance-report#observedCount> "${entry.observedCount}"^^xsd:integer ;
    <https://w3id.org/force/compliance-report#allowedLimit> "${entry.limit}"^^xsd:integer ;
    <https://w3id.org/force/compliance-report#actionType> "${cleanIRI(entry.actionType)}"`;
      } else if (entry.type === 'recipient') {
        ttl += ` ;
    <https://w3id.org/force/compliance-report#requesterWebID> <${cleanIRI(entry.requesterWebId)}> ;
    <https://w3id.org/force/compliance-report#allowedAssignee> <${cleanIRI(entry.allowedAssignee)}>"`;
      } else if (entry.type === 'temporal') {
        ttl += ` ;
    <https://w3id.org/force/compliance-report#currentTime> "${entry.currentTime}"^^xsd:dateTime ;
    <https://w3id.org/force/compliance-report#policyDate> "${entry.policyDate}"^^xsd:dateTime"`;
      }
      
      ttl += ` .
`;
    });
  }
  
  await fs.appendFile(logFile, ttl);
  
  // Console logging
  const status = decision.permitted ? "✅ ACCESS ALLOWED" : "⚠️ POLICY VIOLATION";
  const fields = sensitiveFields.length > 0 ? sensitiveFields.join(', ') : 'none';
  
  if (!decision.permitted && violationEntries.length > 0) {
    const violationDetails = violationEntries.map(v => {
      if (v.type === 'count') {
        return `${v.policyTitle} (${v.assetLabel} [${v.actionType}]: ${v.observedCount} > ${v.limit})`;
      } else if (v.type === 'recipient') {
        return `Recipient (${cleanIRI(v.requesterWebId)} not authorized)`;
      } else if (v.type === 'temporal') {
        return `Temporal (${v.reason})`;
      }
      return v.reason;
    });
    console.log(`${status} | App: ${app} | Action: ${requestedAction} | Fields: ${fields} | VIOLATED: ${violationDetails.join(', ')}`);
  } else {
    console.log(`${status} | App: ${app} | Action: ${requestedAction} | Fields: ${fields} | Reason: ${decision.reason}`);
  }
}

/* ===============================
✅ UPDATED: POLICY ENGINE EVALUATION - With Recipient & Temporal
================================ */
async function evaluateWithAllConstraints(pod, app, sensitiveFields, evalRequest, pathname, requestedAction, requesterWebId) {
  const violations = [];
  const recipientViolations = [];
  const temporalViolations = [];
  
  // Build SotW
  const sotw = await buildSotWWithCount(pod, evalRequest, pathname, sensitiveFields, requestedAction);
  
  // ✅ Check each sensitive field against its policy
  for (const field of sensitiveFields) {
    const fieldConfig = getFieldConfig(field);
    if (!fieldConfig?.protectedByPolicy) continue;
    
    const policyKey = fieldConfig.protectedByPolicy;
    const policy = policyEngine.getPolicy?.(policyKey);
    
    if (!policy || !policy.active) continue;
    
    const cleanFieldIRI = cleanIRI(field);
    
    // ✅ 1. Check action permission
    const actionCheck = isActionAllowed(requestedAction, policy.actions, policy.prohibitions);
    if (!actionCheck.allowed) {
      violations.push({
        type: 'action',
        fieldIRI: cleanFieldIRI,
        policyKey,
        reason: actionCheck.reason
      });
      continue;
    }
    
    // ✅ 2. Check recipient constraint
    if (policy.recipient) {
      const recipientCheck = evaluateRecipientConstraint(
        { rightOperand: policy.recipient },
        requesterWebId
      );
      if (!recipientCheck.allowed) {
        recipientViolations.push({
          fieldIRI: cleanFieldIRI,
          policyAlias: `ex:policy-${policyKey}-default`,
          reason: recipientCheck.reason,
          allowedAssignee: policy.recipient
        });
        violations.push({
          type: 'recipient',
          fieldIRI: cleanFieldIRI,
          policyKey,
          reason: recipientCheck.reason
        });
        continue;
      }
    }
    
    // ✅ 3. Check temporal constraint
    if (policy.temporalValidUntil) {
      const temporalCheck = evaluateTemporalConstraint({
        operator: 'odrl:lteq',
        rightOperand: policy.temporalValidUntil
      });
      if (!temporalCheck.allowed) {
        temporalViolations.push({
          fieldIRI: cleanFieldIRI,
          policyAlias: `ex:policy-${policyKey}-default`,
          reason: temporalCheck.reason,
          policyDate: policy.temporalValidUntil
        });
        violations.push({
          type: 'temporal',
          fieldIRI: cleanFieldIRI,
          policyKey,
          reason: temporalCheck.reason
        });
        continue;
      }
    }
    
    if (policy.temporalValidFrom) {
      const temporalCheck = evaluateTemporalConstraint({
        operator: 'odrl:gteq',
        rightOperand: policy.temporalValidFrom
      });
      if (!temporalCheck.allowed) {
        temporalViolations.push({
          fieldIRI: cleanFieldIRI,
          policyAlias: `ex:policy-${policyKey}-default`,
          reason: temporalCheck.reason,
          policyDate: policy.temporalValidFrom
        });
        violations.push({
          type: 'temporal',
          fieldIRI: cleanFieldIRI,
          policyKey,
          reason: temporalCheck.reason
        });
        continue;
      }
    }
    
    // ✅ 4. Check count constraint (increment first)
    const now = new Date().toISOString();
    if (shouldCountRequest(pod, app, cleanFieldIRI, requestedAction, now)) {
      await accessCounter.increment(pod, app, cleanFieldIRI, requestedAction);
    }
    
    const countData = accessCounter.get(pod, app, cleanFieldIRI, requestedAction) || { count: 0 };
    const limit = policy.permission?.constraint?.rightOperand || 3;
    
    if (countData.count > limit) {
      violations.push({
        type: 'count',
        fieldIRI: cleanFieldIRI,
        policyKey,
        reason: `Count ${countData.count} exceeds limit ${limit}`,
        observedCount: countData.count,
        limit
      });
    }
  }
  
  // ✅ Determine final decision
  const permitted = violations.length === 0;
  const firstViolation = violations[0];
  
  return {
    permitted,
    reason: firstViolation?.reason || 'All constraints satisfied',
    violations,
    recipientViolations,
    temporalViolations,
    violatedConstraints: violations.map(v => ({
      violationType: v.type,
      reason: v.reason
    }))
  };
}

async function buildSotWWithCount(pod, evalRequest, pathname, sensitiveFields, requestedAction = 'ex:read') {
  const sotw = await sotwProvider.build(pod, evalRequest, pathname, sensitiveFields);
  const app = extractAppName(pathname);
  const countState = {};
  
  for (const field of sensitiveFields) {
    const normalizedField = normalizeField(field);
    const countData = accessCounter.get(pod, app, normalizedField, requestedAction) || { count: 0 };
    countState[normalizedField] = {
      ...countData,
      actionType: requestedAction
    };
  }
  sotw.count = countState;
  return sotw;
}

/* ===============================
🔥 GATEWAY SERVER (UPDATED: Full Constraint Evaluation)
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
  for await (const chunk of req) body += chunk;
  
  if (isAuthenticated(headers) && pod && isValidPodName(pod)) {
    await ensurePolicyDeployed(pod, headers.authorization);
  }
  
  const proxy = http.request({
    hostname: "127.0.0.1",
    port: CSS_PORT,
    path: url,
    method,
    headers: { ...headers }
  }, async pres => {
    let resp = "";
    for await (const chunk of pres) resp += chunk;
    
    // ✅ ODRL Evaluation for requests with sensitive data
    if (method === "GET" && isAuthenticated(headers) && !isSystem(target.pathname)) {
      try {
        const sensitiveFields = extractSensitiveFields(resp);
        
        if (sensitiveFields.length > 0) {
          const evalRequest = requestBuilder.buildFromHttpRequest(req, target.pathname, pod, body);
          const app = extractAppName(target.pathname);
          const requestedAction = httpMethodToOdrlAction(method, target.pathname, body);
          
          // ✅ NEW: Extract WebID from Solid-OIDC token
          const requesterWebId = extractWebIdFromRequest(req);
          
          // ✅ UPDATED: Full constraint evaluation (count + recipient + temporal)
          const decisionResult = await evaluateWithAllConstraints(
            pod, app, sensitiveFields, evalRequest, target.pathname, 
            requestedAction, requesterWebId
          );
          
          const personalData = extractPersonalData(resp);
          
          // Update SotW per field
          for (const field of sensitiveFields) {
            const cleanFieldIRI = cleanIRI(field);
            const countData = accessCounter.get(pod, app, cleanFieldIRI, requestedAction) || { count: 0 };
            await updateSotW(pod, app, cleanFieldIRI, countData, 
              decisionResult.permitted ? "ALLOWED" : "VIOLATION", requestedAction);
          }
          
          // ✅ UPDATED: Write log with all violation types
          await writeAccessLog({
            pod, 
            evalRequest, 
            decision: decisionResult, 
            sensitiveFields,
            violationType: decisionResult.violatedConstraints?.[0]?.violationType,
            personalData, 
            method, 
            resource: `${GATEWAY_BASE}${target.pathname}`,
            requestedAction,
            requesterWebId,
            recipientViolation: decisionResult.recipientViolations?.[0],
            temporalViolation: decisionResult.temporalViolations?.[0]
          });
          
          if (!decisionResult.permitted) {
            console.log('⚠️ POLICY VIOLATION DETECTED:', decisionResult.reason);
          }
        }
      } catch (error) {
        console.error('⚠️ ODRL evaluation skipped:', error.message);
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
  accessCounter.resetPod('amd');
  console.log('✅ Access counter reset - Count starts from 0');
  console.log(`✅ Solid Gateway with ODRL (MONITORING MODE) @ ${GATEWAY_BASE}`);
  console.log('🔄 Policy Syncing: Local cache enabled (sync every 5 min)');
  console.log('📊 Multi-Policy Support: bloodType, identity, email, name, birthDate');
  console.log('🔐 Policy as RDF Resource: ex:policy-xxx + dct:identifier + dct:title');
  console.log('🔗 Fully Semantic Links: report:evaluatedPolicy → resource');
  console.log('🗝️ Policy Alias Mapping: alias → resource → UUID');
  console.log('📝 Research-Grade RDF: Compliance Report Model (Listing 6)');
  console.log('🌍 State of the World: currentTime, count+actionType, location');
  console.log('');
  console.log('🎯 NEW CONSTRAINTS SUPPORTED:');
  console.log('   ✅ Count constraint (odrl:count)');
  console.log('   ✅ Recipient constraint (odrl:assignee) - WebID-based');
  console.log('   ✅ Temporal constraint (odrl:dateTime) - Valid until/from');
  console.log('   ✅ Extended prohibitions (distribute, derive, transfer)');
  console.log('');
  console.log('🔧 Testing:');
  console.log('   • Add X-WebID header to test recipient constraint');
  console.log('   • Modify system clock to test temporal constraint');
  console.log('   • Multiple requests to test count constraint');
});