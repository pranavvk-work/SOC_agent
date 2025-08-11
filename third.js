// server.js
// Sentinel "incident created" webhook -> update incident directly (no need to fetch)

const express = require('express');
const axios = require('axios');

const app = express();
app.use(express.json({ limit: '1mb' }));

// ---------- Config ----------
const PORT = process.env.PORT || 8000;
const API_VERSION = process.env.API_VERSION || '2025-06-01';

// Workspace context from ENV (required)
const SUBSCRIPTION_ID = process.env.SUBSCRIPTION_ID??"789ffe48-9506-43da-b629-b0b9174bad4d";
const RESOURCE_GROUP  = process.env.RESOURCE_GROUP??"SOCAutomationAgent";
const WORKSPACE_NAME  = process.env.WORKSPACE_NAME??"SOCAutomation";


// Owner config (fill what you have)
const OWNER = {
  assignedTo:        process.env.OWNER_NAME  || '',
  userPrincipalName: process.env.OWNER_UPN   || '',
  email:             process.env.OWNER_EMAIL || '',
  objectId:          process.env.OWNER_OBJECT_ID || ''
};

// Auth: static token OR client credentials
const ARM_TOKEN = process.env.ARM_TOKEN || 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkpZaEFjVFBNWl9MWDZEQmxPV1E3SG4wTmVYRSIsImtpZCI6IkpZaEFjVFBNWl9MWDZEQmxPV1E3SG4wTmVYRSJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvZDdhYjEyMjUtNDY0OS00Y2IzLWFiZDUtYmM3MzJiZWQzMjAzLyIsImlhdCI6MTc1NDg5MzQxOCwibmJmIjoxNzU0ODkzNDE4LCJleHAiOjE3NTQ4OTczMTgsImFpbyI6IkFXUUFtLzhaQUFBQUtqSk9FRW1RWU5neStaVXZkU3Y1ZWZ6UTIzSkJsV3E2YlBZQy9mSVB3L0xGdzdUR0RxRFJtNlhTNWx0eWFST2N4WStpUjB6NUgyd3ozQ2NYWWZpZzFiNlVtUVZOSVpsYzdkdnJBblBRVndvbk1CODBXVHJpU2NvemFTSXpLNVYwIiwiYXBwaWQiOiJkNzE5MGZhYS1iM2FjLTRjMGQtYjA5MC1hZGM2NzRiOTcwNWMiLCJhcHBpZGFjciI6IjEiLCJpZHAiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9kN2FiMTIyNS00NjQ5LTRjYjMtYWJkNS1iYzczMmJlZDMyMDMvIiwiaWR0eXAiOiJhcHAiLCJvaWQiOiI1MGFkY2Y4OS0yZmUxLTQyMTEtYjc4OC1iOTgwYTk5NzIzNGIiLCJyaCI6IjEuQVhFQUpSS3IxMGxHczB5cjFieHpLLTB5QTBaSWYza0F1dGRQdWtQYXdmajJNQk54QUFCeEFBLiIsInN1YiI6IjUwYWRjZjg5LTJmZTEtNDIxMS1iNzg4LWI5ODBhOTk3MjM0YiIsInRpZCI6ImQ3YWIxMjI1LTQ2NDktNGNiMy1hYmQ1LWJjNzMyYmVkMzIwMyIsInV0aSI6IkdnWEVjaEJpRmstMmd2SEhkMDlnQUEiLCJ2ZXIiOiIxLjAiLCJ4bXNfZnRkIjoiLUVpOXFsYXV6REpGTEt5QS1fTGIwRkNjaW83a01iMVBxU1pTZUdpYzFBSUJZWE5wWVhOdmRYUm9aV0Z6ZEMxa2MyMXoiLCJ4bXNfaWRyZWwiOiI3IDEyIiwieG1zX3JkIjoiMC40MkxsWUJKaUxCUVM0V0FYRWxoMS1IM1NSY1BWWHF1UFg1SVU3OW0wRGlqS0tTUndlMmZybFVXSmFWNk5fSjY3ZU5iY19RVVU1UkFTY1BPb3IyVFlkZDFfbF9PdGd6LS1HUWdEQUEiLCJ4bXNfdGNkdCI6MTYzMDkwODU1NH0.FjkYM1ZsYsAKk464nJkERxfP27kropuCwQ0iv_SeyA9MkG4QQfBtfe6Yxpt7S2U5-WNOsIbhW1rP0F7sPnvJKIhXOWLYr9L7mHVZ-vcf7kNvmdjcrg9QicC76ZnwKsOZGwj9UyghmsHE9YjJUejZ66YurYv-PDQp0JNZ79vBPHAXsjJ8kvORblls2UPVqW37T3F5EYICPqWB3WVwq-ZkyssyL2vioBUobK5Jp6ZHbfjNAwEBnocB0YZTNaM1kppIkYoEUm1z-vuH1RZdtMVC7Hj3R6v3Ofri0Zyl7Z0YYgA7YsxcWEL8BXpVZHCzPHONYdB4ao4AGVfHGbVbNjGPug';
const AZ_TENANT = process.env.AZURE_TENANT_ID || '';
const AZ_CLIENT = process.env.AZURE_CLIENT_ID || '';
const AZ_SECRET = process.env.AZURE_CLIENT_SECRET || '';

const ARM_API = 'https://management.azure.com';
const ELIGIBLE_SEVERITIES = new Set(['informational', 'info', 'low', 'medium']);
const norm = (v) => (v ?? '').toString().trim().toLowerCase();
console.log(`Workspace: ${SUBSCRIPTION_ID}/${RESOURCE_GROUP}/${WORKSPACE_NAME}/${ARM_TOKEN}`);
// ---------- Utilities ----------
function ownerSummary(o = {}) {
  const parts = [o.assignedTo, o.userPrincipalName || o.email, o.objectId].filter(Boolean);
  return parts.length ? parts.join(' | ') : '—';
}

function isUnassigned(o) {
  if (!o || typeof o !== 'object') return true;
  const { assignedTo, userPrincipalName, email, objectId } = o;
  return [assignedTo, userPrincipalName, email, objectId].every(x => !x || !String(x).trim());
}

function buildIncidentUrl({ subscriptionId, resourceGroup, workspaceName, incidentName }) {
  return `${ARM_API}/subscriptions/${subscriptionId}/resourceGroups/${resourceGroup}` +
         `/providers/Microsoft.OperationalInsights/workspaces/${workspaceName}` +
         `/providers/Microsoft.SecurityInsights/incidents/${incidentName}?api-version=${API_VERSION}`;
}

// async function getArmToken() {
//   if (ARM_TOKEN) return ARM_TOKEN;
//   // if (!AZ_TENANT || !AZ_CLIENT || !AZ_SECRET) {
//   //   throw new Error('No ARM auth configured. Set ARM_TOKEN or Entra client credentials.');
//   // }
//   // const url = `https://login.microsoftonline.com/${AZ_TENANT}/oauth2/v2.0/token`;
//   // const form = new URLSearchParams({
//   //   client_id: AZ_CLIENT,
//   //   client_secret: AZ_SECRET,
//   //   grant_type: 'client_credentials',
//   //   scope: 'https://management.azure.com/.default'
//   // });
//   // const { data } = await axios.post(url, form);
//   // return data.access_token;
// }
// console.log(`ARM auth mode: `,getArmToken())
// ---------- ARM calls ----------
async function putIncident(ids, token, etag, props) {
  const url = buildIncidentUrl(ids);
  const { data, headers } = await axios.put(
    url,
    { etag, properties: props },
    {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      timeout: 20000
    }
  );
  return { data, headers };
}

// ---------- Routes ----------
app.get('/health', async (req, res) => {
  res.json({
    status: 'ok',
    timeUtc: new Date().toISOString(),
    apiVersion: API_VERSION,
    workspace: {
      subscriptionId: SUBSCRIPTION_ID || '(missing)',
      resourceGroup:  RESOURCE_GROUP  || '(missing)',
      workspaceName:  WORKSPACE_NAME  || '(missing)'
    },
    owner: {
      assignedTo: OWNER.assignedTo,
      userPrincipalName: OWNER.userPrincipalName
    },
    authMode: ARM_TOKEN ? 'static-token' : (AZ_TENANT && AZ_CLIENT ? 'client-credentials' : 'unset')
  });
});

// Single-incident webhook: expects only { incidentName, correlationId? }
app.post('/incident/activate', async (req, res) => {
  const started = Date.now();

  try {
    const raw = req.body && (req.body.body || req.body);
    if (!raw) return res.status(400).json({ error: 'empty body' });

    const incidentName = raw.incidentName;  // Incident ID (name)
    const correlationId = raw.correlationId || req.header('x-ms-workflow-run-id') || '';

    if (!incidentName) return res.status(400).json({ error: 'missing incidentName' });
    if (!SUBSCRIPTION_ID || !RESOURCE_GROUP || !WORKSPACE_NAME) {
      return res.status(500).json({ error: 'workspace-env-missing' });
    }

    const ids = {
      subscriptionId: SUBSCRIPTION_ID,
      resourceGroup:  RESOURCE_GROUP,
      workspaceName:  WORKSPACE_NAME,
      incidentName
    };

    const token = ARM_TOKEN;

    // Incident data directly available in the request body
    const { status, severity, owner, etag } = raw;

    // Final eligibility check
    const eligibleSeverity = ELIGIBLE_SEVERITIES.has(norm(severity));
    const isNew = norm(status) === 'new';
    const unassigned = isUnassigned(owner);

    if (!eligibleSeverity) {
      return res.json({
        incidentName, updated: false, reason: 'high-severity',
        before: { status, owner: ownerSummary(owner) },
        tookMs: Date.now() - started,
        correlationId
      });
    }
    if (!isNew) {
      return res.json({
        incidentName, updated: false, reason: 'not-new',
        before: { status, owner: ownerSummary(owner) },
        tookMs: Date.now() - started,
        correlationId
      });
    }
    if (!unassigned) {
      return res.json({
        incidentName, updated: false, reason: 'already-assigned',
        before: { status, owner: ownerSummary(owner) },
        tookMs: Date.now() - started,
        correlationId
      });
    }

    // PUT update: set status to "Active", assign owner
    const updateProps = {
      title: raw.title,
      severity,
      status: 'Active',
      owner: {
        ...(OWNER.assignedTo        ? { assignedTo: OWNER.assignedTo } : {}),
        ...(OWNER.userPrincipalName ? { userPrincipalName: OWNER.userPrincipalName } : {}),
        ...(OWNER.email             ? { email: OWNER.email } : {}),
        ...(OWNER.objectId          ? { objectId: OWNER.objectId } : {})
      }
    };

    // Try updating
    try {
      const { data: after, headers: putHdrs } = await putIncident(ids, token, etag, updateProps);
      const ap = after.properties || {};
      return res.json({
        incidentName,
        updated: true,
        reason: 'updated',
        before: { status, owner: ownerSummary(owner) },
        after:  { status: ap.status,    owner: ownerSummary(ap.owner || {}) },
        tookMs: Date.now() - started,
        requestId: putHdrs['x-ms-request-id'] || putHdrs['x-ms-correlation-request-id'] || null,
        correlationId
      });
    } catch (e) {
      const r = e.response;
      if (r && r.status === 412) {
        return res.json({
          incidentName, updated: false, reason: 'race-detected',
          before: { status, owner: ownerSummary(owner) },
          tookMs: Date.now() - started,
          requestId: r.headers?.['x-ms-request-id'] || r.headers?.['x-ms-correlation-request-id'] || null,
          correlationId
        });
      }
      return res.status(502).json({
        error: 'arm-update-failed',
        status: r?.status || null,
        details: r?.data || e.message,
        tookMs: Date.now() - started
      });
    }
  } catch (err) {
    return res.status(500).json({ error: 'server-error', details: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`[svc] listening on :${PORT} (API ${API_VERSION})`);
});
