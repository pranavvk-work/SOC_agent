const express = require('express');
const axios = require('axios');

const app = express();
app.use(express.json({ limit: '1mb' }));

// ---------- Config ----------
const PORT = process.env.PORT || 8000;
const API_VERSION = process.env.API_VERSION || '2025-06-01';

// Workspace context from ENV (required)
const SUBSCRIPTION_ID = process.env.SUBSCRIPTION_ID ?? "789ffe48-9506-43da-b629-b0b9174bad4d";
const RESOURCE_GROUP = process.env.RESOURCE_GROUP ?? "SOCAutomationAgent";
const WORKSPACE_NAME = process.env.WORKSPACE_NAME ?? "SOCAutomation";

// Owner config (fill what you have)
const OWNER = {
  assignedTo: process.env.OWNER_NAME || 'Vijay Ganesh',
  userPrincipalName: process.env.OWNER_UPN || 'Vijay.Ganesh@sstlab.in',
  email: process.env.OWNER_EMAIL || 'Vijay.Ganesh@sstlab.in',
  objectId: process.env.OWNER_OBJECT_ID || '3f49ac52-8132-4f99-ae1f-052e3036e60a'
};

// Auth: static token OR client credentials
const ARM_TOKEN = process.env.ARM_TOKEN || "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkpZaEFjVFBNWl9MWDZEQmxPV1E3SG4wTmVYRSIsImtpZCI6IkpZaEFjVFBNWl9MWDZEQmxPV1E3SG4wTmVYRSJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvZDdhYjEyMjUtNDY0OS00Y2IzLWFiZDUtYmM3MzJiZWQzMjAzLyIsImlhdCI6MTc1NDk5MTY5MiwibmJmIjoxNzU0OTkxNjkyLCJleHAiOjE3NTQ5OTU1OTIsImFpbyI6IkFXUUFtLzhaQUFBQTh4U2JKNFVuQ0t0NnVsQjdqSS9QaXRNbS84Y0pHTzk2Sit1VVBYdnhtN01QYjQzanlvSTc5NWxkK2FkZlIxYlVUc3hUWENpQnpiS2xRRHJWVUNjS2dZcGtUcGlxdjZNK2ExVWFpMnRkUG9HaEZ6ckw1dWlqWS96OFhjTjl2clNQIiwiYXBwaWQiOiJkNzE5MGZhYS1iM2FjLTRjMGQtYjA5MC1hZGM2NzRiOTcwNWMiLCJhcHBpZGFjciI6IjEiLCJpZHAiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9kN2FiMTIyNS00NjQ5LTRjYjMtYWJkNS1iYzczMmJlZDMyMDMvIiwiaWR0eXAiOiJhcHAiLCJvaWQiOiI1MGFkY2Y4OS0yZmUxLTQyMTEtYjc4OC1iOTgwYTk5NzIzNGIiLCJyaCI6IjEuQVhFQUpSS3IxMGxHczB5cjFieHpLLTB5QTBaSWYza0F1dGRQdWtQYXdmajJNQk54QUFCeEFBLiIsInN1YiI6IjUwYWRjZjg5LTJmZTEtNDIxMS1iNzg4LWI5ODBhOTk3MjM0YiIsInRpZCI6ImQ3YWIxMjI1LTQ2NDktNGNiMy1hYmQ1LWJjNzMyYmVkMzIwMyIsInV0aSI6InBCZlFHWGVkbmstcU5fQjVycE1YQUEiLCJ2ZXIiOiIxLjAiLCJ4bXNfZnRkIjoiTUtmRFdUT2F0STFtTFVuYnNiRkFtNzlQMWxCRjVybEZqQnRMRnA1bHdib0JZWE5wWVhOdmRYUm9aV0Z6ZEMxa2MyMXoiLCJ4bXNfaWRyZWwiOiIyMCA3IiwieG1zX3JkIjoiMC40MkxsWUJKaUxCUVM0V0FYRWxoMS1IM1NSY1BWWHF1UFg1SVU3OW0wRGlqS0tTUndlMmZybFVXSmFWNk5fSjY3ZU5iY19RVVU1UkFTY1BPb3IyVFlkZDFfbF9PdGd6LS1HUWdEQUEiLCJ4bXNfdGNkdCI6MTYzMDkwODU1NH0.D_5L6yzWETSF7iA2CNkzqw3igbL08mSj7YDcpg6zCUOwcFFlWfRvdYLFdlfgHHtzNt3CUzvvCD-9OnraMf9HtZ1rVDLT-Xzo_BStg_FsrTX0KrrlFpl8s2a7F66dTUO1mo1uYcRpPE_kq-jsvBQpQiySoWSVNqpaJ11Ee5i7jVlF-zcsN60LdxsMwq2VACaZpzB1XezuYcofU4-XnIZ0Hpae2bXW5qZKTlJxfsIWcgaMmrAB7J3pgtMvPMzCQvobG51-y4Q763iTcPK67bgl220dmsz7mO6w3RUJtKaltqY2K4yayspl0KbOM05r6UJ69PKkPJKu7zUF3OVZaiAhug";

const ARM_API = 'https://management.azure.com';
const norm = (v) => (v ?? '').toString().trim().toLowerCase();

// ---------- Utilities ----------
function ownerSummary(o = {}) {
  const parts = [o.assignedTo, o.userPrincipalName || o.email, o.objectId].filter(Boolean);
  return parts.length ? parts.join(' | ') : '—';
}

// ---------- ARM calls ----------
async function putIncident(ids, token, etag, props) {
  const url = `${ARM_API}/subscriptions/${ids.subscriptionId}/resourceGroups/${ids.resourceGroup}` +
    `/providers/Microsoft.OperationalInsights/workspaces/${ids.workspaceName}` +
    `/providers/Microsoft.SecurityInsights/incidents/${ids.incidentName}?api-version=${API_VERSION}`;
  
  console.log(`[PUT] Attempting to update incident: ${ids.incidentName} at ${new Date().toISOString()}`);
  
  const { data, headers } = await axios.put(
    url,
    { etag, properties: props },
    {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      timeout: 20000
    }
  );
  
  console.log(`[PUT] Incident update successful for ${ids.incidentName} at ${new Date().toISOString()}`);
  
  return { data, headers };
}

async function getIncidentDetails(ids, token) {
  const url = `${ARM_API}/subscriptions/${ids.subscriptionId}/resourceGroups/${ids.resourceGroup}` +
    `/providers/Microsoft.OperationalInsights/workspaces/${ids.workspaceName}` +
    `/providers/Microsoft.SecurityInsights/incidents/${ids.incidentName}?api-version=${API_VERSION}`;
  
  console.log(`[GET] Fetching details for incident: ${ids.incidentName} at ${new Date().toISOString()}`);
  
  const { data } = await axios.get(url, {
    headers: { Authorization: `Bearer ${token}` },
    timeout: 20000
  });

  console.log(`[GET] Incident details fetched for ${ids.incidentName} at ${new Date().toISOString()}`);
  
  return data;
}

// ---------- Routes ----------
app.get('/health', async (req, res) => {
  res.json({
    status: 'ok',
    timeUtc: new Date().toISOString(),
    apiVersion: API_VERSION,
    workspace: {
      subscriptionId: SUBSCRIPTION_ID || '(missing)',
      resourceGroup: RESOURCE_GROUP || '(missing)',
      workspaceName: WORKSPACE_NAME || '(missing)'
    },
    owner: {
      assignedTo: OWNER.assignedTo,
      userPrincipalName: OWNER.userPrincipalName
    },
    authMode: ARM_TOKEN ? 'static-token' : 'unset'
  });
});

// Single-incident webhook: expects only { incidentName, correlationId? }
app.post('/incident/activate', async (req, res) => {
  const started = Date.now();

  try {
    // Extract raw data from the request body
    const raw = req.body && (req.body.body || req.body);
    if (!raw) return res.status(400).json({ error: 'empty body' });

    const incidentName = raw.incidentName;  // Incident ID (name)
    const correlationId = raw.correlationId || req.header('x-ms-workflow-run-id') || '';

    console.log(`[POST] Webhook received at ${new Date().toISOString()}. Incident: ${incidentName}`);

    if (!incidentName) return res.status(400).json({ error: 'missing incidentName' });
    if (!SUBSCRIPTION_ID || !RESOURCE_GROUP || !WORKSPACE_NAME) {
      return res.status(500).json({ error: 'workspace-env-missing' });
    }

    const ids = {
      subscriptionId: SUBSCRIPTION_ID,
      resourceGroup: RESOURCE_GROUP,
      workspaceName: WORKSPACE_NAME,
      incidentName
    };

    const token = ARM_TOKEN;

    // Fetch the existing incident properties to retain non-changed fields
    try {
      const incident = await getIncidentDetails(ids, token);
      if (!incident || !incident.properties) {
        return res.status(400).json({ error: 'incident-not-found' });
      }

      console.log(`[GET] Incident properties fetched for ${incidentName} at ${new Date().toISOString()}`);

      // Retain existing properties like severity, title, etc.
      const { severity, title, etag } = incident.properties;

      // Prepare the update payload with only the necessary changes
      const status = 'Active';  // Hardcoding the status to Active
      const owner = {
        assignedTo: OWNER.assignedTo,
        userPrincipalName: OWNER.userPrincipalName,
        email: OWNER.email,
        objectId: OWNER.objectId
      };

      const updateProps = {
        title: title,   // Keep the title unchanged
        severity: severity, // Keep the severity unchanged
        status: status, // Set status to Active
        owner: owner    // Set the new owner
      };

      // Perform the incident update
      console.log(`[PUT] Updating incident: ${incidentName} at ${new Date().toISOString()}`);
      
      const { data: after, headers: putHdrs } = await putIncident(ids, token, etag, updateProps);

      console.log(`[PUT] Incident updated successfully for ${incidentName} at ${new Date().toISOString()}`);
      
      return res.json({
        incidentName,
        updated: true,
        reason: 'updated',
        before: { status: incident.properties.status, owner: ownerSummary(incident.properties.owner) },
        after: { status: after.properties.status, owner: ownerSummary(after.properties.owner) },
        tookMs: Date.now() - started,
        requestId: putHdrs['x-ms-request-id'] || putHdrs['x-ms-correlation-request-id'] || null,
        correlationId
      });
    } catch (err) {
      console.log(`[ERROR] Error fetching incident details for ${incidentName} at ${new Date().toISOString()},${err.message}`);
      return res.status(502).json({
        error: 'incident-fetch-failed',
        details: err.message,
        tookMs: Date.now() - started
      });
    }
  } catch (err) {
    console.log(`[ERROR] Server error occurred at ${new Date().toISOString()}`);
    return res.status(500).json({ error: 'server-error', details: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`[svc] listening on :${PORT} (API ${API_VERSION})`);
});
