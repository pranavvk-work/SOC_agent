const axios = require('axios');

const CONFIG = {
  TOKEN: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkpZaEFjVFBNWl9MWDZEQmxPV1E3SG4wTmVYRSIsImtpZCI6IkpZaEFjVFBNWl9MWDZEQmxPV1E3SG4wTmVYRSJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvZDdhYjEyMjUtNDY0OS00Y2IzLWFiZDUtYmM3MzJiZWQzMjAzLyIsImlhdCI6MTc1NDg5MzQxOCwibmJmIjoxNzU0ODkzNDE4LCJleHAiOjE3NTQ4OTczMTgsImFpbyI6IkFXUUFtLzhaQUFBQUtqSk9FRW1RWU5neStaVXZkU3Y1ZWZ6UTIzSkJsV3E2YlBZQy9mSVB3L0xGdzdUR0RxRFJtNlhTNWx0eWFST2N4WStpUjB6NUgyd3ozQ2NYWWZpZzFiNlVtUVZOSVpsYzdkdnJBblBRVndvbk1CODBXVHJpU2NvemFTSXpLNVYwIiwiYXBwaWQiOiJkNzE5MGZhYS1iM2FjLTRjMGQtYjA5MC1hZGM2NzRiOTcwNWMiLCJhcHBpZGFjciI6IjEiLCJpZHAiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9kN2FiMTIyNS00NjQ5LTRjYjMtYWJkNS1iYzczMmJlZDMyMDMvIiwiaWR0eXAiOiJhcHAiLCJvaWQiOiI1MGFkY2Y4OS0yZmUxLTQyMTEtYjc4OC1iOTgwYTk5NzIzNGIiLCJyaCI6IjEuQVhFQUpSS3IxMGxHczB5cjFieHpLLTB5QTBaSWYza0F1dGRQdWtQYXdmajJNQk54QUFCeEFBLiIsInN1YiI6IjUwYWRjZjg5LTJmZTEtNDIxMS1iNzg4LWI5ODBhOTk3MjM0YiIsInRpZCI6ImQ3YWIxMjI1LTQ2NDktNGNiMy1hYmQ1LWJjNzMyYmVkMzIwMyIsInV0aSI6IkdnWEVjaEJpRmstMmd2SEhkMDlnQUEiLCJ2ZXIiOiIxLjAiLCJ4bXNfZnRkIjoiLUVpOXFsYXV6REpGTEt5QS1fTGIwRkNjaW83a01iMVBxU1pTZUdpYzFBSUJZWE5wWVhOdmRYUm9aV0Z6ZEMxa2MyMXoiLCJ4bXNfaWRyZWwiOiI3IDEyIiwieG1zX3JkIjoiMC40MkxsWUJKaUxCUVM0V0FYRWxoMS1IM1NSY1BWWHF1UFg1SVU3OW0wRGlqS0tTUndlMmZybFVXSmFWNk5fSjY3ZU5iY19RVVU1UkFTY1BPb3IyVFlkZDFfbF9PdGd6LS1HUWdEQUEiLCJ4bXNfdGNkdCI6MTYzMDkwODU1NH0.FjkYM1ZsYsAKk464nJkERxfP27kropuCwQ0iv_SeyA9MkG4QQfBtfe6Yxpt7S2U5-WNOsIbhW1rP0F7sPnvJKIhXOWLYr9L7mHVZ-vcf7kNvmdjcrg9QicC76ZnwKsOZGwj9UyghmsHE9YjJUejZ66YurYv-PDQp0JNZ79vBPHAXsjJ8kvORblls2UPVqW37T3F5EYICPqWB3WVwq-ZkyssyL2vioBUobK5Jp6ZHbfjNAwEBnocB0YZTNaM1kppIkYoEUm1z-vuH1RZdtMVC7Hj3R6v3Ofri0Zyl7Z0YYgA7YsxcWEL8BXpVZHCzPHONYdB4ao4AGVfHGbVbNjGPug",
  SUBSCRIPTION_ID: '789ffe48-9506-43da-b629-b0b9174bad4d',
  RESOURCE_GROUP: 'SOCAutomationAgent',
  WORKSPACE_NAME: 'SOCAutomation',
  OWNER: {
    objectId: '3f49ac52-8132-4f99-ae1f-052e3036e60a',
    userPrincipalName: 'Vijay.Ganesh@sstlab.in',
    email: 'Vijay.Ganesh@sstlab.in',
    assignedTo: 'Vijay Ganesh'
  }
};

const ARM_API_URL = 'https://management.azure.com';
const API_VERSION = '2025-06-01';
const ELIGIBLE_SEVERITIES = new Set(['informational', 'info', 'low', 'medium']);

const incidentsBasePath = () =>
  `/subscriptions/${CONFIG.SUBSCRIPTION_ID}/resourceGroups/${CONFIG.RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/${CONFIG.WORKSPACE_NAME}/providers/Microsoft.SecurityInsights/incidents`;

// helpers
const norm = (v) => (v ?? '').toString().trim().toLowerCase();
const ownerSummary = (o = {}) => [o.assignedTo, o.userPrincipalName || o.email, o.objectId].filter(Boolean).join(' | ') || '—';
const ownersEqual = (a = {}, b = {}) =>
  norm(a.objectId) === norm(b.objectId) &&
  norm(a.userPrincipalName || a.email) === norm(b.userPrincipalName || b.email) &&
  norm(a.assignedTo) === norm(b.assignedTo);

function toODataDateTimeOffset(d) {
  const iso = (d instanceof Date ? d : new Date(d)).toISOString();
  // strip milliseconds -> 2025-07-12T06:31:42Z
  return iso.replace(/\.\d{3}Z$/, 'Z');
}

// API
async function listIncidentsSince(isoStartNoQuotes) {
  let url = `${ARM_API_URL}${incidentsBasePath()}`;
  let params = {
    'api-version': API_VERSION,
    // IMPORTANT: no quotes around the datetime literal
    '$filter': `properties/createdTimeUtc ge ${isoStartNoQuotes}`,
    '$top': 50,
    '$orderby': 'properties/lastModifiedTimeUtc desc'
  };
  const headers = { Authorization: `Bearer ${CONFIG.TOKEN}` };
  const all = [];
  let page = 0;

  console.log(`[FILTER] ${params['$filter']}`);

  while (url) {
    page += 1;
    console.log(`[FETCH] Page ${page} -> GET ${url}`);
    const { data, headers: h } = await axios.get(url, { headers, params });
    console.log(`[FETCH] Page ${page} received ${data.value?.length ?? 0} item(s). request-id=${h['x-ms-request-id'] || h['x-ms-correlation-request-id'] || 'n/a'}`);
    all.push(...(data.value || []));
    url = data.nextLink || null;
    params = undefined; // nextLink already contains the query
  }
  return all;
}

async function getIncident(id) {
  const url = `${ARM_API_URL}${incidentsBasePath()}/${id}`;
  const { data } = await axios.get(url, {
    headers: { Authorization: `Bearer ${CONFIG.TOKEN}` },
    params: { 'api-version': API_VERSION }
  });
  return data;
}

async function putIncident(id, etag, props) {
  const url = `${ARM_API_URL}${incidentsBasePath()}/${id}`;
  const { data, headers } = await axios.put(
    url,
    { etag, properties: props },
    {
      headers: {
        Authorization: `Bearer ${CONFIG.TOKEN}`,
        'Content-Type': 'application/json'
      },
      params: { 'api-version': API_VERSION }
    }
  );
  return { data, headers };
}

async function updateIncidentIfNeeded(id, desiredStatus, desiredOwner) {
  const before = await getIncident(id);
  const bp = before.properties || {};
  const currentStatus = bp.status;
  const currentOwner = bp.owner || {};

  const statusChanged = norm(currentStatus) !== norm(desiredStatus);
  const ownerChanged = !ownersEqual(currentOwner, desiredOwner);

  if (!statusChanged && !ownerChanged) {
    console.log(`[NO-OP] ${id} | already status='${currentStatus}' & owner='${ownerSummary(currentOwner)}'`);
    return { updated: false };
  }

  console.log(`[APPLY] ${id}`);
  if (statusChanged) console.log(`  Status: '${currentStatus}' -> '${desiredStatus}'`);
  if (ownerChanged)  console.log(`  Owner : '${ownerSummary(currentOwner)}' -> '${ownerSummary(desiredOwner)}'`);

  const props = {
    title: bp.title,
    severity: bp.severity,
    status: statusChanged ? desiredStatus : bp.status,
    owner: ownerChanged ? desiredOwner : currentOwner
  };

  const { data: after, headers } = await putIncident(id, before.etag, props);
  const ap = after.properties || {};

  console.log(`[UPDATED] ${id} (request-id=${headers['x-ms-request-id'] || headers['x-ms-correlation-request-id'] || 'n/a'})`);
  console.log(`  Status: '${currentStatus}' -> '${ap.status}'`);
  console.log(`  Owner : '${ownerSummary(currentOwner)}' -> '${ownerSummary(ap.owner || {})}'`);

  return { updated: true };
}

// main
(async () => {
  try {
    console.log('='.repeat(80));
    console.log('Microsoft Sentinel Incident Processor');
    console.log('='.repeat(80));
    console.log(`Subscription : ${CONFIG.SUBSCRIPTION_ID}`);
    console.log(`ResourceGroup: ${CONFIG.RESOURCE_GROUP}`);
    console.log(`Workspace    : ${CONFIG.WORKSPACE_NAME}`);
    console.log(`API Version  : ${API_VERSION}`);

    const startISO = toODataDateTimeOffset(Date.now() - 30 * 24 * 60 * 60 * 1000);
    console.log(`Time window  : ${startISO} -> now`);

    const incidents = await listIncidentsSince(startISO);
    console.log(`\n[SUMMARY] Found ${incidents.length} incident(s) in last 30 days.`);
    incidents.forEach(i => {
      const p = i.properties || {};
      console.log(`- ${i.name} | "${p.title}" | sev=${p.severity} | status=${p.status} | created=${p.createdTimeUtc}`);
    });

    let eligible = 0, skippedClosed = 0, updated = 0, failed = 0, noop = 0;

    for (const i of incidents) {
      const p = i.properties || {};
      const sev = norm(p.severity);
      const status = norm(p.status);

      if (!ELIGIBLE_SEVERITIES.has(sev)) continue; // only Info/Low/Medium
      eligible += 1;

      if (status === 'closed') {
        skippedClosed += 1;
        console.log(`[SKIP] ${i.name} | severity=${p.severity} but status=Closed`);
        continue;
      }

      try {
        const res = await updateIncidentIfNeeded(i.name, 'Active', CONFIG.OWNER);
        if (res.updated) updated += 1; else noop += 1;
      } catch (e) {
        failed += 1;
        const r = e.response;
        console.error(`[ERROR] ${i.name} | ${r?.status || ''} ${r?.statusText || ''}`);
        if (r?.data) console.error('Response:', JSON.stringify(r.data));
        const cid = r?.headers?.['x-ms-correlation-request-id'] || r?.headers?.['x-ms-request-id'];
        if (cid) console.error('CorrelationId:', cid);
      }
    }

    console.log('\n' + '='.repeat(80));
    console.log('Run Results');
    console.log('='.repeat(80));
    console.log(`Total fetched     : ${incidents.length}`);
    console.log(`Eligible severity : ${eligible}`);
    console.log(`Skipped (Closed)  : ${skippedClosed}`);
    console.log(`Updated           : ${updated}`);
    console.log(`No-ops            : ${noop}`);
    console.log(`Failures          : ${failed}`);
    console.log('\nDone.');
  } catch (err) {
    const r = err.response;
    console.error('[FATAL]', r?.status || '', r?.statusText || '', r?.data || err.message);
    const cid = r?.headers?.['x-ms-correlation-request-id'] || r?.headers?.['x-ms-request-id'];
    if (cid) console.error('CorrelationId:', cid);
    process.exitCode = 1;
  }
})();
