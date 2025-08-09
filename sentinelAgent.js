// Microsoft Sentinel (Azure Resource Manager) configuration
const axios = require('axios');

const CONFIG = {
  CLIENT_ID: 'd7190faa-b3ac-4c0d-b090-adc674b9705c',
  CLIENT_SECRET: 'kMj8Q~ECiZEve_tELf02PgNh.dy7K1O4EW8e7bHM',
  TENANT_ID: 'd7ab1225-4649-4cb3-abd5-bc732bed3203',
  SUBSCRIPTION_ID: '789ffe48-9506-43da-b629-b0b9174bad4d',
  RESOURCE_GROUP: 'socautomationagent',
  WORKSPACE_NAME: 'SOCAutomation',
  // Optional: set owner to assign the incident
  OWNER: {
    OBJECT_ID: '3f49ac52-8132-4f99-ae1f-052e3036e60a',             // Azure AD objectId for the user
    USER_PRINCIPAL_NAME: 'Vijay.Ganesh@sstlab.in',        // UPN of the user
    EMAIL: 'Vijay.Ganesh@sstlab.in',                      // Email of the user
    ASSIGNED_TO: 'Vijay Ganesh'                // Display name
  }
};

const ARM_API_URL = 'https://management.azure.com';
const AUTH_URL = `https://login.microsoftonline.com/${CONFIG.TENANT_ID}/oauth2/v2.0/token`;
const API_VERSION = '2023-02-01'; // Microsoft.SecurityInsights stable API version

// Validate required configuration early
function validateConfig() {
  const missing = Object.entries(CONFIG)
    .filter(([k, v]) => !['OWNER'].includes(k))
    .filter(([, v]) => !v || (typeof v === 'string' && v.startsWith('YOUR_')))
    .map(([k]) => k);
  if (missing.length > 0) {
    throw new Error(`Missing required configuration values: ${missing.join(', ')}. Please fill them in CONFIG.`);
  }
}

function buildOwnerFromConfig() {
  const o = CONFIG.OWNER || {};
  const hasAny = [o.OBJECT_ID, o.USER_PRINCIPAL_NAME, o.EMAIL, o.ASSIGNED_TO]
    .some((v) => v && !String(v).startsWith('YOUR_'));
  if (!hasAny) return undefined;
  const owner = {};
  if (o.OBJECT_ID && !o.OBJECT_ID.startsWith('YOUR_')) owner.objectId = o.OBJECT_ID;
  if (o.USER_PRINCIPAL_NAME && !o.USER_PRINCIPAL_NAME.startsWith('YOUR_')) owner.userPrincipalName = o.USER_PRINCIPAL_NAME;
  if (o.EMAIL && !o.EMAIL.startsWith('YOUR_')) owner.email = o.EMAIL;
  if (o.ASSIGNED_TO && !o.ASSIGNED_TO.startsWith('YOUR_')) owner.assignedTo = o.ASSIGNED_TO;
  return Object.keys(owner).length ? owner : undefined;
}

function decodeJwtPayload(token) {
  try {
    const [, payloadB64] = token.split('.');
    const normalized = payloadB64.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
    const json = Buffer.from(padded, 'base64').toString('utf8');
    return JSON.parse(json);
  } catch {
    return {};
  }
}

// Acquire ARM access token (client credentials)
async function getAccessToken() {
  const payload = new URLSearchParams();
  payload.append('client_id', CONFIG.CLIENT_ID);
  payload.append('client_secret', CONFIG.CLIENT_SECRET);
  payload.append('grant_type', 'client_credentials');
  payload.append('scope', 'https://management.azure.com/.default');

  try {
    const response = await axios.post(AUTH_URL, payload);
    const token = response.data.access_token;
    const claims = decodeJwtPayload(token);
    if (claims?.scp) {
      console.log('Token scopes:', claims.scp);
    }
    return token;
  } catch (error) {
    console.error('Error retrieving access token:', error.response?.data || error.message);
    throw error;
  }
}

function incidentsBasePath() {
  return `/subscriptions/${CONFIG.SUBSCRIPTION_ID}/resourceGroups/${CONFIG.RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/${CONFIG.WORKSPACE_NAME}/providers/Microsoft.SecurityInsights/incidents`;
}

// List Microsoft Sentinel incidents
async function getIncidents() {
  const token = await getAccessToken();
  try {
    const url = `${ARM_API_URL}${incidentsBasePath()}`;
    const response = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      params: {
        'api-version': API_VERSION,
        '$filter': "properties/status eq 'New'",
        '$top': 25,
        '$orderby': 'properties/lastModifiedTimeUtc desc'
      }
    });
    const incidents = response.data.value || [];
    console.log(`Retrieved ${incidents.length} incident(s)`);
    return incidents;
  } catch (error) {
    console.error('Error retrieving incidents:', error.response?.data || error.message);
    throw error;
  }
}

// Get details for a specific Sentinel incident
async function getIncidentDetails(incidentId) {
  const token = await getAccessToken();
  try {
    const url = `${ARM_API_URL}${incidentsBasePath()}/${incidentId}`;
    const response = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      params: {
        'api-version': API_VERSION
      }
    });
    const incidentDetails = response.data;
    console.log('Incident details retrieved');
    return incidentDetails;
  } catch (error) {
    console.error('Error retrieving incident details:', error.response?.data || error.message);
    throw error;
  }
}

// Update Sentinel incident: status and optional owner assignment
async function updateIncident(incidentId, { status, owner }) {
  const token = await getAccessToken();
  try {
    const url = `${ARM_API_URL}${incidentsBasePath()}/${incidentId}`;
    const body = { properties: {} };
    if (status) body.properties.status = status; // 'New' | 'Active' | 'Closed'
    if (owner) body.properties.owner = owner;    // { objectId?, email?, assignedTo?, userPrincipalName? }

    const response = await axios.patch(
      url,
      body,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
          'If-Match': '*'
        },
        params: {
          'api-version': API_VERSION
        }
      }
    );
    console.log(`Incident updated${status ? `, status=${status}` : ''}${owner ? ', owner set' : ''}`);
    return response.data;
  } catch (error) {
    console.error('Error updating incident:', error.response?.data || error.message);
    throw error;
  }
}

// Main
async function run() {
  try {
    validateConfig();

    // Fetch incidents
    const incidents = await getIncidents();
    if (!incidents.length) {
      console.log('No incidents found');
      return;
    }

    // Use the first incident
    const first = incidents[0];
    const incidentId = first.name; // ARM resource name (GUID)
    const details = await getIncidentDetails(incidentId);
    console.log('Incident ID:', incidentId);
    console.log('Incident Title:', details?.properties?.title);

    // Prepare optional owner assignment from CONFIG
    const owner = buildOwnerFromConfig();

    // Example: Move status to 'Active' and assign if owner provided
    await updateIncident(incidentId, { status: 'Active', owner });
  } catch (error) {
    console.error('Error during incident handling:', error.response?.data || error.message);
  }
}

run();
