// Microsoft Sentinel (Azure Resource Manager) configuration
const axios = require('axios');

const CONFIG = {
  CLIENT_ID: 'd7190faa-b3ac-4c0d-b090-adc674b9705c',
  CLIENT_SECRET: 'kMj8Q~ECiZEve_tELf02PgNh.dy7K1O4EW8e7bHM',
  TENANT_ID: 'd7ab1225-4649-4cb3-abd5-bc732bed3203',
  SUBSCRIPTION_ID: '789ffe48-9506-43da-b629-b0b9174bad4d',
  RESOURCE_GROUP: 'SOCAutomationAgent',
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
const API_VERSION = '2025-06-01'; // Microsoft.SecurityInsights stable API version

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
async function getArmToken() {
  const payload = new URLSearchParams();
  payload.append('client_id', CONFIG.CLIENT_ID);
  payload.append('client_secret', CONFIG.CLIENT_SECRET);
  payload.append('grant_type', 'client_credentials');
  payload.append('scope', 'https://management.azure.com/.default');

  try {
    // const response = await axios.post(AUTH_URL, payload);
    // const token = response.data.access_token;
    // const claims = decodeJwtPayload(token);
    // if (claims?.scp) {
    //   console.log('Token scopes:', claims.scp);
    // }
    return "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkpZaEFjVFBNWl9MWDZEQmxPV1E3SG4wTmVYRSIsImtpZCI6IkpZaEFjVFBNWl9MWDZEQmxPV1E3SG4wTmVYRSJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvZDdhYjEyMjUtNDY0OS00Y2IzLWFiZDUtYmM3MzJiZWQzMjAzLyIsImlhdCI6MTc1NDg4ODM0NywibmJmIjoxNzU0ODg4MzQ3LCJleHAiOjE3NTQ4OTIyNDcsImFpbyI6IkFXUUFtLzhaQUFBQWtYV284a1h3Znd0eHRCanlsdzMxYVhYOUZoWUxtSmZuemFwYlpWRElKR294dkkzZFNkZFEyd2MrdVRsMkFDcWJJL0FheEhGQkNnZ000VkRwMFRIYW13dVpLcEloa0pwSHNVNUR1N2FaaDN2cG5TUlBGV1JVUWxxVjUyekRjbG5xIiwiYXBwaWQiOiJkNzE5MGZhYS1iM2FjLTRjMGQtYjA5MC1hZGM2NzRiOTcwNWMiLCJhcHBpZGFjciI6IjEiLCJpZHAiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9kN2FiMTIyNS00NjQ5LTRjYjMtYWJkNS1iYzczMmJlZDMyMDMvIiwiaWR0eXAiOiJhcHAiLCJvaWQiOiI1MGFkY2Y4OS0yZmUxLTQyMTEtYjc4OC1iOTgwYTk5NzIzNGIiLCJyaCI6IjEuQVhFQUpSS3IxMGxHczB5cjFieHpLLTB5QTBaSWYza0F1dGRQdWtQYXdmajJNQk54QUFCeEFBLiIsInN1YiI6IjUwYWRjZjg5LTJmZTEtNDIxMS1iNzg4LWI5ODBhOTk3MjM0YiIsInRpZCI6ImQ3YWIxMjI1LTQ2NDktNGNiMy1hYmQ1LWJjNzMyYmVkMzIwMyIsInV0aSI6IktRUGVxN1oyRUUtME1DMzlGeTFnQUEiLCJ2ZXIiOiIxLjAiLCJ4bXNfZnRkIjoiNHFNTnp6ZDNwOFJ2bzY5cUJHajdEdjVGbHdjUjBfMUNKU3BLVlQ4NVI4VUJhMjl5WldGalpXNTBjbUZzTFdSemJYTSIsInhtc19pZHJlbCI6IjcgMzIiLCJ4bXNfcmQiOiIwLjQyTGxZQkppTEJRUzRXQVhFbGgxLUgzU1JjUFZYcXVQWDVJVTc5bTBEaWpLS1NSd2UyZnJsVVdKYVY2Tl9KNjdlTmJjX1FVVTVSQVNjUE9vcjJUWWRkMV9sX090Z3otLUdRZ0RBQSIsInhtc190Y2R0IjoxNjMwOTA4NTU0fQ.Q8xJj74DqZZLkfd8VdOVsF96xAyFgEhrVzF4WmaKd_T3mbu7smZDagqSC5scg0eQQdhOZWNNIzV9nYSG3NgzRvN2tNvw7qa_l2mEjm1cUIFPSbkG37DDAbxRGphpla5sbO4FJrpwexjqfMeabEXi_wbvq_wxVdRJTNcu-wzHHKE-F7e4WbgJpXNiDKT9BatWE8bxcrNdWqn1CMcQxr1rkMfCj2IGRBFp0syJpwoo0Jy6HaFCUebS_-7Wt2aBTyzsiijpMfcTW8-PrOxtrrgRkjKiZ2-b1j4adWofVFghmwsi7j-WTlVIMDApZBl6TMIyo3aYJY-6mEtqiUfYymLZ5Q";
  } catch (error) {
    // console.error('Error retrieving access token:', error.response?.data || error.message);
    // throw error;
  }
}

function incidentsBasePath() {
  return `/subscriptions/${CONFIG.SUBSCRIPTION_ID}/resourceGroups/${CONFIG.RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/${CONFIG.WORKSPACE_NAME}/providers/Microsoft.SecurityInsights/incidents`;
}

// List Microsoft Sentinel incidents
async function getIncidents() {
  const token = await getArmToken();
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
  const token = await getArmToken();
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
  const token = await getArmToken();
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
