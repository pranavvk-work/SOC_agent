const axios = require('axios');

const CONFIG = {
  TOKEN: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IkpZaEFjVFBNWl9MWDZEQmxPV1E3SG4wTmVYRSIsImtpZCI6IkpZaEFjVFBNWl9MWDZEQmxPV1E3SG4wTmVYRSJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvZDdhYjEyMjUtNDY0OS00Y2IzLWFiZDUtYmM3MzJiZWQzMjAzLyIsImlhdCI6MTc1NDg4OTgxMywibmJmIjoxNzU0ODg5ODEzLCJleHAiOjE3NTQ4OTM3MTMsImFpbyI6IkFXUUFtLzhaQUFBQTRZT1RKdmRDa3VYZWkvaXRVbDd1bEZwYlcxa0FBa00xSVhtQVpzVDRKM3lDWW9XUyswcTV6NDBGWE9vQ2pTblBuQ1c5ek84dnFSeWlsMUs1SDRHS29GYXdjdjBlRmg0Q3JQT3l1MExja0pPeStndUNCNW1ENnRmQUNvQjQySWFVIiwiYXBwaWQiOiJkNzE5MGZhYS1iM2FjLTRjMGQtYjA5MC1hZGM2NzRiOTcwNWMiLCJhcHBpZGFjciI6IjEiLCJpZHAiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9kN2FiMTIyNS00NjQ5LTRjYjMtYWJkNS1iYzczMmJlZDMyMDMvIiwiaWR0eXAiOiJhcHAiLCJvaWQiOiI1MGFkY2Y4OS0yZmUxLTQyMTEtYjc4OC1iOTgwYTk5NzIzNGIiLCJyaCI6IjEuQVhFQUpSS3IxMGxHczB5cjFieHpLLTB5QTBaSWYza0F1dGRQdWtQYXdmajJNQk54QUFCeEFBLiIsInN1YiI6IjUwYWRjZjg5LTJmZTEtNDIxMS1iNzg4LWI5ODBhOTk3MjM0YiIsInRpZCI6ImQ3YWIxMjI1LTQ2NDktNGNiMy1hYmQ1LWJjNzMyYmVkMzIwMyIsInV0aSI6ImZQM0duYXpneUUyNDkxREZ5dEZpQUEiLCJ2ZXIiOiIxLjAiLCJ4bXNfZnRkIjoiMkRWOXI3Qk05TW9wRU5sN3JkYzFQTG53MzdkQ05OM0ZnbUpSbVNUNHNMSUJhbUZ3WVc1bFlYTjBMV1J6YlhNIiwieG1zX2lkcmVsIjoiMjYgNyIsInhtc19yZCI6IjAuNDJMbFlCSmlMQlFTNFdBWEVsaDEtSDNTUmNQVlhxdVBYNUlVNzltMERpaktLU1J3ZTJmcmxVV0phVjZOX0o2N2VOYmNfUVVVNVJBU2NQT29yMlRZZGQxX2xfT3Rnei0tR1FnREFBIiwieG1zX3RjZHQiOjE2MzA5MDg1NTR9.TaP3qYk_NOa2FUhCJ93yVCFzJXC2ATIdSI0bdlR_50d7dG0xww8q8dObHrq4_9L_yIJQ-mX2x9xjE6P3ZWG9sjQ6nWdbq4aPgDn_GNs58CSruQca7TlBZno-FJlNo93ceCmcDxHPaHn-_gqYWIJBlgTtCma9OW9WNP0kMeMBbdSlBcDZM2Uvj0PCWZ9FAI0KWDLsJRZr8_9ZUgp-qcRAv5PVlP6HY8YcTMLPKLJfV9Qk5ZXfCOhVrPSddJKbe5_DoYvcV99W5erVeNsroJsFx-MIUibN3CyAeEPnCrhoLzqxkd8XABPDDtdUrwdq1CJ0nI0og3knLTYeao-oVN1jEg",
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

const incidentsBasePath = () =>
  `/subscriptions/${CONFIG.SUBSCRIPTION_ID}/resourceGroups/${CONFIG.RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/${CONFIG.WORKSPACE_NAME}/providers/Microsoft.SecurityInsights/incidents`;

// GET incidents
async function getIncidents() {
  const url = `${ARM_API_URL}${incidentsBasePath()}`;
  const { data } = await axios.get(url, {
    headers: { Authorization: `Bearer ${CONFIG.TOKEN}` },
    params: {
      'api-version': API_VERSION,
      '$filter': "properties/status eq 'New'",
      '$top': 1,
      '$orderby': 'properties/lastModifiedTimeUtc desc'
    }
  });
  return data.value || [];
}

// UPDATE incident
async function updateIncident(id, status, owner) {
  const url = `${ARM_API_URL}${incidentsBasePath()}/${id}`;
  await axios.patch(url, {
    properties: { status, owner }
  }, {
    headers: {
      Authorization: `Bearer ${CONFIG.TOKEN}`,
      'If-Match': '*'
    },
    params: { 'api-version': API_VERSION }
  });
  console.log(`Incident ${id} updated to '${status}' and assigned.`);
}

// MAIN
(async () => {
  try {
    const incidents = await getIncidents();
    console.log(`Found  new incident(s).`,incidents);
    if (!incidents.length) return console.log('No new incidents found.');

    const incident = incidents[0];
    console.log(`Found incident: ${incident.name} - ${incident.properties.title}`);

    await updateIncident(incident.name, 'Active', CONFIG.OWNER);
  } catch (err) {
    console.error('Error:', err.response?.data || err.message);
  }
})();
