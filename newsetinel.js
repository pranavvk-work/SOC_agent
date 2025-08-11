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
    // console.log(`Found  new incident(s).`,incidents);
    if (!incidents.length) return console.log('No new incidents found.');

    const incident = incidents[0];
    console.log(`Found incident: ${incident.name} - ${incident.properties.title}`);

    await updateIncident(incident.name, 'Active', CONFIG.OWNER);
  } catch (err) {
    console.error('Error:', err.response?.data || err.message,err);
  }
})();
