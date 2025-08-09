// Import required libraries
require('dotenv').config();  // To load environment variables
const axios = require('axios');

// Set up constants and configurations
const API_URL = 'https://api.security.microsoft.com';  // Base URL for Sentinel API
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const TENANT_ID = process.env.TENANT_ID;
const WORKSPACE_ID = process.env.WORKSPACE_ID;
const AUTH_URL = `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`;

// Function to get an access token from Microsoft Identity Platform (OAuth2.0)
async function getAccessToken() {
  const payload = new URLSearchParams();
  payload.append('client_id', CLIENT_ID);
  payload.append('client_secret', CLIENT_SECRET);
  payload.append('grant_type', 'client_credentials');
  payload.append('scope', 'https://api.security.microsoft.com/.default');  // Corrected scope for Sentinel API
  
  try {
    const response = await axios.post(AUTH_URL, payload);
    return response.data.access_token;  // Return the access token
  } catch (error) {
    console.error('Error retrieving access token:', error.response?.data || error);
    throw error;
  }
}

// Function to retrieve incidents from Microsoft Sentinel
async function getIncidents() {
  const token = await getAccessToken();  // Get OAuth token
  
  try {
    const response = await axios.get(`${API_URL}/api/incidents`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      params: {
        // Filter incidents (e.g., New, Active)
        'status': 'New',  // Filter for new incidents
        'workspaceId': WORKSPACE_ID
      }
    });

    const incidents = response.data.value;
    console.log('Retrieved incidents:', incidents);
    return incidents;
  } catch (error) {
    console.error('Error retrieving incidents:', error.response?.data || error);
    throw error;
  }
}

// Function to get details of a specific incident
async function getIncidentDetails(incidentId) {
  const token = await getAccessToken();  // Get OAuth token
  
  try {
    const response = await axios.get(`${API_URL}/api/incidents/${incidentId}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      params: {
        'workspaceId': WORKSPACE_ID
      }
    });

    const incidentDetails = response.data;
    console.log('Incident details:', incidentDetails);
    return incidentDetails;
  } catch (error) {
    console.error('Error retrieving incident details:', error.response?.data || error);
    throw error;
  }
}

// Function to update the status of an incident
async function updateIncidentStatus(incidentId, status) {
  const token = await getAccessToken();  // Get OAuth token
  
  try {
    const response = await axios.patch(`${API_URL}/api/incidents/${incidentId}`, 
    {
      "status": status  // Status to update (e.g., 'InProgress', 'Resolved')
    }, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });

    console.log(`Incident status updated to: ${status}`);
    return response.data;
  } catch (error) {
    console.error('Error updating incident status:', error.response?.data || error);
    throw error;
  }
}

// Main function to simulate the process
async function run() {
  try {
    // Fetch all new incidents
    const incidents = await getIncidents();  // Get all new incidents
    
    // Handle the first incident (can be customized)
    const incidentId = incidents[0]?.id;  // Assume first incident for simplicity
    if (incidentId) {
      const details = await getIncidentDetails(incidentId);  // Fetch incident details
      console.log('Incident Details:', details);

      // Example: Update the incident status to 'InProgress'
      await updateIncidentStatus(incidentId, 'InProgress');  // Update the status
    }
  } catch (error) {
    console.error('Error during incident handling:', error);
  }
}

// Execute the main function
run();
