const express = require('express');
const msal = require('@azure/msal-node');

// Filled with your web app registration values
const CONFIG = {
  CLIENT_ID: 'd7190faa-b3ac-4c0d-b090-adc674b9705c',
  TENANT_ID: 'd7ab1225-4649-4cb3-abd5-bc732bed3203',
  CLIENT_SECRET: 'kMj8Q~ECiZEve_tELf02PgNh.dy7K1O4EW8e7bHM',
  REDIRECT_URI: 'http://localhost:3000/redirect',
};

function validateConfig() {
  const missing = Object.entries(CONFIG)
    .filter(([, v]) => !v || v.startsWith('YOUR_'))
    .map(([k]) => k);
  if (missing.length) {
    throw new Error(`Missing config: ${missing.join(', ')}. Edit CONFIG in authServer.js.`);
  }
}

async function main() {
  validateConfig();

  const clientConfig = {
    auth: {
      clientId: CONFIG.CLIENT_ID,
      authority: `https://login.microsoftonline.com/${CONFIG.TENANT_ID}`,
      clientSecret: CONFIG.CLIENT_SECRET,
    },
    system: { loggerOptions: { piiLoggingEnabled: false, logLevel: msal.LogLevel.Info } },
  };

  const cca = new msal.ConfidentialClientApplication(clientConfig);
  const app = express();
  const PORT = 3000;
  const SCOPES = ['User.Read'];

  app.get('/', async (req, res) => {
    try {
      const authCodeUrl = await cca.getAuthCodeUrl({ scopes: SCOPES, redirectUri: CONFIG.REDIRECT_URI });
      res.redirect(authCodeUrl);
    } catch (e) {
      console.error('Error building auth URL:', e.message || e);
      res.status(500).send('Auth URL error');
    }
  });

  app.get('/redirect', async (req, res) => {
    try {
      const tokenResponse = await cca.acquireTokenByCode({
        code: req.query.code,
        scopes: SCOPES,
        redirectUri: CONFIG.REDIRECT_URI,
      });
      console.log('Access token acquired. ExpiresOn:', tokenResponse.expiresOn);
      res.status(200).send('OK');
    } catch (e) {
      console.error('Auth error:', e);
      res.status(500).send(e.message || 'Auth error');
    }
  });

  app.listen(PORT, () => console.log(`Auth server running on http://localhost:${PORT}`));
}

main().catch((e) => {
  console.error('Startup error:', e.message || e);
  process.exit(1);
}); 