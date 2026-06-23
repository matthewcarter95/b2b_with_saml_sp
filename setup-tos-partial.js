'use strict';

/**
 * One-shot script: configures the signup-id ULP screen to include a
 * Terms-of-Service checkbox (field name: ulp-terms-of-service) via the
 * Auth0 Management API prompt-partials endpoint.
 *
 * Requires the same PROFILE_MGMT_* env vars already used by server.js.
 *
 * Usage:  node setup-tos-partial.js [--dry-run]
 */

require('dotenv').config();

const axios = require('axios');

const DRY_RUN = process.argv.includes('--dry-run');

const TOS_PARTIAL = `
<div class="tos-consent" style="margin:1rem 0 0.5rem;">
  <label style="display:flex;align-items:flex-start;gap:0.6rem;cursor:pointer;font-size:0.875rem;line-height:1.4;">
    <input
      type="checkbox"
      name="ulp-terms-of-service"
      value="true"
      required
      style="margin-top:3px;flex-shrink:0;width:1rem;height:1rem;"
    />
    <span>
      I have read and agree to the
      <a href="${process.env.TOS_URL || 'https://example.com/terms'}" target="_blank" rel="noopener noreferrer">
        Terms of Service
      </a>
    </span>
  </label>
</div>
`.trim();

async function getMgmtToken() {
  const resp = await axios.post(
    process.env.PROFILE_MGMT_TOKEN_URL,
    new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: process.env.PROFILE_MGMT_CLIENT_ID,
      client_secret: process.env.PROFILE_MGMT_CLIENT_SECRET,
      audience: process.env.PROFILE_MGMT_AUDIENCE,
    }).toString(),
    { headers: { 'content-type': 'application/x-www-form-urlencoded' }, validateStatus: () => true }
  );
  if (resp.status < 200 || resp.status >= 300 || !resp.data.access_token) {
    throw new Error(`Token request failed (HTTP ${resp.status}): ${JSON.stringify(resp.data)}`);
  }
  return resp.data.access_token;
}

async function main() {
  const required = ['PROFILE_MGMT_TOKEN_URL', 'PROFILE_MGMT_CLIENT_ID', 'PROFILE_MGMT_CLIENT_SECRET', 'PROFILE_MGMT_AUDIENCE'];
  const missing = required.filter((k) => !process.env[k]);
  if (missing.length) {
    console.error('Missing required env vars:', missing.join(', '));
    process.exit(1);
  }

  const apiBase = process.env.PROFILE_MGMT_AUDIENCE.replace(/\/?$/, '');

  const partialBody = {
    'signup-id': {
      'form-content-end': TOS_PARTIAL,
    },
  };

  console.log('Prompt partial payload:');
  console.log(JSON.stringify(partialBody, null, 2));

  if (DRY_RUN) {
    console.log('\n[dry-run] Skipping API calls.');
    return;
  }

  console.log('\nFetching Management API token...');
  const token = await getMgmtToken();

  // NOTE: A page template is no longer created here. Auth0 stores and renders
  // prompt partials independently of a custom page template, and setting a
  // minimal template breaks the tenant's default branding (background image,
  // widget position). Leave the tenant on Auth0's default template.

  const url = `${apiBase}/prompts/signup-id/partials`;
  console.log(`\nPUT ${url}`);

  const resp = await axios.put(url, partialBody, {
    headers: {
      Authorization: `Bearer ${token}`,
      'content-type': 'application/json',
    },
    validateStatus: () => true,
  });

  if (resp.status >= 200 && resp.status < 300) {
    console.log(`\n✓ Signup prompt partial configured (HTTP ${resp.status})`);
  } else {
    console.error(`\n✗ Failed (HTTP ${resp.status}):`);
    console.error(JSON.stringify(resp.data, null, 2));
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
