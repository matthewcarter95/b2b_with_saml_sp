/**
 * Auth0 Action — Pre-User Registration trigger
 *
 * Deployment:
 *   Auth0 Dashboard → Actions → Library → Build Custom → "Pre-User Registration"
 *   Paste this file, Save, Deploy, then add it to the Pre-User Registration flow.
 *
 * What it does:
 *   1. Reads the ulp-terms-of-service field submitted via the signup form partial.
 *   2. Blocks registration if the checkbox was not checked.
 *   3. Stamps tos_accepted_at in app_metadata with an ISO-8601 timestamp.
 */

exports.onExecutePreUserRegistration = async (event, api) => {
  const agreed =
    event.request.body && event.request.body['ulp-terms-of-service'];

  if (!agreed || String(agreed).toLowerCase() !== 'true') {
    api.access.deny(
      'tos_not_accepted',
      'You must accept the Terms of Service to create an account.'
    );
    return;
  }

  api.user.setAppMetadata('tos_accepted_at', new Date().toISOString());
};
