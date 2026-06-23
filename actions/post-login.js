/**
 * Auth0 Action — Post-Login trigger
 *
 * Deployment:
 *   Auth0 Dashboard → Actions → Library → Build Custom → "Login / Post Login"
 *   Save, Deploy, then add to the Login flow AFTER any action that sets digital_profile.
 *
 * What it does:
 *   Guarantees the `name` claim is always present in the ID token so the app
 *   shows a real name instead of a user_id on first login / progressive signup.
 *
 *   Priority order for the display name:
 *     1. user_metadata.profile.full_name  (set when user fills the profile form)
 *     2. user.name                        (set by the profile-update PATCH)
 *     3. given_name + family_name         (social / enterprise IdP)
 *     4. given_name alone
 *     5. nickname
 *
 *   Also propagates the name into SAML responses so the SAML-initiated flow
 *   picks it up from the assertion without needing extra attribute mapping.
 */

exports.onExecutePostLogin = async (event, api) => {
  const meta    = event.user.user_metadata || {};
  const profile = (meta.profile && typeof meta.profile === 'object') ? meta.profile : {};

  const displayName =
    profile.full_name ||
    event.user.name ||
    (event.user.given_name && event.user.family_name
      ? `${event.user.given_name} ${event.user.family_name}`
      : null) ||
    event.user.given_name ||
    event.user.nickname ||
    null;

  if (!displayName) return;

  // OIDC: override / set the `name` claim in the ID token
  api.idToken.setCustomClaim('name', displayName);

  // SAML: set the name attribute in the assertion (no-op for OIDC apps)
  if (api.samlResponse) {
    api.samlResponse.setAttribute('name', displayName);
  }
};
