# SAML SP Demo + Token Exchange

A small Node.js / Express app that:

1. Performs **SP-initiated SAML SSO** against an Auth0 tenant (`fiscal-psft.cic-demo-platform.auth0app.com`) configured as the IdP via the SAML2 Web App Add-on.
2. After login, calls Auth0's `/oauth/token` with the **`urn:ietf:params:oauth:grant-type:token-exchange`** grant, sending the SAML NameID as the `subject_token`.
3. Renders a home page with the user's profile and a **collapsible view of the returned access token**.

## Run

```bash
npm install
npm start
```

The app listens on `http://localhost:8080` by default.

- Landing page: <http://localhost:8080/>
- SP metadata XML: <http://localhost:8080/saml/metadata>

The IdP cert is read from `fiscal-psft.pem` and the IdP endpoints are read from `fiscal-psft_cic-demo-platform_auth0app_com-metadata.xml`. Token-exchange credentials and the API audience are in `.env` (gitignored — see `.env.example` for the template).

## SP values to put into the Auth0 SAML Add-on

In the Auth0 dashboard, open the application that has the SAML Add-on enabled, go to **Addons → SAML2 Web App**, and on the **Settings** tab paste:

**Application Callback URL** (top input):

```
http://localhost:8080/saml/callback
```

**Settings** (the JSON box):

```json
{
  "audience": "urn:fiscal-psft:saml-sp-demo",
  "recipient": "http://localhost:8080/saml/callback",
  "destination": "http://localhost:8080/saml/callback",
  "nameIdentifierFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  "signResponse": false
}
```

Save. The SP entity ID (`urn:fiscal-psft:saml-sp-demo`) and ACS URL match what the app sends in its AuthnRequest and what's published at `/saml/metadata`.

If you'd rather upload SP metadata directly, run the app and grab the XML from `http://localhost:8080/saml/metadata`.

## End-to-end test

1. Start the app: `npm start`
2. Open <http://localhost:8080/saml/metadata> — confirm SP metadata XML renders.
3. Apply the Auth0 SAML Add-on settings above and save.
4. Open <http://localhost:8080/> → click **Login with SSO**.
5. Authenticate at Auth0.
6. Land back on `/home` showing your NameID/email and a collapsible **Access Token** panel.
7. Expand the panel — confirm a JWT is shown. Decode at <https://jwt.io> and verify `aud` is `api://adp.com/services`.

If the token exchange fails (e.g. the Auth0 Action that handles `https://fiscal-psft.com/token-type/oag-session` is not yet configured), the home page will show the HTTP status and full error response body in place of the token, so you can correlate with Auth0 → Monitoring → Logs.

## Files

| Path | Purpose |
|---|---|
| `server.js` | Express app, passport-saml strategy, token-exchange call |
| `views/login.ejs` | Pre-login landing page |
| `views/home.ejs` | Post-login page with collapsible access token |
| `views/error.ejs` | Error page |
| `public/style.css` | Styling |
| `fiscal-psft_cic-demo-platform_auth0app_com-metadata.xml` | IdP metadata (entryPoint, SLO, NameID formats) |
| `fiscal-psft.pem` | IdP signing certificate (used to verify SAML assertions) |
| `.env` | Local secrets (gitignored) |
| `.env.example` | Template for `.env` |

## Notes

- Local-dev only: HTTP, no SP signing/encryption, in-memory session store.
- Port `6000` is blocked by browsers (X11 reserved). This app uses `8080`.
- The token-exchange grant relies on a custom token type (`https://fiscal-psft.com/token-type/oag-session`) that an Auth0 Action must accept and resolve.
