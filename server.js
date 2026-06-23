'use strict';

require('dotenv').config();

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const passport = require('passport');
const { Strategy: SamlStrategy } = require('@node-saml/passport-saml');
const { XMLParser } = require('fast-xml-parser');
const axios = require('axios');

const PORT = parseInt(process.env.PORT, 10) || 8080;
const SP_BASE_URL = process.env.SP_BASE_URL;
const SP_ENTITY_ID = process.env.SP_ENTITY_ID;
const CALLBACK_URL = `${SP_BASE_URL}/saml/callback`;

function loadIdpFromMetadata(metadataPath) {
  const xml = fs.readFileSync(metadataPath, 'utf8');
  const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_' });
  const doc = parser.parse(xml);
  const ed = doc.EntityDescriptor;
  const idpDescriptor = ed.IDPSSODescriptor;

  const sso = Array.isArray(idpDescriptor.SingleSignOnService)
    ? idpDescriptor.SingleSignOnService
    : [idpDescriptor.SingleSignOnService];
  const slo = Array.isArray(idpDescriptor.SingleLogoutService)
    ? idpDescriptor.SingleLogoutService
    : [idpDescriptor.SingleLogoutService];

  const findByBinding = (list, binding) =>
    list.find((s) => s['@_Binding'] === binding) || list[0];

  const ssoRedirect = findByBinding(sso, 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');
  const sloRedirect = findByBinding(slo, 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');

  const entryPoint = ssoRedirect['@_Location'];
  const entryPointUrl = new URL(entryPoint);
  const tenantBaseUrl = `${entryPointUrl.protocol}//${entryPointUrl.hostname}`;
  const samlClientIdMatch = entryPointUrl.pathname.match(/^\/samlp\/([^\/]+)/);
  const samlClientId = samlClientIdMatch ? samlClientIdMatch[1] : null;

  return {
    issuer: ed['@_entityID'],
    entryPoint,
    samlSloUrl: sloRedirect['@_Location'],
    tenantBaseUrl,
    samlClientId,
  };
}

const idp = loadIdpFromMetadata(path.resolve(process.env.IDP_METADATA_PATH));
const idpCert = fs.readFileSync(path.resolve(process.env.IDP_CERT_PATH), 'utf8');

const samlConfig = {
  entryPoint: idp.entryPoint,
  issuer: SP_ENTITY_ID,
  callbackUrl: CALLBACK_URL,
  idpCert,
  identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  wantAssertionsSigned: true,
  wantAuthnResponseSigned: false,
  signatureAlgorithm: 'sha256',
  digestAlgorithm: 'sha256',
};

const samlStrategy = new SamlStrategy(samlConfig, verifyProfile, verifyProfile);

function verifyProfile(profile, done) {
  done(null, profile);
}

passport.use('saml', samlStrategy);
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

const app = express();

app.set('trust proxy', true);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

function buildSessionStore() {
  const kind = (process.env.SESSION_STORE || 'memory').toLowerCase();
  if (kind === 'dynamodb') {
    const DynamoDBStore = require('connect-dynamodb')(session);
    return new DynamoDBStore({
      table: process.env.SESSION_DDB_TABLE || 'b2b-saml-sp-sessions',
      AWSRegion: process.env.AWS_REGION || 'us-east-1',
    });
  }
  return undefined;
}

const isProd = (process.env.NODE_ENV === 'production') || /^https:/.test(SP_BASE_URL || '');
app.use(
  session({
    name: 'sp.sid',
    secret: process.env.SESSION_SECRET || 'dev-secret',
    resave: false,
    saveUninitialized: false,
    store: buildSessionStore(),
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: isProd,
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());

function requireAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  return res.redirect('/');
}

async function callTokenExchange({ subjectToken, audience, scope }) {
  const params = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    client_id: process.env.TOKEN_EXCHANGE_CLIENT_ID,
    client_secret: process.env.TOKEN_EXCHANGE_CLIENT_SECRET,
    subject_token: subjectToken,
    subject_token_type: process.env.TOKEN_EXCHANGE_SUBJECT_TOKEN_TYPE,
    audience,
  });
  if (scope) params.append('scope', scope);

  const response = await axios.post(
    process.env.TOKEN_EXCHANGE_URL,
    params.toString(),
    {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      validateStatus: () => true,
    }
  );

  return { status: response.status, data: response.data };
}

let mgmtTokenCache = { token: null, expiresAt: 0, inflight: null };

async function getProfileMgmtToken() {
  if (mgmtTokenCache.token && Date.now() < mgmtTokenCache.expiresAt - 60000) {
    return mgmtTokenCache.token;
  }
  if (mgmtTokenCache.inflight) return mgmtTokenCache.inflight;
  mgmtTokenCache.inflight = (async () => {
    const params = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: process.env.PROFILE_MGMT_CLIENT_ID,
      client_secret: process.env.PROFILE_MGMT_CLIENT_SECRET,
      audience: process.env.PROFILE_MGMT_AUDIENCE,
    });
    const response = await axios.post(
      process.env.PROFILE_MGMT_TOKEN_URL,
      params.toString(),
      {
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        validateStatus: () => true,
      }
    );
    if (response.status < 200 || response.status >= 300 || !response.data.access_token) {
      const err = new Error(`profile-mgmt token request failed (HTTP ${response.status})`);
      err.status = response.status;
      err.body = response.data;
      throw err;
    }
    mgmtTokenCache = {
      token: response.data.access_token,
      expiresAt: Date.now() + (response.data.expires_in || 0) * 1000,
      inflight: null,
    };
    return mgmtTokenCache.token;
  })().catch((err) => {
    mgmtTokenCache.inflight = null;
    throw err;
  });
  return mgmtTokenCache.inflight;
}

app.get('/', (req, res) => {
  if (req.isAuthenticated && req.isAuthenticated()) return res.redirect('/home');
  res.render('login', { spEntityId: SP_ENTITY_ID, callbackUrl: CALLBACK_URL });
});

app.get(
  '/login',
  (req, res, next) => passport.authenticate('saml', { failureRedirect: '/error' })(req, res, next)
);

app.get('/register', (req, res) => {
  if (req.isAuthenticated && req.isAuthenticated()) return res.redirect('/home');

  const verifier  = base64url(crypto.randomBytes(32));
  const challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
  const state     = base64url(crypto.randomBytes(16));

  req.session.oidcContext = { verifier, state, returnTo: '/home' };

  const url = new URL(`${process.env.OIDC_TENANT_BASE_URL || idp.tenantBaseUrl}/authorize`);
  url.searchParams.set('client_id',              process.env.OIDC_CLIENT_ID);
  url.searchParams.set('response_type',          'code');
  url.searchParams.set('redirect_uri',           oidcRedirectUri());
  url.searchParams.set('scope',                  'openid profile email');
  url.searchParams.set('state',                  state);
  url.searchParams.set('code_challenge',         challenge);
  url.searchParams.set('code_challenge_method',  'S256');
  url.searchParams.set('screen_hint',            'signup');
  res.redirect(url.toString());
});

async function exchangeApiTokenForSession(req) {
  const { status, data } = await callTokenExchange({
    subjectToken: req.user.nameID,
    audience: process.env.TOKEN_EXCHANGE_AUDIENCE,
  });
  if (status >= 200 && status < 300 && data.access_token) {
    req.session.accessToken = data.access_token;
    req.session.tokenResponse = data;
    req.session.tokenError = null;
  } else {
    req.session.accessToken = null;
    req.session.tokenResponse = null;
    req.session.tokenError = { status, body: data };
  }
}

app.post(
  '/saml/callback',
  passport.authenticate('saml', { failureRedirect: '/error', failureFlash: false }),
  async (req, res, next) => {
    try {
      const subjectToken = req.user && req.user.nameID;
      if (!subjectToken) {
        return res.render('error', {
          title: 'Missing NameID',
          message: 'SAML assertion did not contain a NameID, cannot perform token exchange.',
          detail: JSON.stringify(req.user, null, 2),
        });
      }
      await exchangeApiTokenForSession(req);
      res.redirect('/home');
    } catch (err) {
      next(err);
    }
  }
);

function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeJwtPayload(token) {
  const parts = token.split('.');
  if (parts.length < 2) return {};
  const padded = parts[1] + '==='.slice((parts[1].length + 3) % 4);
  const b64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  return JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
}

function oidcRedirectUri() {
  return process.env.OIDC_REDIRECT_URI || `${SP_BASE_URL}/oidc/callback`;
}

const SESSION_TRANSFER_COOKIE = 'session_transfer_token';

function renderDebugEcho(req, res, opts) {
  const title = (opts && opts.title) || '/context/echo';
  const note = (opts && opts.note) || '';

  const rawCookieHeader = req.headers.cookie || '';
  const cookies = req.cookies || {};
  const stt = cookies[SESSION_TRANSFER_COOKIE];
  const sttPresent = typeof stt === 'string' && stt.length > 0;
  const sttIsJwt = sttPresent && stt.split('.').length === 3;
  let sttPayloadPreview = null;
  if (sttIsJwt) {
    try {
      const claims = decodeJwtPayload(stt);
      sttPayloadPreview = {
        iss: claims.iss,
        aud: claims.aud,
        sub: claims.sub,
        target_client: claims.target_client,
        exp: claims.exp,
        iat: claims.iat,
      };
    } catch (e) {
      sttPayloadPreview = { decode_error: e.message };
    }
  }

  const safe = (s) => String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  const sttBlock = !sttPresent
    ? '<p class="bad">✗ <code>session_transfer_token</code> cookie NOT present on this request.</p>'
    : `<p class="ok">✓ <code>session_transfer_token</code> cookie present (length ${stt.length}).</p>
       <p>Looks like a JWT? <strong>${sttIsJwt ? 'YES' : 'NO — opaque token, will fail on /authorize'}</strong></p>
       ${sttIsJwt ? `<pre>${safe(JSON.stringify(sttPayloadPreview, null, 2))}</pre>` : ''}`;

  res.type('text/html').send(`<!doctype html>
<html><head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${safe(title)}</title>
<style>
  body { font: 14px -apple-system, Helvetica, sans-serif; padding: 1rem; line-height: 1.45; color: #1f2937; }
  h1 { font-size: 1.1rem; margin: 0 0 1rem; }
  h2 { font-size: 0.95rem; color: #374151; margin: 1.2rem 0 0.4rem; text-transform: uppercase; letter-spacing: 0.05em; }
  pre { background: #f1f5f9; padding: 0.6rem; border-radius: 6px; word-break: break-all; white-space: pre-wrap; font-size: 12px; }
  code { background: rgba(15,23,42,.06); padding: 0 0.3em; border-radius: 3px; }
  .ok { color: #047857; font-weight: 600; }
  .bad { color: #b91c1c; font-weight: 600; }
  .note { background: #fef3c7; border: 1px solid #fde68a; padding: 0.6rem 0.8rem; border-radius: 6px; color: #78350f; }
</style>
</head><body>
<h1>${safe(title)}</h1>
${note ? `<p class="note">${safe(note)}</p>` : ''}
${sttBlock}
<h2>Raw <code>Cookie:</code> request header</h2>
<pre>${safe(rawCookieHeader || '(empty)')}</pre>
<h2>Parsed cookies</h2>
<pre>${safe(JSON.stringify(cookies, null, 2))}</pre>
<h2>Selected request headers</h2>
<pre>${safe(JSON.stringify({
  host: req.headers.host,
  'user-agent': req.headers['user-agent'],
  'x-forwarded-for': req.headers['x-forwarded-for'],
  'x-forwarded-proto': req.headers['x-forwarded-proto'],
  'x-forwarded-host': req.headers['x-forwarded-host'],
  'cloudfront-viewer-tls': req.headers['cloudfront-viewer-tls'],
  referer: req.headers.referer,
  origin: req.headers.origin,
  accept: req.headers.accept,
  'accept-language': req.headers['accept-language'],
}, null, 2))}</pre>
<h2>Connection</h2>
<pre>${safe(JSON.stringify({
  method: req.method,
  protocol: req.protocol,
  ip: req.ip,
  ips: req.ips,
  hostname: req.hostname,
  path: req.path,
  query: req.query,
}, null, 2))}</pre>
<p style="color:#6b7280; font-size: 12px;">Debug page is gated by <code>DEBUG_ECHO=1</code>.</p>
</body></html>`);
}

app.get('/context/echo', (req, res) => {
  if (process.env.DEBUG_ECHO !== '1') {
    return res.status(404).type('text/plain').send('Not found');
  }
  renderDebugEcho(req, res);
});

app.get('/context/set', (req, res) => {
  const sessionToken =
    (typeof req.query.session_token === 'string' && req.query.session_token) ||
    (req.cookies && req.cookies[SESSION_TRANSFER_COOKIE]) ||
    null;

  // When DEBUG_ECHO=1, force-render the debug page (?debug=1) OR fall through
  // to it if no token is present, so the mobile WKWebView gets useful diagnostic
  // info on the same URL it already loads.
  const debugOn = process.env.DEBUG_ECHO === '1';
  const forceDebug = debugOn && req.query.debug === '1';
  if (forceDebug || (!sessionToken && debugOn)) {
    return renderDebugEcho(req, res, {
      title: '/context/set — debug',
      note: sessionToken
        ? 'session_transfer_token was present, but ?debug=1 forced this page to render instead of redirecting to /authorize.'
        : 'No session_transfer_token found in either the cookie or the ?session_token query. The request details below should help you figure out why.',
    });
  }

  if (!sessionToken) {
    return res.status(400).render('error', {
      title: 'Missing session_token',
      message: `/context/set needs the session_transfer_token, either in the '?session_token=<jwt>' query parameter or in the '${SESSION_TRANSFER_COOKIE}' cookie.`,
      detail: 'The mobile app obtains a session_transfer_token from Auth0 ' +
              '(/oauth/token with audience=urn:<tenant>:session_transfer) and either ' +
              'sets it as a host-only cookie on this domain before loading the URL, ' +
              'or includes it as ?session_token=<jwt>.',
    });
  }

  const verifier = base64url(crypto.randomBytes(32));
  const challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
  const state = base64url(crypto.randomBytes(16));
  req.session.oidcContext = {
    verifier,
    state,
    returnTo: typeof req.query.returnTo === 'string' ? req.query.returnTo : '/home',
  };

  if (req.cookies && req.cookies[SESSION_TRANSFER_COOKIE]) {
    res.clearCookie(SESSION_TRANSFER_COOKIE, { path: '/', secure: isProd, sameSite: 'lax' });
  }

  const url = new URL(`${process.env.OIDC_TENANT_BASE_URL || idp.tenantBaseUrl}/authorize`);
  url.searchParams.set('client_id', process.env.OIDC_CLIENT_ID);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('redirect_uri', oidcRedirectUri());
  url.searchParams.set('scope', 'openid profile email');
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('session_token', sessionToken);
  res.redirect(url.toString());
});

app.get('/oidc/callback', async (req, res, next) => {
  try {
    const { code, state, error, error_description } = req.query;
    const stored = req.session.oidcContext;
    delete req.session.oidcContext;

    if (error) {
      return res.status(401).render('error', {
        title: `OIDC error: ${error}`,
        message: error_description || 'Auth0 returned an error during the native-to-web bridge.',
        detail: null,
      });
    }
    if (!stored || !state || stored.state !== state) {
      return res.status(400).render('error', {
        title: 'OIDC state mismatch',
        message: 'OIDC callback state did not match the request that started the flow.',
        detail: null,
      });
    }
    if (!code) {
      return res.status(400).render('error', {
        title: 'OIDC callback missing code',
        message: 'No authorization code returned from Auth0.',
        detail: null,
      });
    }

    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: process.env.OIDC_CLIENT_ID,
      client_secret: process.env.OIDC_CLIENT_SECRET,
      code,
      redirect_uri: oidcRedirectUri(),
      code_verifier: stored.verifier,
    });
    const tokenResp = await axios.post(
      `${process.env.OIDC_TENANT_BASE_URL || idp.tenantBaseUrl}/oauth/token`,
      params.toString(),
      { headers: { 'content-type': 'application/x-www-form-urlencoded' }, validateStatus: () => true }
    );
    if (tokenResp.status < 200 || tokenResp.status >= 300 || !tokenResp.data.id_token) {
      return res.status(502).render('error', {
        title: `Token exchange failed (HTTP ${tokenResp.status})`,
        message: 'Failed to exchange authorization code for tokens.',
        detail: typeof tokenResp.data === 'string'
          ? tokenResp.data
          : JSON.stringify(tokenResp.data, null, 2),
      });
    }
    const claims = decodeJwtPayload(tokenResp.data.id_token);
    const profile = {
      nameID: claims.sub,
      email: claims.email,
      name: claims.name,
      nameIDFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:opaque',
      _origin: 'oidc-context-set',
      _claims: claims,
    };

    req.login(profile, async (loginErr) => {
      if (loginErr) return next(loginErr);
      try {
        await exchangeApiTokenForSession(req);
      } catch (e) {
        req.session.tokenError = { status: 0, body: { message: e.message } };
      }
      res.redirect(stored.returnTo || '/home');
    });
  } catch (err) {
    next(err);
  }
});

const JWT_SKIP = new Set(['iss', 'aud', 'iat', 'exp', 'nbf', 'jti', 'sub', 'nonce', 'sid', 'at_hash', 'c_hash']);

function extractDigitalProfile(profile) {
  if (!profile || typeof profile !== 'object') return null;

  // Normalise a raw claim value into { profile: {...} } regardless of how
  // the Auth0 Action serialised it:
  //   - object already shaped { profile: {...} }  → returned as-is
  //   - flat object { job_title, phone, ... }     → wrapped as { profile: {...} }
  //   - JSON string of either of the above        → parsed then normalised
  function normalise(raw) {
    let val = raw;
    if (typeof val === 'string') {
      try { val = JSON.parse(val); } catch (e) { return null; }
    }
    if (!val || typeof val !== 'object' || Array.isArray(val)) return null;
    if (val.profile && typeof val.profile === 'object') return val;
    return { profile: val };
  }

  const candidates = [];

  if (profile.digital_profile != null) candidates.push(profile.digital_profile);

  if (profile._claims) {
    if (profile._claims.digital_profile != null) candidates.push(profile._claims.digital_profile);
    for (const key of Object.keys(profile._claims)) {
      if (key.endsWith('/digital_profile') || key.endsWith(':digital_profile')) {
        candidates.push(profile._claims[key]);
      }
    }
  }

  for (const key of Object.keys(profile)) {
    if (key.endsWith('/digital_profile') || key.endsWith(':digital_profile')) {
      candidates.push(profile[key]);
    }
  }

  for (const c of candidates) {
    const result = normalise(c);
    if (result) return result;
  }
  return null;
}

app.get('/home', requireAuth, (req, res) => {
  const notice = req.session.homeNotice || null;
  req.session.homeNotice = null;
  res.render('home', {
    profile: req.user,
    accessToken: req.session.accessToken || null,
    tokenResponse: req.session.tokenResponse || null,
    tokenError: req.session.tokenError || null,
    digitalProfile: extractDigitalProfile(req.user),
    jwtSkip: JWT_SKIP,
    notice,
  });
});

app.post('/home/digital-profile', requireAuth, async (req, res, next) => {
  try {
    let token;
    try {
      token = await getProfileMgmtToken();
    } catch (err) {
      req.session.homeNotice = { type: 'error', message: `Could not obtain management token: ${err.message}` };
      return res.redirect('/home#profile');
    }

    const sub = req.user.nameID;
    const name     = ((req.body.name      || '') + '').trim();
    const jobTitle = ((req.body.job_title || '') + '').trim();
    const phone    = ((req.body.phone     || '') + '').trim();

    // Fetch current user record so we can merge into user_metadata.profile
    // without wiping unknown fields that may already be there.
    const userResp = await axios.get(
      `${idp.tenantBaseUrl}/api/v2/users/${encodeURIComponent(sub)}`,
      { headers: { Authorization: `Bearer ${token}` }, validateStatus: () => true }
    );
    const currentMeta    = (userResp.data && userResp.data.user_metadata) || {};
    const currentProfile = (currentMeta.profile && typeof currentMeta.profile === 'object')
      ? currentMeta.profile : {};
    const mergedProfile  = Object.assign({}, currentProfile, { job_title: jobTitle, phone });

    const patch = { user_metadata: Object.assign({}, currentMeta, { profile: mergedProfile }) };
    if (name) patch.name = name;

    const result = await axios.patch(
      `${idp.tenantBaseUrl}/api/v2/users/${encodeURIComponent(sub)}`,
      patch,
      {
        headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        validateStatus: () => true,
      }
    );

    if (result.status >= 400) {
      req.session.homeNotice = {
        type: 'error',
        message: `Update failed (HTTP ${result.status}): ${JSON.stringify(result.data)}`,
      };
    } else {
      if (name) req.user.name = name;
      req.session.homeNotice = { type: 'success', message: 'Profile saved.' };
    }
    req.session.save(() => res.redirect('/home#profile'));
  } catch (err) {
    next(err);
  }
});

const PROFILE_FIELDS = ['display_name', 'title', 'phone', 'department', 'bio'];

app.get('/profile', requireAuth, async (req, res, next) => {
  try {
    let token;
    try {
      token = await getProfileMgmtToken();
    } catch (err) {
      return res.render('profile', {
        profile: req.user,
        userData: null,
        userMetadata: {},
        tokenError: { status: err.status, body: err.body, message: err.message },
        notice: req.session.profileNotice || null,
      });
    }
    const sub = req.user.nameID;
    const userResp = await axios.get(
      `${idp.tenantBaseUrl}/api/v2/users/${encodeURIComponent(sub)}`,
      { headers: { Authorization: `Bearer ${token}` }, validateStatus: () => true }
    );
    const notice = req.session.profileNotice || null;
    req.session.profileNotice = null;
    if (userResp.status >= 400) {
      return res.render('profile', {
        profile: req.user,
        userData: null,
        userMetadata: {},
        tokenError: { status: userResp.status, body: userResp.data, message: 'Management API GET failed' },
        notice,
      });
    }
    res.render('profile', {
      profile: req.user,
      userData: userResp.data,
      userMetadata: userResp.data.user_metadata || {},
      tokenError: null,
      notice,
    });
  } catch (err) {
    next(err);
  }
});

app.post('/profile', requireAuth, async (req, res, next) => {
  try {
    const update = {};
    for (const f of PROFILE_FIELDS) {
      update[f] = ((req.body[f] || '') + '').trim();
    }
    let token;
    try {
      token = await getProfileMgmtToken();
    } catch (err) {
      req.session.profileNotice = {
        type: 'error',
        message: `Could not obtain a profile-management token (HTTP ${err.status}): ${JSON.stringify(err.body)}`,
      };
      return res.redirect('/profile');
    }
    const sub = req.user.nameID;
    const result = await axios.patch(
      `${idp.tenantBaseUrl}/api/v2/users/${encodeURIComponent(sub)}`,
      { user_metadata: update },
      {
        headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        validateStatus: () => true,
      }
    );
    if (result.status >= 400) {
      req.session.profileNotice = {
        type: 'error',
        message: `Update failed (HTTP ${result.status}): ${JSON.stringify(result.data)}`,
      };
    } else {
      req.session.profileNotice = { type: 'success', message: 'Profile saved.' };
    }
    res.redirect('/profile');
  } catch (err) {
    next(err);
  }
});

app.get('/saml/metadata', (req, res) => {
  const metadata = samlStrategy.generateServiceProviderMetadata(null, null);
  res.type('application/xml').send(metadata);
});

app.get('/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    req.session.destroy(() => {
      res.clearCookie('sp.sid');
      if (!idp.tenantBaseUrl || !idp.samlClientId) return res.redirect('/');
      const url = new URL(`${idp.tenantBaseUrl}/v2/logout`);
      url.searchParams.set('client_id', idp.samlClientId);
      url.searchParams.set('returnTo', `${SP_BASE_URL}/`);
      res.redirect(url.toString());
    });
  });
});

app.get('/error', (req, res) => {
  res.status(401).render('error', {
    title: 'Authentication failed',
    message: 'SAML authentication did not complete successfully.',
    detail: null,
  });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).render('error', {
    title: 'Server error',
    message: err.message || 'Unexpected error',
    detail: err.stack,
  });
});

module.exports = app;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`SAML SP demo listening on ${SP_BASE_URL}`);
    console.log(`  Entity ID:    ${SP_ENTITY_ID}`);
    console.log(`  Callback URL: ${CALLBACK_URL}`);
    console.log(`  IdP entryPoint: ${idp.entryPoint}`);
    console.log(`  SP metadata:    ${SP_BASE_URL}/saml/metadata`);
  });
}
