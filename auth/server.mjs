import { createHmac } from 'node:crypto';
import { createServer } from 'node:http';
import { readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { Provider, errors } from 'oidc-provider';
import { eventContexts } from './events-context.mjs';
import { openStore } from './store.mjs';
import { CHATGPT_CLIENT, CHATGPT_REDIRECT, CHATGPT_STATIC_CLIENT } from './chatgpt.mjs';
import { appPaths, loadApps, validateApps } from '../lib/apps.mjs';
import { publicOrigin } from '../lib/origin.mjs';
import { join } from 'node:path';

const escapeHtml = (text) => text.replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);

function json(res, status, value) {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify(value));
}

async function form(req) {
  if (req.headers['content-type'] !== 'application/x-www-form-urlencoded') throw new errors.InvalidRequest();
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (Buffer.byteLength(body) > 4096) throw new errors.InvalidRequest();
  }
  return new URLSearchParams(body);
}

function createAppAuth({ app, origin, secrets, database, clients = [] }) {
  const prefix = app.oauth.path;
  const scope = app.resource.scope;
  const { metadata: metadataPath, issuerMetadata: issuerMetadataPath, verify: verifyPath, eventsAuthorize: eventsAuthorizePath } = appPaths(app);
  const url = new URL(origin);
  if (!secrets.accountId || !secrets.cookieKeys?.length || secrets.cookieKeys.some((key) => typeof key !== 'string' || key.length < 32)
      || !secrets.jwks?.keys?.length) throw new Error('OAuth signing keys, cookie keys, and operator identity are required');
  const issuer = `${origin}${prefix}`;
  const resource = `${origin}${app.resource.path}`;
  const store = openStore(database);
  const contexts = eventContexts(secrets.cookieKeys, issuer);
  // Keep ChatGPT as a static provider client instead of rebuilding it from its
  // CIMD document for every token request. oidc-provider otherwise creates a
  // fresh Client/KeyStore on each CIMD lookup, which forces a remote JWKS fetch
  // on every silent refresh. A transient fetch failure then becomes
  // invalid_client and ChatGPT treats the connection as expired.
  const configuredClients = clients.some((client) => client.client_id === CHATGPT_CLIENT)
    ? clients : [...clients, CHATGPT_STATIC_CLIENT];
  const provider = new Provider(issuer, {
    adapter: store.Adapter,
    clients: configuredClients,
    jwks: secrets.jwks,
    cookies: { names: app.oauth.cookies, keys: secrets.cookieKeys, long: { secure: true, sameSite: 'lax' }, short: { secure: true, sameSite: 'lax' } },
    claims: { openid: ['sub'] },
    scopes: ['openid', 'offline_access'],
    responseTypes: ['code'],
    clientAuthMethods: [...new Set(['private_key_jwt', ...configuredClients.map((c) => c.token_endpoint_auth_method)])],
    pkce: { required: () => true },
    issueRefreshToken: (_ctx, client, source) => client.grantTypeAllowed('refresh_token')
      && (client.clientId === CHATGPT_CLIENT || source.scopes.has('offline_access')),
    expiresWithSession: (_ctx, source) => source.clientId !== CHATGPT_CLIENT
      && !source.scopes.has('offline_access'),
    features: {
      devInteractions: { enabled: false },
      userinfo: { enabled: false },
      rpInitiatedLogout: { enabled: false },
      revocation: { enabled: true, allowedPolicy: (_ctx, client, token) => token.clientId === client.clientId },
      clientIdMetadataDocument: {
        enabled: true,
        ack: 'draft-02',
        allowFetch: (_ctx, clientId) => clientId === CHATGPT_CLIENT,
        allowClient: (_ctx, client) => client.clientId === CHATGPT_CLIENT
          && client.redirectUris.length === 1 && client.redirectUris[0] === CHATGPT_REDIRECT
          && client.clientAuthMethod === 'private_key_jwt',
      },
      resourceIndicators: {
        enabled: true,
        getResourceServerInfo(_ctx, indicator) {
          if (indicator !== resource) throw new errors.InvalidTarget();
          return { scope, audience: resource, accessTokenTTL: 600, accessTokenFormat: 'opaque' };
        },
      },
    },
    interactions: { url: (_ctx, interaction) => `${prefix}/interaction/${interaction.uid}` },
    findAccount: (_ctx, id) => id === secrets.accountId
      ? { accountId: id, claims: async () => ({ sub: id }) } : undefined,
    ttl: {
      AccessToken: 600,
      IdToken: 600,
      AuthorizationCode: 60,
      Interaction: 300,
      Session: 86400,
      Grant: 2592000,
      RefreshToken: 2592000,
    },
    // ChatGPT may refresh concurrently while tools are active. One-time refresh
    // rotation turns a benign duplicate refresh into whole-grant revocation in
    // oidc-provider. Keep rotation for other clients, but use the client-bound
    // persistent credential for the trusted ChatGPT CIMD client.
    // Explicit disconnect must invalidate the grant, not merely its tokens.
    revokeGrantPolicy: () => true,
    rotateRefreshToken: (ctx) => ctx.oidc.client.clientId !== CHATGPT_CLIENT,
    renderError(ctx) { ctx.type = 'text'; ctx.body = 'Authorization failed. Restart linking from ChatGPT.'; },
  });
  provider.proxy = true;
  // Log only sanitized OAuth failure classification. Never log request
  // parameters, assertions, authorization codes, or token values.
  provider.on('grant.error', (ctx, error) => {
    const suppliedType = ctx?.oidc?.params?.grant_type;
    const grantType = ['authorization_code', 'refresh_token'].includes(suppliedType) ? suppliedType : 'unknown';
    const classification = /^[a-z_]+$/.test(error?.error ?? '') ? error.error : 'unknown';
    console.error(`OAuth grant rejection app=${app.id} grant_type=${grantType} error=${classification}`);
  });
  provider.on('server_error', () => console.error('OAuth provider server_error'));
  const callback = provider.callback();
  const csrf = (uid) => createHmac('sha256', secrets.cookieKeys[0]).update(uid).digest('hex');
  const challenge = `Bearer resource_metadata="${origin}${metadataPath}", scope="${scope}"`;

  async function interaction(req, res, path) {
    if (req.headers['x-host-ingress-operator'] !== 'authenticated') return json(res, 401, { error: 'operator_login_required' });
    const details = await provider.interactionDetails(req, res);
    if (path !== `${prefix}/interaction/${details.uid}`) return json(res, 400, { error: 'invalid_interaction' });
    if (!['login', 'consent'].includes(details.prompt.name)) return json(res, 400, { error: 'unsupported_interaction' });
    if (req.method === 'GET') {
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store',
        'content-security-policy': "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        'referrer-policy': 'same-origin', 'x-content-type-options': 'nosniff',
      });
      return res.end(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Authorize ${escapeHtml(app.title)}</title>
        <h1>Authorize ChatGPT</h1><p>${escapeHtml(app.description)}</p>
        <p>This authorization remains active until you revoke it. Only approve a connection you started in ChatGPT.</p>
        <form method="post"><input type="hidden" name="csrf" value="${csrf(details.uid)}">
        <button name="decision" value="allow">Allow access</button> <button name="decision" value="deny">Deny</button></form></html>`);
    }
    if (req.method !== 'POST') return json(res, 405, { error: 'method_not_allowed' });
    const body = await form(req);
    if (req.headers.origin !== origin || body.getAll('csrf').length !== 1 || body.get('csrf') !== csrf(details.uid)) {
      return json(res, 403, { error: 'invalid_csrf' });
    }
    if (body.get('decision') !== 'allow') {
      return provider.interactionFinished(req, res, { error: 'access_denied', error_description: 'Operator denied access' }, { mergeWithLastSubmission: false });
    }
    const grant = details.grantId ? await provider.Grant.find(details.grantId)
      : new provider.Grant({ accountId: secrets.accountId, clientId: details.params.client_id });
    if (!grant || grant.accountId !== secrets.accountId || grant.clientId !== details.params.client_id) throw new errors.InvalidGrant();
    const scopes = new Set(String(details.params.scope).split(' '));
    grant.addOIDCScope(['openid', 'offline_access'].filter((scope) => scopes.has(scope)).join(' '));
    if (details.params.resource !== resource || !scopes.has(scope)) throw new errors.InvalidTarget();
    grant.addResourceScope(resource, scope);
    await provider.interactionFinished(req, res, {
      login: { accountId: secrets.accountId, amr: ['pwd'], remember: false },
      consent: { grantId: await grant.save() },
    }, { mergeWithLastSubmission: false });
  }

  const handle = async (req, res) => {
    let path = '';
    try {
      // Discovery and callbacks use the configured issuer, never caller-supplied host headers.
      req.headers['x-forwarded-host'] = url.host;
      req.headers['x-forwarded-proto'] = 'https';
      req.baseUrl = prefix;
      path = new URL(req.url, origin).pathname;
      if (path === metadataPath && req.method === 'GET') {
        return json(res, 200, { resource, resource_name: app.title, authorization_servers: [issuer], scopes_supported: [scope], bearer_methods_supported: ['header'] });
      }
      if (path === verifyPath && req.method === 'GET') {
        const bearer = /^Bearer ([A-Za-z0-9_-]{20,512})$/i.exec(req.headers.authorization ?? '');
        const token = bearer && await provider.AccessToken.find(bearer[1]);
        const grant = token && await provider.Grant.find(token.grantId);
        if (token && token.aud === resource && token.accountId === secrets.accountId
            && token.scopes.has(scope) && token.exp > Math.floor(Date.now() / 1000)
            && grant && grant.accountId === token.accountId && grant.clientId === token.clientId
            && grant.getResourceScope(resource).split(' ').includes(scope)) {
          const authorization = { principal: token.accountId, clientId: token.clientId,
            grantId: token.grantId, resource, scope };
          res.writeHead(204, { 'cache-control': 'no-store',
            'x-host-ingress-client-id': token.clientId,
            'x-host-ingress-auth-context': contexts.seal({ kind: 'request', ...authorization,
              iat: Math.floor(Date.now() / 1000), exp: Math.min(token.exp, Math.floor(Date.now() / 1000) + 30) }) });
          return res.end();
        }
        res.setHeader('www-authenticate', `${challenge}${bearer ? ', error="invalid_token"' : ''}`);
        return json(res, 401, { error: 'authentication_required' });
      }
      if (path === eventsAuthorizePath) {
        if (req.method !== 'POST') return json(res, 405, { error: 'method_not_allowed' });
        if (req.headers['content-type'] !== 'application/json') return json(res, 400, { error: 'invalid_request' });
        let bytes = '';
        for await (const chunk of req) {
          bytes += chunk;
          if (Buffer.byteLength(bytes) > 8192) return json(res, 413, { error: 'invalid_request' });
        }
        let input;
        try { input = JSON.parse(bytes); } catch { return json(res, 400, { error: 'invalid_request' }); }
        const requestCheck = typeof input?.requestContext === 'string' && Object.keys(input).length === 1;
        const grantCheck = input?.authorization && Object.keys(input).length === 1;
        const supplied = grantCheck && input.authorization;
        const context = contexts.open(requestCheck ? input.requestContext : supplied?.grantContext);
        const now = Math.floor(Date.now() / 1000);
        const fields = ['principal', 'clientId', 'grantId', 'resource', 'scope'];
        const validContext = context && fields.every((key) => typeof context[key] === 'string' && context[key].length > 0)
          && context.principal === secrets.accountId && context.resource === resource && context.scope === scope
          && (requestCheck ? context.kind === 'request' && context.iat <= now && context.exp > now
            && context.exp <= context.iat + 30 : grantCheck && context.kind === 'grant'
            && fields.every((key) => supplied[key] === context[key]));
        const grant = validContext && await provider.Grant.find(context.grantId);
        if (!grant || grant.accountId !== context.principal || grant.clientId !== context.clientId
            || !grant.getResourceScope(resource).split(' ').includes(scope)) {
          return json(res, 403, { allowed: false });
        }
        const authorization = Object.fromEntries(fields.map((key) => [key, context[key]]));
        return json(res, 200, { allowed: true, authorization: { ...authorization,
          grantContext: requestCheck ? contexts.seal({ kind: 'grant', ...authorization }) : supplied.grantContext } });
      }
      if (path.startsWith(`${prefix}/interaction/`)) return await interaction(req, res, path);
      if (path === issuerMetadataPath && req.method === 'GET') {
        req.url = '/.well-known/openid-configuration';
      } else if (path.startsWith(`${prefix}/`)) {
        req.url = req.url.slice(prefix.length);
      } else {
        return json(res, 404, { error: 'not_found' });
      }
      return callback(req, res);
    } catch (error) {
      if (!res.headersSent) {
        if (path.startsWith(`${prefix}/interaction/`)) {
          res.writeHead(error instanceof errors.OIDCProviderError ? 400 : 500, {
            'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store',
            'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
            'referrer-policy': 'same-origin', 'x-content-type-options': 'nosniff',
          });
          return res.end(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Link already used</title>
        <h1>Link already used or expired</h1><p>This approval link has already been used or expired. Return to ChatGPT and restart linking, then approve once.</p></html>`);
        }
        json(res, error instanceof errors.OIDCProviderError ? 400 : 500, { error: 'authorization_failed' });
      } else res.end();
      if (!(error instanceof errors.OIDCProviderError)) console.error('OAuth request failed');
    }
  };
  return { handle, provider, close: store.close };
}

// Each issuer has its own provider and database; no token/grant/cache can cross apps.
export function createAuth({ origin, secrets, apps }) {
  origin = publicOrigin({ PUBLIC_ORIGIN: origin });
  validateApps(apps.map(({ app }) => app));
  if (new Set(apps.map(({ database }) => database)).size !== apps.length) throw new Error('OAuth databases must be separate');
  const handlers = [];
  try {
    for (const configuration of apps) handlers.push({ app: configuration.app,
      ...createAppAuth({ origin, secrets, ...configuration }) });
  } catch (error) {
    handlers.forEach((handler) => handler.close());
    throw error;
  }
  const server = createServer((req, res) => {
    let path;
    try { path = new URL(req.url, origin).pathname; }
    catch { return json(res, 400, { error: 'invalid_request' }); }
    if (path === '/healthz' && req.method === 'GET') return json(res, 200, { ready: true });
    for (const handler of handlers) {
      const paths = appPaths(handler.app);
      if ([paths.verify, paths.eventsAuthorize].includes(path)
          || new RegExp(paths.oauthPattern).test(path) || new RegExp(paths.consentPattern).test(path)) return handler.handle(req, res);
    }
    return json(res, 404, { error: 'not_found' });
  });
  server.on('close', () => handlers.forEach((handler) => handler.close()));
  return { server, providers: new Map(handlers.map(({ app, provider }) => [app.id, provider])) };
}

if (import.meta.main) {
  process.umask(0o077);
  const secretPath = `${homedir()}/.config/host-ingress/oauth-secrets.json`;
  if ((statSync(secretPath).mode & 0o077) !== 0) throw new Error('OAuth secrets must have mode 0600');
  const secrets = JSON.parse(readFileSync(secretPath, 'utf8'));
  const apps = loadApps().map((app) => ({ app, database: join(homedir(), '.local/state/host-ingress', app.oauth.database) }));
  const { server } = createAuth({ origin: publicOrigin(), secrets, apps });
  server.listen(9001, '127.0.0.1', () => console.log('Host OAuth ready on loopback:9001'));
  process.on('SIGTERM', () => server.close());
}
