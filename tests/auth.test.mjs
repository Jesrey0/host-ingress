import { strict as assert } from 'node:assert';
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { test } from 'node:test';
import { createAuth as createService } from '../auth/server.mjs';
import { CHATGPT_CLIENT, CHATGPT_JWKS, CHATGPT_REDIRECT } from '../auth/chatgpt.mjs';
import { loadApp, loadApps, appPaths } from '../lib/apps.mjs';
const app = loadApp();
const SCOPE = app.resource.scope;
const METADATA_PATH = appPaths(app).metadata;
function createAuth({ origin, secrets, ...options }) {
  const auth = createService({ origin, secrets, apps: [{ app, ...options }] });
  return { server: auth.server, provider: auth.providers.get(app.id) };
}
import { eventContexts } from '../auth/events-context.mjs';

const origin = 'https://ingress.example';
const prefix = '/codex-connect/oauth';
const resource = `${origin}/codex-connect/mcp`;
const redirect = 'https://client.example/callback';
const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const secrets = {
  accountId: randomUUID(), cookieKeys: [randomBytes(32).toString('base64url')],
  jwks: { keys: [{ ...privateKey.export({ format: 'jwk' }), kid: 'test', use: 'sig', alg: 'RS256' }] },
};

async function fixture(t) {
  const prefix = app.oauth.path;
  const resource = `${origin}${app.resource.path}`;
  const SCOPE = app.resource.scope;
  const directory = mkdtempSync(`${tmpdir()}/host-oauth-test-`);
  const options = {
    app, origin, secrets, database: `${directory}/state.sqlite`,
    clients: [{ client_id: 'test-client', redirect_uris: [redirect], response_types: ['code'],
      grant_types: ['authorization_code', 'refresh_token'], token_endpoint_auth_method: 'none' },
      { client_id: 'test-signed', redirect_uris: [redirect], response_types: ['code'],
        grant_types: ['authorization_code', 'refresh_token'], token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'RS256', jwks: { keys: [{ ...createPublicKey(privateKey).export({ format: 'jwk' }), kid: 'test', alg: 'RS256' }] } },
      { client_id: CHATGPT_CLIENT, redirect_uris: [CHATGPT_REDIRECT], response_types: ['code'],
        grant_types: ['authorization_code', 'refresh_token'], token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'RS256', jwks: { keys: [{ ...createPublicKey(privateKey).export({ format: 'jwk' }), kid: 'test', alg: 'RS256' }] } }],
  };
  let auth;
  let base;
  const cookies = new Map();
  async function start() {
    auth = createAuth(options);
    await new Promise((resolve) => auth.server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${auth.server.address().port}`;
  }
  async function stop() {
    auth.server.closeAllConnections();
    await new Promise((resolve) => auth.server.close(resolve));
  }
  await start();
  t.after(async () => { await stop(); rmSync(directory, { recursive: true }); });
  async function request(path, { method = 'GET', headers = {}, body } = {}) {
    const response = await fetch(`${base}${path}`, { method, body, redirect: 'manual', headers: {
      host: 'ingress.example', 'x-forwarded-proto': 'https',
      cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join('; '), ...headers,
    } });
    for (const cookie of response.headers.getSetCookie()) {
      const [pair] = cookie.split(';');
      const split = pair.indexOf('=');
      cookies.set(pair.slice(0, split), pair.slice(split + 1));
    }
    return response;
  }
  function params({ clientId = 'test-client', redirectUri = redirect, includeOffline = true } = {}) {
    const verifier = randomBytes(32).toString('base64url');
    const query = new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, response_type: 'code',
      scope: `openid ${includeOffline ? 'offline_access ' : ''}${SCOPE}`, resource, prompt: 'consent', state: randomUUID(),
      code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' });
    return { verifier, query };
  }
  async function authorize(clientId = 'test-client', { includeOffline = true, redirectUri = redirect } = {}) {
    const { verifier, query } = params({ clientId, includeOffline, redirectUri });
    let response = await request(`${prefix}/auth?${query}`);
    assert.equal(response.status, 303);
    const location = new URL(response.headers.get('location'), origin);
    response = await request(location.pathname);
    assert.equal(response.status, 401, 'interaction must require authenticated gateway identity');
    response = await request(location.pathname, { headers: { 'x-host-ingress-operator': 'authenticated' } });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('referrer-policy'), 'same-origin',
      'consent form must retain its POST Origin without sending cross-origin referrers');
    const html = await response.text();
    const csrf = /name="csrf" value="([a-f0-9]+)"/.exec(html)[1];
    const body = new URLSearchParams({ csrf, decision: 'allow' }).toString();
    for (const requestOrigin of ['https://attacker.example', 'null', undefined]) {
      response = await request(location.pathname, { method: 'POST', body,
        headers: { 'x-host-ingress-operator': 'authenticated', 'content-type': 'application/x-www-form-urlencoded',
          ...(requestOrigin === undefined ? {} : { origin: requestOrigin }) } });
      assert.equal(response.status, 403, 'foreign, null, and missing Origin must fail closed');
    }
    for (const invalidBody of [
      new URLSearchParams({ decision: 'allow' }).toString(),
      new URLSearchParams({ csrf: 'invalid', decision: 'allow' }).toString(),
      `${body}&csrf=${csrf}`,
    ]) {
      response = await request(location.pathname, { method: 'POST', body: invalidBody,
        headers: { 'x-host-ingress-operator': 'authenticated', 'content-type': 'application/x-www-form-urlencoded', origin } });
      assert.equal(response.status, 403, 'missing, invalid, and duplicated CSRF tokens must fail closed');
    }
    response = await request(location.pathname, { method: 'POST', body,
      headers: { 'x-host-ingress-operator': 'authenticated', 'content-type': 'application/x-www-form-urlencoded', origin } });
    assert.equal(response.status, 303);
    const resume = new URL(response.headers.get('location'), origin);
    response = await request(resume.pathname + resume.search);
    assert.equal(response.status, 303);
    const callback = new URL(response.headers.get('location'));
    assert.equal(callback.origin + callback.pathname, redirectUri);
    assert.equal(callback.searchParams.get('iss'), `${origin}${prefix}`);
    assert.equal(callback.searchParams.get('state'), query.get('state'));
    assert.ok(callback.searchParams.has('code'), 'authorization must return a code');
    return { code: callback.searchParams.get('code'), verifier };
  }
  async function token(parameters) {
    return request(`${prefix}/token`, { method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: 'test-client', resource, ...parameters }).toString() });
  }
  function clientAssertion(clientId) {
    const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const time = Math.floor(Date.now() / 1000);
    const input = `${encode({ alg: 'RS256', kid: 'test' })}.${encode({ iss: clientId, sub: clientId,
      aud: `${origin}${prefix}`, iat: time, exp: time + 60, jti: randomUUID() })}`;
    return `${input}.${sign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url')}`;
  }
  async function grant() {
    const { code, verifier } = await authorize();
    const response = await token({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: redirect });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.ok(result.access_token && result.refresh_token);
    return result;
  }
  const verify = (value) => request(appPaths(app).verify, { headers: { authorization: `Bearer ${value}` } });
  return { request, params, authorize, token, grant, verify, clientAssertion, provider: () => auth.provider,
    restart: async () => { await stop(); await start(); } };
}

test('discovery advertises PKCE, issuer identification, ChatGPT CIMD, and exact protected resource', async (t) => {
  const f = await fixture(t);
  const protectedResource = await (await f.request(METADATA_PATH)).json();
  assert.equal(protectedResource.resource, resource);
  assert.equal(protectedResource.resource_name, app.title);
  assert.deepEqual(protectedResource.scopes_supported, [SCOPE]);
  assert.deepEqual(protectedResource.bearer_methods_supported, ['header']);
  assert.deepEqual(protectedResource.authorization_servers, [`${origin}${prefix}`]);
  for (const path of [`${prefix}/.well-known/openid-configuration`, '/.well-known/oauth-authorization-server/codex-connect/oauth']) {
    const metadata = await (await f.request(path)).json();
    assert.equal(metadata.issuer, `${origin}${prefix}`);
    assert.equal(metadata.authorization_endpoint, `${origin}${prefix}/auth`);
    assert.equal(metadata.token_endpoint, `${origin}${prefix}/token`);
    assert.equal(metadata.authorization_response_iss_parameter_supported, true);
    assert.equal(metadata.client_id_metadata_document_supported, true);
    assert.deepEqual(metadata.code_challenge_methods_supported, ['S256']);
    assert.ok(metadata.scopes_supported.includes('offline_access'));
    assert.equal(metadata.registration_endpoint, undefined);
  }
  for (const headers of [{}, { authorization: 'Basic invalid' }, { authorization: 'Bearer invalid' }, { 'x-host-ingress-operator': 'authenticated' }]) {
    const response = await f.request(appPaths(app).verify, { headers });
    assert.equal(response.status, 401);
    assert.ok(response.headers.get('www-authenticate').includes(METADATA_PATH));
  }
});

test('production ChatGPT client is static so its signing-key cache survives token requests', async (t) => {
  const directory = mkdtempSync(`${tmpdir()}/host-oauth-static-client-`);
  const auth = createService({ origin, secrets, apps: [{ app, database: `${directory}/state.sqlite` }] });
  t.after(() => { auth.server.close(); rmSync(directory, { recursive: true }); });
  const first = await auth.providers.get(app.id).Client.find(CHATGPT_CLIENT);
  const second = await auth.providers.get(app.id).Client.find(CHATGPT_CLIENT);
  assert.equal(first, second, 'ChatGPT client must be provider-static rather than recreated through CIMD');
  assert.equal(first.clientAuthMethod, 'private_key_jwt');
  assert.equal(first.jwksUri, CHATGPT_JWKS);
  assert.equal(first.redirectUris.length, 1);
  assert.equal(first.redirectUris[0], CHATGPT_REDIRECT);
  assert.equal(first.asymmetricKeyStore, second.asymmetricKeyStore,
    'private_key_jwt signing keys must share one cache across refreshes');
});

test('authorization-code + PKCE, opaque access checks, refresh rotation and persistence', async (t) => {
  const f = await fixture(t);
  const result = await f.grant();
  assert.equal((await f.verify(result.access_token)).status, 204);
  assert.equal((await f.verify(`${result.access_token}tampered`)).status, 401);
  await f.restart();
  assert.equal((await f.verify(result.access_token)).status, 204, 'tokens survive auth restart');
  const response = await f.token({ grant_type: 'refresh_token', refresh_token: result.refresh_token });
  assert.equal(response.status, 200);
  const refreshed = await response.json();
  assert.ok(refreshed.refresh_token !== result.refresh_token);
  assert.equal((await f.verify(refreshed.access_token)).status, 204);
  assert.equal((await f.token({ grant_type: 'refresh_token', refresh_token: result.refresh_token })).status, 400);
  assert.equal((await f.verify(refreshed.access_token)).status, 401, 'refresh reuse revokes grant');
});

test('ChatGPT gets persistent silent refresh without offline_access or rotation', async (t) => {
  const f = await fixture(t);
  const { code, verifier } = await f.authorize(CHATGPT_CLIENT, { includeOffline: false, redirectUri: CHATGPT_REDIRECT });
  const assertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
  const exchange = await f.token({ client_id: CHATGPT_CLIENT, grant_type: 'authorization_code', code,
    code_verifier: verifier, redirect_uri: CHATGPT_REDIRECT, client_assertion_type: assertionType,
    client_assertion: f.clientAssertion(CHATGPT_CLIENT) });
  assert.equal(exchange.status, 200);
  const initial = await exchange.json();
  assert.ok(initial.access_token && initial.refresh_token, 'ChatGPT must receive a refresh token without offline_access');
  const stored = await f.provider().RefreshToken.find(initial.refresh_token);
  assert.ok(stored);
  assert.equal(stored.exp, undefined, 'ChatGPT refresh authorization has no expiry in durable storage');
  const grant = await f.provider().Grant.find(stored.grantId);
  assert.equal(grant.exp, undefined, 'ChatGPT grant has no expiry in durable storage');
  assert.equal(stored.expiresWithSession, undefined, 'refresh authorization must not depend on the browser session');
  await f.restart();
  for (let attempt = 0; attempt < 2; attempt++) {
    const response = await f.token({ client_id: CHATGPT_CLIENT, grant_type: 'refresh_token', refresh_token: initial.refresh_token,
      client_assertion_type: assertionType, client_assertion: f.clientAssertion(CHATGPT_CLIENT) });
    assert.equal(response.status, 200, 'the same client-bound refresh token may be reused safely');
    const refreshed = await response.json();
    assert.equal((await f.verify(refreshed.access_token)).status, 204);
    assert.equal(refreshed.refresh_token, initial.refresh_token, 'non-rotating refresh must preserve the same credential');
  }
  assert.ok(await f.provider().RefreshToken.find(initial.refresh_token), 'refresh credential must remain valid after reuse');
  const revoked = await f.request(`${prefix}/token/revocation`, { method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: CHATGPT_CLIENT, token: initial.refresh_token,
      client_assertion_type: assertionType, client_assertion: f.clientAssertion(CHATGPT_CLIENT) }).toString() });
  assert.equal(revoked.status, 200);
  assert.equal((await f.verify(initial.access_token)).status, 401,
    'revoking the grant invalidates outstanding short-lived access tokens');
  assert.equal(await f.provider().RefreshToken.find(initial.refresh_token), undefined,
    'revoking a durable refresh credential removes its grant');
});

test('wrong verifier, code replay, foreign resources, missing PKCE, and untrusted clients fail closed', async (t) => {
  const f = await fixture(t);
  const { code, verifier } = await f.authorize();
  assert.equal((await f.token({ grant_type: 'authorization_code', code, code_verifier: 'x'.repeat(43), redirect_uri: redirect })).status, 400);
  const next = await f.authorize();
  const exchange = { grant_type: 'authorization_code', code: next.code, code_verifier: next.verifier, redirect_uri: redirect };
  assert.equal((await f.token(exchange)).status, 200);
  assert.equal((await f.token(exchange)).status, 400);
  for (const change of [
    (q) => q.set('resource', 'https://other.example/mcp'),
    (q) => q.delete('code_challenge'),
    (q) => q.set('code_challenge_method', 'plain'),
    (q) => q.set('redirect_uri', 'https://attacker.example/callback'),
    (q) => q.set('client_id', 'https://127.0.0.1/client.json'),
  ]) {
    const { query } = f.params();
    change(query);
    const response = await f.request(`${prefix}/auth?${query}`);
    const location = response.headers.get('location');
    assert.ok(response.status >= 400 || (location && new URL(location, origin).searchParams.has('error')));
  }
  assert.ok(verifier);
});

test('token validation enforces audience, scope, subject, expiry and grant revocation', async (t) => {
  const f = await fixture(t);
  const valid = await f.grant();
  const original = await f.provider().AccessToken.find(valid.access_token);
  for (const change of [
    { aud: 'https://other.example/mcp' }, { scope: 'unrelated' },
    { accountId: 'another-user' }, { exp: Math.floor(Date.now() / 1000) - 10 },
    { grantId: 'nonexistent' },
  ]) {
    const token = new (f.provider().AccessToken)({
      accountId: original.accountId, clientId: original.clientId, grantId: original.grantId,
      aud: original.aud, scope: original.scope, ...change,
    });
    assert.equal((await f.verify(await token.save())).status, 401);
  }
  const response = await f.request(`${prefix}/token/revocation`, { method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: 'test-client', token: valid.access_token }).toString() });
  assert.equal(response.status, 200);
  assert.equal((await f.verify(valid.access_token)).status, 401);
});

test('only ChatGPT may resolve a metadata document', async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.provider().Client.find('https://attacker.example/client.json'));
  assert.equal(CHATGPT_CLIENT, 'https://chatgpt.com/oauth/client.json');
});

test('signed client assertions are required, verified, and replay protected', async (t) => {
  const f = await fixture(t);
  const { code, verifier } = await f.authorize('test-signed');
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const time = Math.floor(Date.now() / 1000);
  const input = `${encode({ alg: 'RS256', kid: 'test' })}.${encode({ iss: 'test-signed', sub: 'test-signed', aud: `${origin}${prefix}`, iat: time, exp: time + 60, jti: randomUUID() })}`;
  const assertion = `${input}.${sign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url')}`;
  const params = { client_id: 'test-signed', grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: redirect,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' };
  assert.equal((await f.token(params)).status, 401);
  assert.equal((await f.token({ ...params, client_assertion: `${assertion}tampered` })).status, 401);
  const attempts = await Promise.all([f.token({ ...params, client_assertion: assertion }), f.token({ ...params, client_assertion: assertion })]);
  assert.deepEqual(attempts.map((r) => r.status).sort(), [200, 401]);
  const response = attempts.find((r) => r.status === 200);
  const tokens = await response.json();
  assert.equal((await f.verify(tokens.access_token)).status, 204);
  assert.equal((await f.token({ client_id: 'test-signed', grant_type: 'refresh_token', refresh_token: tokens.refresh_token,
    client_assertion_type: params.client_assertion_type, client_assertion: assertion })).status, 401);
});

test('concurrent authorization-code redemption cannot issue two token sets', async (t) => {
  const f = await fixture(t);
  const { code, verifier } = await f.authorize();
  const params = { grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: redirect };
  const responses = await Promise.all([f.token(params), f.token(params)]);
  assert.deepEqual(responses.map((r) => r.status).sort(), [200, 400]);
});

test('consumed consent links fail closed with a browser-friendly message', async (t) => {
  const f = await fixture(t);
  const { query } = f.params();
  let response = await f.request(`${prefix}/auth?${query}`);
  assert.equal(response.status, 303);
  const location = new URL(response.headers.get('location'), origin);
  response = await f.request(location.pathname, { headers: { 'x-host-ingress-operator': 'authenticated' } });
  assert.equal(response.status, 200);
  const csrf = /name="csrf" value="([a-f0-9]+)"/.exec(await response.text())[1];
  const body = new URLSearchParams({ csrf, decision: 'allow' }).toString();
  const headers = { 'x-host-ingress-operator': 'authenticated', 'content-type': 'application/x-www-form-urlencoded', origin };
  response = await f.request(location.pathname, { method: 'POST', body, headers });
  assert.equal(response.status, 303);
  const resume = new URL(response.headers.get('location'), origin);
  assert.equal((await f.request(resume.pathname + resume.search)).status, 303);
  for (const attempt of [
    () => f.request(location.pathname, { method: 'POST', body, headers }),
    () => f.request(location.pathname, { headers: { 'x-host-ingress-operator': 'authenticated' } }),
  ]) {
    response = await attempt();
    assert.equal(response.status, 400, 'reused approval links must fail closed');
    assert.match(response.headers.get('content-type'), /text\/html/);
    assert.match(await response.text(), /already been used or expired/);
  }
});


test('Events contexts authenticate the single operator tuple and survive token expiry, not revocation', async (t) => {
  const f = await fixture(t);
  const check = (body) => f.request(appPaths(app).eventsAuthorize, { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const initial = await f.grant();
  const requestContext = (await f.verify(initial.access_token)).headers.get('x-host-ingress-auth-context');
  assert.ok(requestContext);
  let response = await check({ requestContext });
  assert.equal(response.status, 200);
  const { authorization } = await response.json();
  assert.equal(authorization.principal, secrets.accountId);
  assert.equal(authorization.resource, resource);
  assert.equal(authorization.scope, SCOPE);
  const contexts = eventContexts(secrets.cookieKeys, `${origin}${prefix}`);
  const sealed = contexts.open(requestContext);
  assert.ok(sealed.exp <= sealed.iat + 30);
  for (const body of [{}, { requestContext: 'forged' }, { requestContext: requestContext + 'x' },
    { requestContext: authorization.grantContext },
    { authorization: { ...authorization, grantContext: requestContext } },
    { requestContext: contexts.seal({ ...sealed, exp: sealed.iat - 1 }) },
    { requestContext: contexts.seal({ ...sealed, resource: 'https://wrong.example/mcp' }) },
    { requestContext: eventContexts(secrets.cookieKeys, 'https://wrong.example').seal(sealed) },
    ...['principal', 'clientId', 'grantId', 'resource', 'scope'].map((field) => ({
      authorization: { ...authorization, [field]: 'wrong' },
    }))]) assert.equal((await check(body)).status, 403);
  const access = await f.provider().AccessToken.find(initial.access_token);
  await access.destroy(); // Ordinary expiry/removal does not revoke the live grant.
  assert.equal((await f.verify(initial.access_token)).status, 401);
  assert.equal((await check({ authorization })).status, 200);
  await f.restart();
  assert.equal((await check({ authorization })).status, 200, 'grant context survives auth restart');
  const separate = new (f.provider().Grant)({ accountId: secrets.accountId, clientId: 'test-client' });
  separate.addResourceScope(resource, SCOPE);
  const separateId = await separate.save();
  const separateToken = await new (f.provider().AccessToken)({ accountId: secrets.accountId,
    clientId: 'test-client', grantId: separateId, aud: resource, scope: SCOPE }).save();
  const second = await (await check({ requestContext: (await f.verify(separateToken)).headers.get('x-host-ingress-auth-context') })).json();
  assert.notEqual(second.authorization.grantId, authorization.grantId);
  const revoked = await f.request(`${prefix}/token/revocation`, { method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: 'test-client', token: initial.refresh_token }).toString() });
  assert.equal(revoked.status, 200);
  assert.equal((await check({ authorization })).status, 403);
  assert.equal((await check({ requestContext })).status, 403);
  assert.equal((await check({ authorization: second.authorization })).status, 200);
  separate.rejectResourceScope(resource, SCOPE);
  await separate.save();
  assert.equal((await check({ authorization: second.authorization })).status, 403);
});


test('shared OAuth restart preserves Codex grants and issuer-bound contexts while isolating both apps', async (t) => {
  const directory = mkdtempSync(`${tmpdir()}/host-oauth-two-apps-`);
  const apps = loadApps();
  const configurations = apps.map((app) => ({ app, database: `${directory}/${app.oauth.database}` }));
  let auth;
  async function start() {
    auth = createService({ origin, secrets, apps: configurations });
    await new Promise((resolve) => auth.server.listen(0, '127.0.0.1', resolve));
  }
  async function stop() {
    auth.server.closeAllConnections();
    await new Promise((resolve) => auth.server.close(resolve));
  }
  await start();
  t.after(async () => { await stop(); rmSync(directory, { recursive: true }); });
  const request = (path, options = {}) => fetch(`http://127.0.0.1:${auth.server.address().port}${path}`, options);
  const entries = [];
  for (const app of apps) {
    const provider = auth.providers.get(app.id);
    const resource = `${origin}${app.resource.path}`;
    // Deliberately use an identical grant id: database ownership, not id uniqueness,
    // must prevent one issuer's authorization from crossing into the other.
    const grant = new provider.Grant({ jti: 'same-grant-id', accountId: secrets.accountId, clientId: CHATGPT_CLIENT });
    grant.addResourceScope(resource, app.resource.scope);
    const grantId = await grant.save();
    const bearer = await new provider.AccessToken({ accountId: secrets.accountId, clientId: CHATGPT_CLIENT,
      grantId, aud: resource, scope: app.resource.scope }).save();
    const verify = await request(appPaths(app).verify, { headers: { authorization: `Bearer ${bearer}` } });
    assert.equal(verify.status, 204);
    const context = verify.headers.get('x-host-ingress-auth-context');
    const check = await request(appPaths(app).eventsAuthorize, { method: 'POST',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify({ requestContext: context }) });
    const authorization = (await check.json()).authorization;
    entries.push({ app, bearer, authorization });
    assert.equal((await provider.Grant.find(grantId)).exp, undefined);
  }
  assert.equal(entries[0].authorization.grantId, entries[1].authorization.grantId);
  await stop(); await start();
  for (const { app, bearer, authorization } of entries) {
    assert.equal((await request(appPaths(app).verify, { headers: { authorization: `Bearer ${bearer}` } })).status, 204);
    for (const other of apps) {
      const response = await request(appPaths(other).eventsAuthorize, { method: 'POST',
        headers: { 'content-type': 'application/json' }, body: JSON.stringify({ authorization }) });
      assert.equal(response.status, app.id === other.id ? 200 : 403);
    }
  }
  await auth.providers.get(app.id).Grant.adapter.destroy(entries[0].authorization.grantId);
  assert.equal((await request(appPaths(app).verify, { headers: { authorization: `Bearer ${entries[0].bearer}` } })).status, 401);
  assert.equal((await request(appPaths(apps[1]).verify, { headers: { authorization: `Bearer ${entries[1].bearer}` } })).status, 204,
    'same id in a separate issuer database remains independent');
});
