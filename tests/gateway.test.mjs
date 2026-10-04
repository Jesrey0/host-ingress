import { strict as assert } from 'node:assert';
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { homedir, tmpdir } from 'node:os';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { createAuth } from '../auth/server.mjs';
import { CHATGPT_CLIENT, CHATGPT_REDIRECT } from '../auth/chatgpt.mjs';
import { loadApps, appPaths } from '../lib/apps.mjs';
import { renderNetwork } from '../transport/assurance.mjs';
import { renderApps } from '../lib/routes.mjs';
import { checkApps } from '../scripts/check-apps.mjs';
import { privateRouteProbes } from '../scripts/check-oauth.mjs';

test('both Connect apps cross real Caddy with isolated OAuth, scrubbed credentials and independent backends', async (t) => {
  const directory = mkdtempSync(`${tmpdir()}/host-gateway-test-`);
  const origin = 'https://ingress.example';
  const apps = loadApps();
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const auth = createAuth({ origin, apps: apps.map((app) => ({ app, database: `${directory}/${app.oauth.database}`, clients: [{
    client_id: CHATGPT_CLIENT, redirect_uris: [CHATGPT_REDIRECT], response_types: ['code'],
    grant_types: ['authorization_code', 'refresh_token'], token_endpoint_auth_method: 'private_key_jwt',
    token_endpoint_auth_signing_alg: 'RS256',
    jwks: { keys: [{ ...createPublicKey(privateKey).export({ format: 'jwk' }), kid: 'test', alg: 'RS256' }] },
  }] })), secrets: {
    accountId: 'operator', cookieKeys: [randomBytes(32).toString('hex')],
    jwks: { keys: [{ ...privateKey.export({ format: 'jwk' }), kid: 'test', alg: 'RS256', use: 'sig' }] },
  } });
  let omitContext = false;
  const authHandler = auth.server.listeners('request')[0];
  auth.server.removeAllListeners('request');
  auth.server.on('request', (req, res) => {
    if (omitContext && apps.some((app) => req.url === appPaths(app).verify)) { res.writeHead(204); res.end(); }
    else authHandler(req, res);
  });
  const backends = apps.map((app) => createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ backend: app.id, path: req.url, method: req.method, headers: req.headers, body: Buffer.concat(chunks).toString() }));
  }));
  const listen = async (server) => {
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    return server.address().port;
  };
  const authPort = await listen(auth.server);
  const backendPorts = await Promise.all(backends.map(listen));
  const reservation = createServer();
  const port = await listen(reservation);
  await new Promise((resolve) => reservation.close(resolve));
  const runningApps = apps.map((app, i) => ({ ...app, backend: { ...app.backend, port: backendPorts[i] } }));
  // This fixture exercises the generic OAuth/backend gateway contract. Keep
  // transport assurance observational here; enforcement semantics have their
  // own real-Caddy coverage in transport-gateway.test.mjs.
  const routes = renderApps(runningApps, `127.0.0.1:${authPort}`, { mode: 'observe' });
  const path = `${directory}/Caddyfile`;
  mkdirSync(`${directory}/.local/state/host-ingress/logs`, { recursive: true });
  writeFileSync(`${directory}/apps.caddy`, routes);
  writeFileSync(`${directory}/assurance.caddy`, renderNetwork());
  writeFileSync(path, readFileSync(new URL('../Caddyfile', import.meta.url), 'utf8')
    .replace('admin 127.0.0.1:2019', 'admin off\n\tauto_https off').replace(':9000 {', `http://127.0.0.1:${port} {`));
  const caddy = `${homedir()}/.local/bin/caddy`;
  const password = randomBytes(32).toString('hex');
  const hash = spawnSync(caddy, ['hash-password', '--algorithm', 'bcrypt'], { input: `${password}\n`, encoding: 'utf8' });
  assert.equal(hash.status, 0);
  const child = spawn(caddy, ['run', '--config', path, '--adapter', 'caddyfile'], {
    env: { ...process.env, HOME: directory, XDG_CONFIG_HOME: directory,
      CODEX_CONNECT_BASIC_AUTH_USER: 'operator', CODEX_CONNECT_BASIC_AUTH_HASH: hash.stdout.trim() },
    stdio: 'ignore',
  });
  const canaries = [password, Buffer.from(`operator:${password}`).toString('base64'), 'private=canary', 'spoofed', 'sample=kept'];
  t.after(async () => {
    if (child.exitCode === null) { child.kill(); await once(child, 'exit'); }
    for (const backend of backends) {
      if (backend.listening) { backend.closeAllConnections(); await new Promise((resolve) => backend.close(resolve)); }
    }
    if (auth.server.listening) {
      auth.server.closeAllConnections();
      await new Promise((resolve) => auth.server.close(resolve));
    }
    const logs = readFileSync(`${directory}/.local/state/host-ingress/logs/access.log`, 'utf8');
    assert.ok(logs.includes('codex-connect-mcp') && logs.includes('opencode-connect-mcp'));
    for (const canary of canaries) assert.ok(!logs.includes(canary), 'access log contains sensitive request data');
    for (const entry of logs.trim().split('\n').map(JSON.parse)) {
      assert.equal(entry.request.uri, undefined);
      for (const name of ['Authorization', 'Cookie', 'X-Host-Ingress-Operator', 'X-Host-Ingress-Auth-Context', 'X-Host-Ingress-Client-Id', 'X-Host-Ingress-Transport-Assurance', 'X-Forwarded-For']) assert.equal(entry.request.headers?.[name], undefined);
      for (const name of ['Location', 'Set-Cookie']) assert.equal(entry.resp_headers?.[name], undefined);
    }
    rmSync(directory, { recursive: true });
  });
  const request = (url, headers = {}) => fetch(`http://127.0.0.1:${port}${url}`, { headers, redirect: 'manual', signal: AbortSignal.timeout(5000) });
  const cookies = new Map();
  async function browserRequest(url, { method = 'GET', headers = {}, body } = {}) {
    const cookie = [...cookies].map(([name, value]) => `${name}=${value}`).join('; ');
    const response = await fetch(`http://127.0.0.1:${port}${url}`, {
      method, body, redirect: 'manual', signal: AbortSignal.timeout(5000),
      headers: { ...(cookie ? { cookie } : {}), ...headers },
    });
    for (const setCookie of response.headers.getSetCookie()) {
      const [pair] = setCookie.split(';');
      const split = pair.indexOf('=');
      cookies.set(pair.slice(0, split), pair.slice(split + 1));
    }
    return response;
  }
  function clientAssertion(app) {
    const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const time = Math.floor(Date.now() / 1000);
    const input = `${encode({ alg: 'RS256', kid: 'test' })}.${encode({
      iss: CHATGPT_CLIENT, sub: CHATGPT_CLIENT, aud: `${origin}${app.oauth.path}`,
      iat: time, exp: time + 60, jti: randomUUID(),
    })}`;
    return `${input}.${sign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url')}`;
  }
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    try { ready = (await request('/')).status === 404; } catch { /* bounded startup readiness */ }
    if (ready || child.exitCode !== null) break;
    await delay(25);
  }
  assert.ok(ready, 'fixture Caddy failed to start');
  const surviving = [];
  for (const app of runningApps) {
    const provider = auth.providers.get(app.id);
    await checkApps('backend', app);

    const resource = `${origin}${app.resource.path}`;
    const resourceMetadata = await (await request(appPaths(app).metadata)).json();
    assert.equal(resourceMetadata.resource, resource);
    assert.deepEqual(resourceMetadata.authorization_servers, [`${origin}${app.oauth.path}`]);
    assert.equal(resourceMetadata.resource_name, app.title);
    assert.deepEqual(resourceMetadata.scopes_supported, [app.resource.scope]);
    assert.deepEqual(resourceMetadata.bearer_methods_supported, ['header']);
    for (const headers of [{}, { authorization: 'Basic invalid' }, { authorization: 'Bearer invalid' },
      { 'x-host-ingress-operator': 'authenticated' }]) {
      const response = await request(app.resource.path, headers);
      assert.equal(response.status, 401);
      assert.ok(response.headers.get('www-authenticate').includes(appPaths(app).metadata));
    }
    assert.equal((await request(`${app.oauth.path}/interaction/invalid`, { 'x-host-ingress-operator': 'authenticated' })).status, 401);
    assert.equal((await request(`${app.oauth.path}/interaction/invalid`, { authorization: `Basic ${Buffer.from(`operator:${password}`).toString('base64')}` })).status, 400);
    for (const path of privateRouteProbes(app)) {
      assert.equal((await request(path)).status, 404, `private or undeclared route exposed: ${path}`);
    }
    assert.equal((await request(appPaths(app).metadata)).status, 200);

    const verifier = randomBytes(32).toString('base64url');
    const state = randomUUID();
    const authorize = new URLSearchParams({
      client_id: CHATGPT_CLIENT,
      redirect_uri: CHATGPT_REDIRECT,
      response_type: 'code',
      scope: `openid ${app.resource.scope}`,
      resource,
      prompt: 'consent',
      state,
      code_challenge: createHash('sha256').update(verifier).digest('base64url'),
      code_challenge_method: 'S256',
    });
    let oauth = await browserRequest(`${app.oauth.path}/auth?${authorize}`);
    assert.equal(oauth.status, 303);
    const interaction = new URL(oauth.headers.get('location'), origin);
    const basic = `Basic ${Buffer.from(`operator:${password}`).toString('base64')}`;
    oauth = await browserRequest(interaction.pathname, { headers: { authorization: basic } });
    assert.equal(oauth.status, 200);
    const csrf = /name="csrf" value="([a-f0-9]+)"/.exec(await oauth.text())[1];
    oauth = await browserRequest(interaction.pathname, {
      method: 'POST',
      headers: { authorization: basic, origin, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ csrf, decision: 'allow' }).toString(),
    });
    assert.equal(oauth.status, 303);
    const resume = new URL(oauth.headers.get('location'), origin);
    oauth = await browserRequest(resume.pathname + resume.search);
    assert.equal(oauth.status, 303);
    const callback = new URL(oauth.headers.get('location'));
    assert.equal(callback.origin + callback.pathname, CHATGPT_REDIRECT);
    assert.equal(callback.searchParams.get('state'), state);
    assert.equal(callback.searchParams.get('iss'), `${origin}${app.oauth.path}`);

    const assertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
    const tokenRequest = (parameters) => fetch(`http://127.0.0.1:${port}${app.oauth.path}/token`, {
      method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(5000),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: CHATGPT_CLIENT, resource, client_assertion_type: assertionType,
        client_assertion: clientAssertion(app), ...parameters,
      }).toString(),
    });
    const other = apps.find((candidate) => candidate.id !== app.id);
    const crossToken = async (parameters, assertionApp = other) => fetch(`http://127.0.0.1:${port}${other.oauth.path}/token`, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: CHATGPT_CLIENT, resource: `${origin}${other.resource.path}`,
        client_assertion_type: assertionType, client_assertion: clientAssertion(assertionApp), ...parameters }),
    });
    assert.equal((await crossToken({ grant_type: 'authorization_code', code: callback.searchParams.get('code'),
      code_verifier: verifier, redirect_uri: CHATGPT_REDIRECT })).status, 400);
    let tokenResponse = await tokenRequest({
      grant_type: 'authorization_code',
      code: callback.searchParams.get('code'),
      code_verifier: verifier,
      redirect_uri: CHATGPT_REDIRECT,
    });
    assert.equal(tokenResponse.status, 200);
    const initial = await tokenResponse.json();
    canaries.push(initial.access_token, initial.refresh_token, csrf, callback.searchParams.get('code'));
    assert.equal((await crossToken({ grant_type: 'refresh_token', refresh_token: initial.refresh_token })).status, 400);
    assert.equal((await crossToken({ grant_type: 'refresh_token', refresh_token: initial.refresh_token }, app)).status, 401);
    assert.ok(initial.access_token && initial.refresh_token);

    const mcpRequest = {
      jsonrpc: '2.0', id: 1, method: 'initialize',
      params: { protocolVersion: '2026-07-28', capabilities: {},
        clientInfo: { name: 'host-ingress-test', version: '1.0.0' } },
    };
    const response = await fetch(`http://127.0.0.1:${port}${app.resource.path}?sample=kept`, {
      method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(5000),
      headers: { authorization: `Bearer ${initial.access_token}`, cookie: 'private=canary',
        'x-host-ingress-operator': 'spoofed', 'x-host-ingress-auth-context': ['forged', 'duplicate'], 'content-type': 'application/json',
        accept: 'application/json, text/event-stream' },
      body: JSON.stringify(mcpRequest),
    });
    assert.equal(response.status, 200);
    const upstream = await response.json();
    assert.equal(upstream.backend, app.id);
    assert.equal(upstream.path, `${app.resource.upstreamPath}?sample=kept`);
    assert.equal(upstream.method, 'POST');
    assert.deepEqual(JSON.parse(upstream.body), mcpRequest);
    assert.equal(upstream.headers.accept, 'application/json, text/event-stream');
    assert.equal(upstream.headers.authorization, undefined);
    assert.equal(upstream.headers.cookie, undefined);
    assert.equal(upstream.headers['x-host-ingress-operator'], undefined);
    assert.equal(upstream.headers['x-host-ingress-client-id'], undefined);
    assert.equal(upstream.headers['x-host-ingress-transport-assurance'], undefined);
    const context = upstream.headers['x-host-ingress-auth-context'];
    assert.ok(context && !context.includes('forged') && !context.includes(','));
    const contextCheck = await fetch(`http://127.0.0.1:${authPort}${appPaths(app).eventsAuthorize}`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ requestContext: context }),
    });
    assert.equal(contextCheck.status, 200);
    const authorization = (await contextCheck.json()).authorization;
    canaries.push(context, authorization.grantContext);
    assert.equal(authorization.principal, 'operator');
    const sibling = apps.find((other) => other.id !== app.id);
    assert.equal((await request(sibling.resource.path, { authorization: `Bearer ${initial.access_token}`,
      'x-host-ingress-auth-context': context })).status, 401);
    for (const body of [{ requestContext: context }, { authorization }]) {
      const denied = await fetch(`http://127.0.0.1:${authPort}${appPaths(sibling).eventsAuthorize}`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
      });
      assert.equal(denied.status, 403, 'sibling issuer must reject request and durable grant contexts');
    }

    tokenResponse = await tokenRequest({ grant_type: 'refresh_token', refresh_token: initial.refresh_token });
    assert.equal(tokenResponse.status, 200);
    const refreshed = await tokenResponse.json();
    assert.ok(refreshed.access_token);
    assert.equal(refreshed.refresh_token, initial.refresh_token);
    const revoked = await fetch(`http://127.0.0.1:${port}${app.oauth.path}/token/revocation`, {
      method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(5000),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: CHATGPT_CLIENT, token: initial.refresh_token,
        client_assertion_type: assertionType, client_assertion: clientAssertion(app),
      }).toString(),
    });
    assert.equal(revoked.status, 200);
    assert.equal((await request(app.resource.path, { authorization: `Bearer ${refreshed.access_token}` })).status, 401);
    assert.equal((await tokenRequest({ grant_type: 'refresh_token', refresh_token: initial.refresh_token })).status, 400);

    const metadata = await (await request(appPaths(app).issuerMetadata)).json();
    assert.equal(metadata.issuer, `${origin}${app.oauth.path}`);
    assert.equal(metadata.token_endpoint, `${origin}${app.oauth.path}/token`);
    assert.equal(metadata.authorization_endpoint, `${origin}${app.oauth.path}/auth`);
    assert.equal(metadata.authorization_response_iss_parameter_supported, true);
    assert.equal(metadata.client_id_metadata_document_supported, true);
    assert.deepEqual(metadata.code_challenge_methods_supported, ['S256']);
    assert.deepEqual(metadata.token_endpoint_auth_methods_supported, ['private_key_jwt']);

    const residualGrant = new provider.Grant({ accountId: 'operator', clientId: CHATGPT_CLIENT });
    residualGrant.addResourceScope(resource, app.resource.scope);
    const residualBearer = await new provider.AccessToken({ accountId: 'operator', clientId: CHATGPT_CLIENT,
      grantId: await residualGrant.save(), aud: resource, scope: app.resource.scope }).save();
    omitContext = true;
    assert.equal((await request(app.resource.path, { authorization: `Bearer ${residualBearer}`,
      'x-host-ingress-auth-context': 'spoofed' })).status, 502, 'verifier success without context must fail closed');
    omitContext = false;
    surviving.push({ app, bearer: residualBearer });
  }
  backends[0].closeAllConnections();
  await new Promise((resolve) => backends[0].close(resolve));
  assert.equal((await request(surviving[0].app.resource.path, { authorization: `Bearer ${surviving[0].bearer}` })).status, 502);
  assert.equal((await request(surviving[1].app.resource.path, { authorization: `Bearer ${surviving[1].bearer}` })).status, 200, 'OpenCode stays usable while Codex backend is down');
  auth.server.closeAllConnections();
  await new Promise((resolve) => auth.server.close(resolve));
  for (const { app, bearer } of surviving) assert.equal((await request(app.resource.path, { authorization: `Bearer ${bearer}` })).status, 502);
});
