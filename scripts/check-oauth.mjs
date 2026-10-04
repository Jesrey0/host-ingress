#!/usr/bin/env node
import { strict as assert } from 'node:assert';
import { createHash, randomBytes } from 'node:crypto';
import { CHATGPT_CLIENT, CHATGPT_REDIRECT } from '../auth/chatgpt.mjs';
import { appPaths, loadApps } from '../lib/apps.mjs';
import { publicOrigin } from '../lib/origin.mjs';

// Regression probes for the default-deny boundary; these are not app configuration.
export function privateRouteProbes(app) {
  const { verify, eventsAuthorize } = appPaths(app);
  const prefix = app.oauth.path;
  const backendPaths = ['/status', '/health', '/healthz', '/session', '/session/raw',
    '/provider', '/config', '/event', '/global', '/permission', '/file'];
  return ['/verify', '/mcp', ...backendPaths, verify, eventsAuthorize,
    `${prefix}/verify`, `${prefix}/healthz`, `${app.resource.path}/`, `${prefix}/reg`,
    `${prefix}/token/extra`, `${prefix}/auth/extra/path`, `${prefix}/interaction/extra/path`,
    ...backendPaths.map((path) => `/${app.id}${path}`)];
}

export async function checkOAuth(base, origin, app) {
  const { metadata: metadataPath, issuerMetadata } = appPaths(app);
  const scope = app.resource.scope;
  const prefix = app.oauth.path;
  const resource = `${origin}${app.resource.path}`;
  const request = (path, options = {}) => fetch(`${base}${path}`, { redirect: 'manual', signal: AbortSignal.timeout(8000), ...options });
  for (const headers of [{}, { authorization: 'Basic invalid' }, { authorization: 'Bearer invalid' },
    { 'x-host-ingress-operator': 'authenticated', 'x-forwarded-user': 'operator' }]) {
    const response = await request(app.resource.path, { method: 'POST', headers });
    assert.equal(response.status, 401, 'MCP must reject missing/invalid credentials');
    assert.ok(response.headers.get('www-authenticate')?.includes(`resource_metadata="${origin}${metadataPath}"`), 'Bearer discovery challenge missing');
  }
  for (const path of privateRouteProbes(app)) {
    assert.equal((await request(path)).status, 404, `private or undeclared route exposed: ${path}`);
  }
  assert.equal((await request(`${prefix}/interaction/invalid`, { headers: { 'x-host-ingress-operator': 'authenticated' } })).status, 401, 'consent login can be spoofed');
  const response = await request(metadataPath);
  assert.equal(response.status, 200);
  const metadata = await response.json();
  assert.equal(metadata.resource, resource);
  assert.deepEqual(metadata.authorization_servers, [`${origin}${prefix}`]);
  assert.equal(metadata.resource_name, app.title);
  assert.deepEqual(metadata.scopes_supported, [scope]);
  assert.deepEqual(metadata.bearer_methods_supported, ['header']);
  const discovery = await (await request(issuerMetadata)).json();
  assert.equal(discovery.issuer, metadata.authorization_servers[0]);
  assert.equal(discovery.token_endpoint, `${discovery.issuer}/token`);
  assert.equal(discovery.authorization_response_iss_parameter_supported, true);
  assert.equal(discovery.client_id_metadata_document_supported, true);
  assert.deepEqual(discovery.token_endpoint_auth_methods_supported, ['private_key_jwt']);
  assert.deepEqual(discovery.code_challenge_methods_supported, ['S256']);
  assert.ok(discovery.scopes_supported.includes('offline_access'));
  if (base.startsWith('https:')) assert.ok(response.headers.get('strict-transport-security')?.includes('max-age='));

  // Exercise the deployed provider's registered ChatGPT CIMD client.
  // Stop at the operator login: this must not approve a grant or mint tokens.
  const query = new URLSearchParams({
    client_id: CHATGPT_CLIENT, redirect_uri: CHATGPT_REDIRECT, response_type: 'code',
    scope: `openid offline_access ${scope}`, resource, prompt: 'consent',
    state: randomBytes(24).toString('base64url'),
    code_challenge: createHash('sha256').update(randomBytes(32)).digest('base64url'),
    code_challenge_method: 'S256',
  });
  const authorization = await request(`${prefix}/auth?${query}`);
  assert.equal(authorization.status, 303, 'ChatGPT CIMD authorization must reach operator login');
  const interaction = new URL(authorization.headers.get('location'), origin);
  assert.equal(interaction.origin, origin);
  assert.ok(interaction.pathname.startsWith(`${prefix}/interaction/`), 'authorization redirected somewhere other than consent');
  const login = await request(interaction.pathname);
  assert.equal(login.status, 401);
  assert.ok(login.headers.get('www-authenticate')?.startsWith('Basic '), 'operator login challenge missing');

  query.delete('code_challenge');
  const rejected = await request(`${prefix}/auth?${query}`);
  assert.equal(rejected.status, 303);
  const callback = new URL(rejected.headers.get('location'));
  assert.equal(callback.origin + callback.pathname, CHATGPT_REDIRECT);
  assert.equal(callback.searchParams.get('iss'), discovery.issuer, 'OAuth errors must identify the issuer');
  assert.equal(callback.searchParams.get('state'), query.get('state'));
  assert.equal(callback.searchParams.get('error'), 'invalid_request');
  const surface = base.startsWith('https:') ? 'public' : 'local';
  console.log(`${app.id} ${surface} OAuth boundary: discovery, ChatGPT CIMD login handoff, PKCE rejection, issuer identification, private routes, and consent isolation verified`);
}

if (import.meta.main) {
  const base = process.argv[2];
  if (!base) throw new Error('usage: node scripts/check-oauth.mjs <gateway-or-public-base>');
  const origin = publicOrigin();
  for (const app of loadApps()) await checkOAuth(base, origin, app);
}
