import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { loadApp, loadApps, validateApp, validateApps, appPaths } from '../lib/apps.mjs';
import { publicOrigin } from '../lib/origin.mjs';
import { renderRoutes, renderApps } from '../lib/routes.mjs';
import { ngrokArguments, tunnelIdentity, edgeHeaders } from '../transport/ngrok/transport.mjs';

const app = loadApp();

test('Codex Connect profile freezes the existing public and persistent-state contract', () => {
  assert.equal(app.id, 'codex-connect');
  assert.deepEqual(app.resource, { path: '/codex-connect/mcp', upstreamPath: '/mcp', scope: 'codex-connect:access' });
  assert.deepEqual(app.oauth, {
    path: '/codex-connect/oauth', database: 'oauth.sqlite',
    cookies: { session: '_session', interaction: '_interaction', resume: '_interaction_resume' },
  });
  assert.deepEqual(app.backend, { port: 8767, service: 'codex-connect.service', healthPath: '/healthz' });
  assert.equal(appPaths(app).metadata, '/.well-known/oauth-protected-resource/codex-connect/mcp');
  assert.equal(appPaths(app).issuerMetadata, '/.well-known/oauth-authorization-server/codex-connect/oauth');
});

test('PUBLIC_ORIGIN is the only accepted public authority', () => {
  const origin = 'https://ingress.example';
  for (const env of [{ PUBLIC_ORIGIN: origin }, { PUBLIC_ORIGIN: `${origin}/` }]) assert.equal(publicOrigin(env), origin);
  for (const env of [{}, { PUBLIC_ORIGIN: '' },
    ...['http://example.com', `${origin}/path`, `${origin}//`, `${origin}?q=1`, `${origin}#x`, 'https://user:pass@example.com'].map((PUBLIC_ORIGIN) => ({ PUBLIC_ORIGIN }))]) {
    assert.throws(() => publicOrigin(env));
  }
});

test('Codex Connect profile rejects unsafe paths, interpolation and non-loopback destinations', () => {
  assert.equal(validateApp(app), app);
  for (const change of [
    (a) => { a.oauth.database = '../escape.sqlite'; },
    (a) => { a.resource.path = '/another-app/mcp'; },
    (a) => { a.resource.path = '/dummy/*'; },
    (a) => { a.oauth.path = a.resource.path; },
    (a) => { a.resource.path = `${a.oauth.path}/token`; },
    (a) => { a.backend.port = 'example.com:80'; },
    (a) => { a.backend.port = 9000; },
    (a) => { a.oauth.cookies.resume = a.oauth.cookies.session; },
    (a) => { delete a.resource.scope; },
    (a) => { a.resource.scope = 'bad"scope'; },
  ]) {
    const invalid = structuredClone(app);
    change(invalid);
    assert.throws(() => renderRoutes(invalid));
  }
  assert.throws(() => renderRoutes(app, '0.0.0.0:9001'));
  assert.throws(() => validateApp({ ...structuredClone(app), id: 'another-app' }));
});

test('ngrok owns transport identity and edge evidence independently of app routes', () => {
  const origin = 'https://ingress.example';
  const args = ngrokArguments(origin, '/example');
  assert.deepEqual(args.slice(0, 7), ['http', '127.0.0.1:9000', '--url', origin, '--name', 'host-ingress', '--inspect=false']);
  assert.ok(args.includes('/example/.config/ngrok/ngrok.yml'));
  const tunnel = { name: 'host-ingress', public_url: origin, config: { addr: 'http://127.0.0.1:9000' } };
  assert.doesNotThrow(() => tunnelIdentity({ tunnels: [tunnel] }, origin));
  for (const candidate of [{ ...tunnel, name: 'other' }, { ...tunnel, public_url: 'https://other.example' },
    { ...tunnel, config: { addr: 'http://0.0.0.0:9000' } }]) assert.throws(() => tunnelIdentity({ tunnels: [candidate] }, origin));
  assert.throws(() => edgeHeaders(new Headers()));
  assert.doesNotThrow(() => edgeHeaders(new Headers({ 'x-host-ingress-policy': 'ngrok-edge-v2', 'strict-transport-security': 'max-age=31536000' })));
});


test('two explicit production profiles isolate OAuth state and reuse the existing operator', () => {
  const apps = loadApps();
  assert.deepEqual(apps.map((app) => app.id), ['codex-connect', 'opencode-connect']);
  const open = apps[1];
  assert.deepEqual(open.resource, { path: '/opencode-connect/mcp', upstreamPath: '/mcp', scope: 'opencode-connect:access' });
  assert.equal(open.oauth.path, '/opencode-connect/oauth');
  assert.equal(open.oauth.database, 'opencode-connect-oauth.sqlite');
  assert.deepEqual(open.backend, { port: 8788, service: 'opencode-connect.service', healthPath: '/health' });
  const routes = renderApps(apps);
  for (const app of apps) {
    assert.ok(routes.includes(`127.0.0.1:${app.backend.port}`));
    assert.match(renderRoutes(app), /basic_auth \{\s+\{\$CODEX_CONNECT_BASIC_AUTH_USER\} \{\$CODEX_CONNECT_BASIC_AUTH_HASH\}/);
  }
  for (const change of [
    (a) => { a[1].oauth.database = a[0].oauth.database; },
    (a) => { a[1].oauth.cookies = a[0].oauth.cookies; },
    (a) => { a[1].backend.port = a[0].backend.port; },
    (a) => { a[1].resource.scope = a[0].resource.scope; },
  ]) {
    const invalid = structuredClone(apps); change(invalid);
    assert.throws(() => validateApps(invalid));
  }
  assert.throws(() => validateApps([app, app]));
});
