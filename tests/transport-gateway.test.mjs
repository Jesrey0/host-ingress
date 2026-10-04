import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { createServer, request as httpRequest } from 'node:http';
import { once } from 'node:events';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { loadApps, appPaths } from '../lib/apps.mjs';
import { renderApps } from '../lib/routes.mjs';
import { parseSource, renderNetwork } from '../transport/assurance.mjs';
import { CHATGPT_CLIENT } from '../auth/chatgpt.mjs';
import { checkXff } from '../scripts/check-xff.mjs';

for (const mode of ['observe', 'enforce']) test(`real Caddy ${mode} binds verified client identity to strict authoritative client_ip`, async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'host-transport-gateway-'));
  const apps = loadApps();
  const servers = [];
  let child;
  t.after(async () => {
    if (child && child.exitCode === null) { child.kill(); await once(child, 'exit'); }
    for (const server of servers) {
      server.closeAllConnections();
      if (server.listening) await new Promise((resolve) => server.close(resolve));
    }
    rmSync(directory, { recursive: true, force: true });
  });
  const listen = async (handler) => {
    const server = createServer(handler); servers.push(server);
    server.listen(0, '127.0.0.1'); await once(server, 'listening');
    return server.address().port;
  };
  const backendPorts = await Promise.all(apps.map(() => listen((req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ path: req.url, headers: req.headers }));
  })));
  const verifierRequests = [];
  const authPort = await listen((req, res) => {
    verifierRequests.push({ path: req.url, headers: req.headers });
    if (apps.some((app) => req.url === appPaths(app).verify)) {
      const token = req.headers.authorization;
      if (!token) { res.writeHead(401); res.end(); return; }
      if (token !== 'Bearer no-context') res.setHeader('x-host-ingress-auth-context', 'sealed-context-canary');
      if (token !== 'Bearer missing') res.setHeader('x-host-ingress-client-id', token === 'Bearer chatgpt'
        ? CHATGPT_CLIENT : token === 'Bearer similar' ? `${CHATGPT_CLIENT}/` : 'future-client');
      res.writeHead(204); res.end();
    } else { res.writeHead(200); res.end('oauth'); }
  });
  const reservation = createServer();
  reservation.listen(0, '127.0.0.1'); await once(reservation, 'listening');
  const port = reservation.address().port;
  await new Promise((resolve) => reservation.close(resolve));
  const runningApps = apps.map((app, i) => ({ ...app, backend: { ...app.backend, port: backendPorts[i] } }));
  const routes = renderApps(runningApps, `127.0.0.1:${authPort}`, { mode });
  const network = parseSource({ creationTime: '2026-09-22T18:18:05.915327',
    prefixes: [{ ipv4Prefix: '100.31.168.162/32' }, { ipv6Prefix: '2606:4700::/32' }] }, Date.parse('2026-10-03T00:00:00Z'));
  mkdirSync(join(directory, '.local/state/host-ingress/logs'), { recursive: true });
  writeFileSync(join(directory, 'apps.caddy'), routes);
  writeFileSync(join(directory, 'assurance.caddy'), renderNetwork(network));
  writeFileSync(join(directory, 'Caddyfile'), readFileSync(new URL('../Caddyfile', import.meta.url), 'utf8')
    .replace('admin 127.0.0.1:2019', 'admin off\n\tauto_https off').replace(':9000 {', `http://127.0.0.1:${port} {`));
  const caddy = join(homedir(), '.local/bin/caddy');
  const hash = spawnSync(caddy, ['hash-password', '--algorithm', 'bcrypt'], { input: 'fixture-password\n', encoding: 'utf8' });
  assert.equal(hash.status, 0);
  const env = { ...process.env, HOME: directory, XDG_CONFIG_HOME: directory,
    CODEX_CONNECT_BASIC_AUTH_USER: 'operator', CODEX_CONNECT_BASIC_AUTH_HASH: hash.stdout.trim() };
  const adapted = spawnSync(caddy, ['adapt', '--config', join(directory, 'Caddyfile'), '--adapter', 'caddyfile'], { env, encoding: 'utf8' });
  assert.equal(adapted.status, 0, adapted.stderr);
  const serverConfig = Object.values(JSON.parse(adapted.stdout).apps.http.servers)[0];
  assert.deepEqual(serverConfig.trusted_proxies, { source: 'static', ranges: ['127.0.0.1/32', '::1/128'] });
  // Caddy 2.11.4 represents enabled strict parsing as integer 1.
  assert.equal(serverConfig.trusted_proxies_strict, 1);
  assert.deepEqual(serverConfig.client_ip_headers, ['X-Forwarded-For']);
  child = spawn(caddy, ['run', '--config', join(directory, 'Caddyfile'), '--adapter', 'caddyfile'], { env, stdio: ['ignore', 'ignore', 'pipe'] });
  let runtimeLogs = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => { runtimeLogs += chunk; });
  const request = (path, token, xff, extra = {}) => fetch(`http://127.0.0.1:${port}${path}`, {
    headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(xff ? { 'x-forwarded-for': xff } : {}), ...extra },
    redirect: 'manual', signal: AbortSignal.timeout(5000),
  });
  let ready = false;
  for (let i = 0; i < 100; i++) {
    try { ready = (await request('/')).status === 404; } catch { /* bounded fixture startup */ }
    if (ready || child.exitCode !== null) break;
    await delay(25);
  }
  assert.ok(ready, 'fixture Caddy did not start');
  const outsider = '203.0.113.99';
  for (const app of apps) {
    const resource = app.resource.path;
    const spoof = { 'x-host-ingress-client-id': CHATGPT_CLIENT, 'x-host-ingress-auth-context': 'forged-context-canary',
      'x-host-ingress-operator': 'forged-operator-canary', 'x-host-ingress-transport-assurance': 'openai-network', 'x-host-ingress-unexpected': 'internal-canary', cookie: 'cookie-canary', 'x-openai-subject': 'subject-canary', 'x-openai-session': 'session-canary' };
    const expected = mode === 'observe' ? 200 : 403;
    assert.equal((await request(resource, 'chatgpt', outsider, spoof)).status, expected);
    // A left-hand caller-supplied OpenAI address cannot override the actual peer appended by the edge.
    assert.equal((await request(resource, 'chatgpt', `100.31.168.162, ${outsider}`, spoof)).status, expected);
    assert.equal((await request(resource, 'chatgpt')).status, expected, 'absent XFF is loopback, outside the provider network');
    assert.equal((await request(resource, 'chatgpt', 'invalid-xff-canary')).status, expected);
    assert.equal((await request(resource, 'missing', '100.31.168.162', spoof)).status, 502);
    assert.equal((await request(resource, 'no-context', '100.31.168.162', spoof)).status, 502);
    // Send distinct physical header values, not a single spoofed identity.
    const duplicateStatus = await new Promise((resolve, reject) => {
      const req = httpRequest({ hostname: '127.0.0.1', port, path: resource,
        headers: { authorization: 'Bearer future', 'x-forwarded-for': outsider,
          'x-host-ingress-client-id': [CHATGPT_CLIENT, 'duplicate-client-canary'] } }, (res) => {
        let body = ''; res.setEncoding('utf8'); res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          try {
            assert.equal(JSON.parse(body).headers['x-host-ingress-auth-context'], 'sealed-context-canary');
            assert.equal(JSON.parse(body).headers['x-host-ingress-client-id'], undefined);
            resolve(res.statusCode);
          } catch (error) { reject(error); }
        });
      });
      req.on('error', reject); req.end();
    });
    assert.equal(duplicateStatus, 200, 'duplicate caller IDs must be replaced by future verifier identity');
    assert.equal((await request(resource, 'chatgpt', outsider, {
      ...spoof, 'x-host-ingress-client-id': 'future-client, duplicate-client-canary',
    })).status, expected, 'duplicate caller IDs cannot bypass exact verified ChatGPT assurance');
    for (const token of ['future', 'similar']) {
      const result = await request(resource, token, outsider, spoof);
      assert.equal(result.status, 200, 'only the exact verified ChatGPT client is gated');
      const upstream = await result.json();
      assert.equal(upstream.headers['x-host-ingress-auth-context'], 'sealed-context-canary');
      assert.equal(upstream.headers.authorization, undefined);
      assert.equal(upstream.headers.cookie, undefined);
      assert.deepEqual(Object.keys(upstream.headers).filter((key) => key.startsWith('x-host-ingress-')), ['x-host-ingress-auth-context']);
    }
    for (const xff of ['100.31.168.162', '2606:4700::1234', `${outsider}, 100.31.168.162, 127.0.0.1`]) {
      const result = await request(resource, 'chatgpt', xff, spoof);
      assert.equal(result.status, 200);
      const upstream = await result.json();
      assert.equal(upstream.headers['x-openai-subject'], undefined);
      assert.equal(upstream.headers['x-openai-session'], undefined);
      assert.equal(upstream.headers['x-host-ingress-client-id'], undefined);
      assert.equal(upstream.headers['x-host-ingress-transport-assurance'], undefined);
      assert.equal(upstream.headers['x-host-ingress-auth-context'], 'sealed-context-canary');
    }
    assert.equal((await request(resource, null, '100.31.168.162', spoof)).status, 401);
    // Discovery, browser, token and operator consent always reach their ordinary auth boundary.
    for (const path of [appPaths(app).metadata, appPaths(app).issuerMetadata, `${app.oauth.path}/auth`, `${app.oauth.path}/token`]) {
      assert.equal((await request(path, null, outsider, spoof)).status, 200);
    }
    const basic = `Basic ${Buffer.from('operator:fixture-password').toString('base64')}`;
    assert.equal((await request(`${app.oauth.path}/interaction/fixture`, null, outsider, { ...spoof, authorization: basic })).status, 200);
    // Even a loopback address outside the explicit /32 cannot supply trusted XFF.
    const status = await new Promise((resolve, reject) => {
      const req = httpRequest({ hostname: '127.0.0.1', port, path: resource, localAddress: '127.0.0.2',
        headers: { authorization: 'Bearer chatgpt', 'x-forwarded-for': '100.31.168.162' } }, (res) => { res.resume(); resolve(res.statusCode); });
      req.on('error', reject); req.end();
    });
    assert.equal(status, expected);
  }
  for (const { path, headers } of verifierRequests.filter((req) => apps.some((app) => req.path === appPaths(app).verify))) {
    assert.deepEqual(Object.keys(headers).filter((key) => key.startsWith('x-host-ingress-')), [], `caller trust header reached verifier at ${path}`);
  }
  for (const { path, headers } of verifierRequests.filter((req) => !apps.some((app) => req.path === appPaths(app).verify))) {
    const internal = Object.keys(headers).filter((key) => key.startsWith('x-host-ingress-'));
    if (path.includes('/interaction/')) {
      assert.deepEqual(internal, ['x-host-ingress-operator'], `caller trust leaked into consent at ${path}`);
      assert.equal(headers['x-host-ingress-operator'], 'authenticated');
    } else assert.deepEqual(internal, [], `caller trust leaked into OAuth at ${path}`);
  }
  // Exercise the actual redacted default-deny log correlation through fixture Caddy.
  await checkXff(`http://127.0.0.1:${port}`, {
    logPath: join(directory, '.local/state/host-ingress/logs/access.log'), snapshot: network,
    fetcher: (url, options) => fetch(url, { ...options,
      headers: { 'x-forwarded-for': `${options.headers['X-Forwarded-For']}, ${outsider}` } }),
  });
  for (const server of servers.slice(0, apps.length)) {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
  assert.equal((await request(`${apps[0].resource.path}?uri-canary=private`, 'future', outsider,
    { 'x-host-ingress-auth-context': 'forged-context-canary', cookie: 'cookie-canary' })).status, 502);
  child.kill(); await once(child, 'exit');
  const logText = readFileSync(join(directory, '.local/state/host-ingress/logs/access.log'), 'utf8');
  const logs = logText.trim().split('\n').map(JSON.parse);
  for (const canary of ['Bearer', 'cookie-canary', 'sealed-context-canary', 'forged-context-canary', 'internal-canary', 'invalid-xff-canary', 'uri-canary', 'subject-canary', 'session-canary', 'duplicate-client-canary', 'forged-operator-canary', CHATGPT_CLIENT]) {
    assert.ok(!logText.includes(canary), `sensitive access log content: ${canary}`);
    assert.ok(!runtimeLogs.includes(canary), `sensitive runtime log content: ${canary}`);
  }
  for (const entry of logs) {
    assert.equal(entry.request.headers, undefined);
    assert.equal(entry.request.uri, undefined);
    assert.equal(entry.resp_headers, undefined);
  }
  for (const app of apps) {
    for (const status of [401, 502]) {
      const attempts = logs.filter((entry) => entry.surface === `${app.id}-mcp` && entry.status === status);
      assert.ok(attempts.length >= (status === 502 ? 2 : 1));
      for (const entry of attempts) {
        assert.equal(entry.assurance_mode, mode);
        assert.equal(entry.assurance_required, undefined);
        assert.equal(entry.assurance_decision, undefined);
      }
    }
    const mismatch = logs.find((entry) => entry.surface === `${app.id}-mcp` && entry.request.client_ip === outsider && entry.assurance_decision);
    assert.ok(mismatch);
    assert.equal(mismatch.assurance_mode, mode);
    assert.equal(mismatch.assurance_required, 'openai-network');
    assert.equal(mismatch.assurance_decision, mode === 'observe' ? 'would-deny' : 'deny');
    assert.equal(mismatch.status, mode === 'observe' ? 200 : 403);
    assert.ok(logs.some((entry) => entry.surface === `${app.id}-mcp` && entry.assurance_required === 'openai-network'
      && entry.request.client_ip === '100.31.168.162' && !entry.assurance_decision && entry.status === 200));
    assert.ok(logs.some((entry) => entry.surface === `${app.id}-mcp` && entry.request.client_ip === outsider
      && !entry.assurance_required && !entry.assurance_decision && entry.status === 200));
  }
});
