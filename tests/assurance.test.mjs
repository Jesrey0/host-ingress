import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { spawnSync } from 'node:child_process';
import { cidr, parseSource, snapshotText, loadSnapshot, validateSnapshot, loadAssurance, validateAssurance,
  refreshSnapshot, renderNetwork, assertFresh, assuranceStatus, MAX_SOURCE_AGE_DAYS, OPENAI_SOURCE } from '../transport/assurance.mjs';
import { loadApps } from '../lib/apps.mjs';
import { renderApps, renderRoutes } from '../lib/routes.mjs';
import { CHATGPT_CLIENT } from '../auth/chatgpt.mjs';
import { writeFreshSnapshot } from './network-fixture.mjs';

const creationTime = '2026-09-22T18:18:05.915327';
const now = Date.parse('2026-10-03T00:00:00Z');
const source = (time = creationTime) => ({ creationTime: time,
  prefixes: [{ ipv6Prefix: '2606:4700:0000::/32' }, { ipv4Prefix: '104.192.219.204/30' }, { ipv4Prefix: '100.31.168.162/32' }] });
const snapshot = () => parseSource(source(), now);

test('strict CIDRs support the full IPv4/IPv6 prefix range and canonical IPv6', () => {
  for (const [input, expected] of [['0.0.0.0/0', '0.0.0.0/0'], ['128.0.0.0/1', '128.0.0.0/1'],
    ['::/0', '::/0'], ['2000::/3', '2000::/3'], ['2606:4700:0000::/32', '2606:4700::/32'],
    ['2606:4700::1234/128', '2606:4700::1234/128'], ['::ffff:192.0.2.0/120', '::ffff:c000:200/120']]) {
    assert.equal(cidr(input).text, expected);
  }
  for (const value of [null, 1, '', '1.2.3.4', '01.2.3.4/32', '999.1.1.1/32', '1.2.3.4/33', '1.2.3.4/24',
    '1.2.3.4/032', '1.2.3.4/-1', '1.2.3.4/32\n', '2606:4700::/129', '2606:4700::1/32', '::1%eth0/128']) {
    assert.throws(() => cidr(value), undefined, String(value));
  }
});

test('official schema, family, duplicate and timestamp errors are rejected', () => {
  for (const document of [null, [], {}, { ...source(), extra: true }, { ...source(), prefixes: {} },
    { ...source(), prefixes: [] }, { ...source(), prefixes: [{ ipv4Prefix: '2606:4700::/32' }] },
    { ...source(), prefixes: [{ ipv6Prefix: '1.2.3.4/32' }] },
    { ...source(), prefixes: [{ ipv4Prefix: '1.2.3.4/32', extra: true }] },
    { ...source(), prefixes: ['1.2.3.4/32'] }, { ...source(), prefixes: [{ cidr: '1.2.3.4/32' }] },
    { ...source(), prefixes: [{ ipv6Prefix: '2606:4700::/32' }, { ipv6Prefix: '2606:4700:0::/32' }] }]) {
    assert.throws(() => parseSource(document, now));
  }
  for (const time of ['garbage', '2026-02-30T00:00:00', '2026-09-22T25:00:00', '2026-09-22T18:18:05+08:00',
    '2026-09-22T18:18:05.1234567', '2026-09-01T00:00:00', '2026-10-04T00:00:00']) {
    assert.throws(() => parseSource(source(time), now));
  }
});

test('canonical snapshot sorting and offline Caddy rendering are deterministic', () => {
  const a = snapshot();
  const reversed = source(); reversed.prefixes.reverse();
  assert.equal(snapshotText(a), snapshotText(parseSource(reversed, now)));
  assert.equal(a.creationTime, `${creationTime}Z`);
  assert.deepEqual(a.prefixes, ['100.31.168.162/32', '104.192.219.204/30', '2606:4700::/32']);
  assert.throws(() => validateSnapshot({ ...a, source: 'https://other.example' }));
  assert.throws(() => validateSnapshot({ ...a, prefixes: [...a.prefixes].reverse() }), /canonical/);
  assert.throws(() => validateSnapshot({ ...a, creationTime }), /canonical/);
  assert.equal(renderNetwork(a), renderNetwork(parseSource(reversed, now)));
  assert.match(renderNetwork(a), /client_ip 100\.31\.168\.162\/32 104\.192\.219\.204\/30 2606:4700::\/32/);
  const apps = loadApps();
  const rendered = renderApps(apps, undefined, { mode: 'enforce' });
  assert.equal(rendered, renderApps(apps, undefined, { mode: 'enforce' }));
  for (const app of apps) {
    assert.ok(renderRoutes(app).includes(`header X-Host-Ingress-Client-Id ${CHATGPT_CLIENT}`));
    assert.ok(rendered.includes(`@${app.id}_network_mismatch`));
  }
  assert.deepEqual(loadAssurance(), { mode: 'enforce' });
  for (const policy of [{}, { mode: 'on' }, { mode: 'observe', openaiNetworkResources: [] }]) assert.throws(() => validateAssurance(policy));
});

test('snapshot age is visible and freshness has an explicit 30-day boundary', () => {
  const a = snapshot();
  const boundary = Date.parse(a.creationTime) + MAX_SOURCE_AGE_DAYS * 86400000;
  assertFresh(a, boundary);
  assert.throws(() => assertFresh(a, boundary + 1), /stale/);
  assert.match(assuranceStatus({ mode: 'observe' }, a, boundary + 86400000), /age=31\.0 days; .*stale/);
  assert.throws(() => assertFresh(a, Date.parse(a.creationTime) - 300001), /future/);
});

test('explicit refresh atomically canonicalizes data and preserves last-known-good on every input failure', async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'host-network-refresh-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, 'snapshot.json');
  const bytes = snapshotText(snapshot());
  writeFileSync(path, bytes);
  const response = (document) => async (url, options) => {
    assert.equal(url, OPENAI_SOURCE); assert.equal(options.redirect, 'error'); assert.ok(options.signal);
    return new Response(JSON.stringify(document));
  };
  const cases = [async () => { throw new Error('fetch failed'); }, async () => new Response('error', { status: 503 }),
    async () => new Response('{'), async () => new Response(new Uint8Array([0xff])),
    async () => new Response('x'.repeat(1024 * 1024 + 1)),
    response({ ...source(), prefixes: null }), response(source('2026-09-01T00:00:00')),
    response(source('2026-10-04T00:00:00')), response(source('2026-09-22T18:18:05.915326')),
    response({ ...source(), prefixes: [{ ipv4Prefix: '1.2.3.4/32' }] }), response({ ...source(), unknown: true })];
  for (const fetcher of cases) {
    await assert.rejects(refreshSnapshot({ path, fetcher, now }));
    assert.equal(readFileSync(path, 'utf8'), bytes);
    assert.deepEqual(readdirSync(directory), ['snapshot.json']);
  }
  await refreshSnapshot({ path, fetcher: response(source()), now });
  assert.equal(readFileSync(path, 'utf8'), bytes);
  const next = source('2026-09-22T18:18:05.915328'); next.prefixes.reverse();
  await refreshSnapshot({ path, fetcher: response(next), now });
  assert.equal(readFileSync(path, 'utf8'), snapshotText(parseSource(next, now)));
  assert.deepEqual(loadSnapshot(path), parseSource(next, now));
  assert.deepEqual(readdirSync(directory), ['snapshot.json']);
  // Relative filesystem paths also resolve beside the target, not beside a URL host.
  const relativePath = (path) => relative(process.cwd(), path);
  const relativeTarget = join(directory, 'first.json');
  await refreshSnapshot({ path: relativePath(relativeTarget), fetcher: response(source()), now });
  assert.equal(readFileSync(relativeTarget, 'utf8'), bytes);
  writeFileSync(path, `${bytes}\n`);
  await assert.rejects(refreshSnapshot({ path, fetcher: response(next), now }), /canonical/);
  assert.equal(readFileSync(path, 'utf8'), `${bytes}\n`);
  writeFileSync(path, '{}');
  await assert.rejects(refreshSnapshot({ path, fetcher: response(next), now }), /schema/);
  assert.equal(readFileSync(path, 'utf8'), '{}');
});

test('operator network status works outside the repository and never changes mode or snapshot', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'host-network-operator-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  for (const path of ['scripts', 'auth', 'config', 'transport']) {
    cpSync(new URL(`../${path}`, import.meta.url), join(directory, path), { recursive: true });
  }
  symlinkSync(new URL('../node_modules', import.meta.url).pathname, join(directory, 'node_modules'), 'dir');
  writeFreshSnapshot(directory);
  const config = readFileSync(join(directory, 'config/transport-assurance.json'), 'utf8');
  const network = readFileSync(join(directory, 'transport/openai-network.json'), 'utf8');
  const result = spawnSync(process.execPath, [join(directory, 'scripts/operator'), 'network', 'status'],
    { cwd: tmpdir(), encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /mode=enforce/);
  assert.match(result.stdout, /count=\d+; age=/);
  assert.equal(readFileSync(join(directory, 'config/transport-assurance.json'), 'utf8'), config);
  assert.equal(readFileSync(join(directory, 'transport/openai-network.json'), 'utf8'), network);
});


test('release renderer and status are offline, deterministic and reject stale or malformed snapshots', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'host-network-source-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  for (const path of ['lib', 'config', 'transport', 'Caddyfile']) {
    cpSync(new URL(`../${path}`, import.meta.url), join(directory, path), { recursive: true });
  }
  mkdirSync(join(directory, 'scripts'));
  mkdirSync(join(directory, 'auth'));
  cpSync(new URL('../auth/chatgpt.mjs', import.meta.url), join(directory, 'auth/chatgpt.mjs'));
  for (const path of ['render-caddy.mjs', 'network.mjs']) cpSync(new URL(`../scripts/${path}`, import.meta.url), join(directory, 'scripts', path));
  writeFreshSnapshot(directory);
  // A fetch trap demonstrates that source rendering/status need only bundled inputs.
  const trap = join(directory, 'no-fetch.mjs');
  writeFileSync(trap, "globalThis.fetch = () => { throw new Error('unexpected fetch'); };\n");
  const run = (script, args) => spawnSync(process.execPath, ['--import', trap, join(directory, 'scripts', script), ...args], { encoding: 'utf8' });
  for (const target of ['a', 'b']) {
    const result = run('render-caddy.mjs', [join(directory, target)]);
    assert.equal(result.status, 0, result.stderr);
  }
  for (const file of ['Caddyfile', 'apps.caddy', 'assurance.caddy']) {
    assert.equal(readFileSync(join(directory, 'a', file), 'utf8'), readFileSync(join(directory, 'b', file), 'utf8'));
  }
  assert.equal(run('network.mjs', ['status']).status, 0);
  const snapshotPath = join(directory, 'transport/openai-network.json');
  const bytes = readFileSync(snapshotPath, 'utf8');
  writeFileSync(join(directory, 'release-manifest.json'), '{}');
  const refresh = run('network.mjs', ['refresh']);
  assert.notEqual(refresh.status, 0);
  assert.match(refresh.stderr, /immutable deployed release/);
  assert.doesNotMatch(refresh.stderr, /unexpected fetch/);
  assert.equal(readFileSync(snapshotPath, 'utf8'), bytes);
  assert.equal(run('network.mjs', ['status']).status, 0, 'deployed status remains available');
  const stale = { ...snapshot(), creationTime: '2000-01-01T00:00:00.000000Z' };
  writeFileSync(snapshotPath, snapshotText(stale));
  const status = run('network.mjs', ['status']);
  assert.notEqual(status.status, 0);
  assert.match(status.stdout, /age=.*stale/);
  const rendered = run('render-caddy.mjs', [join(directory, 'stale')]);
  assert.notEqual(rendered.status, 0);
  assert.match(rendered.stderr, /stale/);
  assert.equal(existsSync(join(directory, 'stale')), false);
  writeFileSync(snapshotPath, '{}');
  assert.notEqual(run('network.mjs', ['status']).status, 0);
  assert.notEqual(run('render-caddy.mjs', [join(directory, 'invalid')]).status, 0);
});
