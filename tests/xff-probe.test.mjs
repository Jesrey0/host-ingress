import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { appendFileSync, cpSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { checkXff } from '../scripts/check-xff.mjs';
import { writeFreshSnapshot } from './network-fixture.mjs';

const token = '0123456789abcdef0123456789abcdef';
const forged = '100.31.168.162';
const snapshot = { prefixes: [`${forged}/32`] };
const record = (client_ip = '203.0.113.99', extra = {}) => JSON.stringify({
  xff_probe: token, status: 404, request: { client_ip }, ...extra,
}) + '\n';

test('public XFF probe requires new correlated authoritative redacted evidence', async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'host-xff-probe-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const logPath = join(directory, 'access.log');
  const run = (append, status = 404) => checkXff('https://ingress.example', {
    snapshot, logPath, token, timeoutMs: 0,
    fetcher: async (url, options) => {
      assert.equal(url, `https://ingress.example/__host-ingress-xff-probe/${token}`);
      assert.deepEqual(options.headers, { 'X-Forwarded-For': forged });
      assert.equal(options.redirect, 'manual');
      assert.ok(options.signal);
      append();
      return new Response(null, { status });
    },
  });
  // Even an old, matching successful record cannot prove this invocation.
  writeFileSync(logPath, record());
  await assert.rejects(run(() => {}), /No newly appended correlated/);
  await assert.rejects(run(() => appendFileSync(logPath, record(forged))), /accepted forged/);
  await assert.rejects(run(() => appendFileSync(logPath, record(undefined, { request: {} }))), /lacks authoritative/);
  await assert.rejects(run(() => appendFileSync(logPath, record('203.0.113.99', { xff_probe: 'another-probe' }))), /No newly appended correlated/);
  await assert.rejects(run(() => appendFileSync(logPath, record('203.0.113.99', { status: 200 }))), /default deny/);
  await assert.rejects(run(() => {}, 200), /default deny/);
  for (const key of ['headers', 'uri']) {
    await assert.rejects(run(() => appendFileSync(logPath, record('203.0.113.99', {
      request: { client_ip: '203.0.113.99', [key]: 'private-canary' },
    }))), /redaction missing/);
  }
  await assert.rejects(run(() => appendFileSync(logPath, record('203.0.113.99', { resp_headers: {} }))), /redaction missing/);
  await run(() => appendFileSync(logPath, record()));
  await assert.rejects(run(() => {
    renameSync(logPath, join(directory, 'rotated.log'));
    writeFileSync(logPath, record());
  }), /rotated or truncated/);
});

test('XFF probe waits for a complete newly appended record', async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'host-xff-partial-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const logPath = join(directory, 'access.log');
  writeFileSync(logPath, '');
  const line = record();
  let timer;
  t.after(() => clearTimeout(timer));
  await checkXff('https://ingress.example', { snapshot, logPath, token,
    fetcher: async () => {
      appendFileSync(logPath, line.slice(0, 20));
      timer = setTimeout(() => appendFileSync(logPath, line.slice(20)), 30);
      return new Response(null, { status: 404 });
    },
  });
  assert.equal(readFileSync(logPath, 'utf8'), line);
});

test('gates-public CLI runs one public XFF probe for all apps, with no internet', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'host-xff-cli-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  for (const path of ['scripts', 'lib', 'config', 'auth/chatgpt.mjs', 'transport']) {
    cpSync(new URL(`../${path}`, import.meta.url), join(directory, path), { recursive: true });
  }
  writeFreshSnapshot(directory);
  const logDirectory = join(directory, '.local/state/host-ingress/logs');
  mkdirSync(logDirectory, { recursive: true });
  const logPath = join(logDirectory, 'access.log');
  writeFileSync(logPath, '');
  const trap = join(directory, 'fixture-fetch.mjs');
  writeFileSync(trap, `
    import { appendFileSync } from 'node:fs';
    globalThis.fetch = async (url, options) => {
      const parsed = new URL(url);
      if (parsed.origin !== 'https://ingress.example') throw new Error('unexpected origin');
      if (parsed.pathname.startsWith('/__host-ingress-xff-probe/')) {
        if (options.headers['X-Forwarded-For'] !== '${forged}') throw new Error('unexpected forged IP');
        appendFileSync(${JSON.stringify(logPath)}, JSON.stringify({
          xff_probe: parsed.pathname.split('/').pop(), status: 404,
          request: { client_ip: '203.0.113.99' },
        }) + '\\n');
        return new Response(null, { status: 404 });
      }
      if (['/codex-connect/mcp', '/opencode-connect/mcp'].includes(parsed.pathname)) return new Response(null, { status: 401 });
      throw new Error('unexpected request');
    };
  `);
  const result = spawnSync(process.execPath, ['--import', trap, join(directory, 'scripts/check-apps.mjs'), 'gates-public'], {
    env: { ...process.env, HOME: directory, PUBLIC_ORIGIN: 'https://ingress.example' }, encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.match(/public XFF integrity: ok/g)?.length, 1);
  assert.equal(readFileSync(logPath, 'utf8').trim().split('\n').length, 1);
  assert.match(result.stdout, /codex-connect public auth gate: ok/);
  assert.match(result.stdout, /opencode-connect public auth gate: ok/);
});
