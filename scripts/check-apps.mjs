#!/usr/bin/env node
import { strict as assert } from 'node:assert';
import { loadApps } from '../lib/apps.mjs';
import { publicOrigin } from '../lib/origin.mjs';
import { checkOAuth } from './check-oauth.mjs';
import { checkXff } from './check-xff.mjs';

const local = 'http://127.0.0.1:9000';
export async function probe(name, url, status, expectedBody) {
  const response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(8000) });
  assert.equal(response.status, status, `${name}: ${url}`);
  if (expectedBody === undefined) await response.body?.cancel();
  else assert.equal(await response.text(), expectedBody, `${name}: ${url}`);
  console.log(`${name}: ok (${status})`);
}

export async function checkApps(mode, app, origin) {
  if (mode === 'backend') {
    await probe(`${app.id} backend`, `http://127.0.0.1:${app.backend.port}${app.backend.healthPath}`, 200);
    return;
  }
  const base = mode.includes('public') ? origin : local;
  if (!base) throw new Error('public origin required');
  const surface = base === local ? 'local' : 'public';
  if (mode === 'ingress') await probe('oauth backend', 'http://127.0.0.1:9001/healthz', 200);
  if (!mode.startsWith('gates-')) {
    await probe(`${surface} robots`, `${base}/robots.txt`, 200, 'User-agent: *\nDisallow: /');
    await probe(`${surface} default deny`, `${base}/`, 404);
  }
  await probe(`${app.id} ${surface} auth gate`, `${base}${app.resource.path}`, 401);
  if (!mode.startsWith('gates-')) await checkOAuth(base, origin, app);
}

if (import.meta.main) {
  const mode = process.argv[2];
  if (!['backend', 'ingress', 'public', 'gates-local', 'gates-public'].includes(mode)) throw new Error('invalid app check mode');
  const origin = mode === 'backend' ? undefined : publicOrigin();
  if (mode === 'public' || mode === 'gates-public') await checkXff(origin);
  for (const app of loadApps()) await checkApps(mode, app, origin);
}
