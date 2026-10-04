import { strict as assert } from 'node:assert';
import { openSync, closeSync, fstatSync, statSync, readSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { isIP } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { loadSnapshot, assertFresh } from '../transport/assurance.mjs';

// Correlate a safe default-deny request without retaining headers or request URI.
// Pin the file and its initial length: old records cannot establish integrity.
export async function checkXff(origin, {
  logPath = join(homedir(), '.local/state/host-ingress/logs/access.log'),
  snapshot = assertFresh(loadSnapshot()), fetcher = fetch,
  token = randomBytes(16).toString('hex'), timeoutMs = 3000,
} = {}) {
  assert.match(token, /^[a-f0-9]{32}$/);
  const forged = snapshot.prefixes[0].split('/')[0];
  const fd = openSync(logPath, 'r');
  const initial = fstatSync(fd);
  let offset = initial.size;
  let pending = '';
  try {
    const response = await fetcher(`${origin}/__host-ingress-xff-probe/${token}`, {
      headers: { 'X-Forwarded-For': forged }, redirect: 'manual', signal: AbortSignal.timeout(8000),
    });
    await response.body?.cancel();
    assert.equal(response.status, 404, 'public XFF integrity probe must hit default deny');
    const deadline = Date.now() + timeoutMs;
    do {
      const current = statSync(logPath);
      assert.ok(current.ino === initial.ino && current.dev === initial.dev && current.size >= offset,
        'Caddy access log rotated or truncated during XFF probe; integrity unverified');
      const buffer = Buffer.alloc(current.size - offset);
      const length = readSync(fd, buffer, 0, buffer.length, offset);
      offset += length;
      pending += buffer.subarray(0, length).toString('utf8');
      const lines = pending.split('\n');
      pending = lines.pop();
      for (const line of lines) {
        const entry = JSON.parse(line);
        if (entry.xff_probe !== token) continue;
        assert.equal(entry.status, 404, 'correlated XFF probe must be default deny');
        assert.ok(isIP(entry.request?.client_ip), 'XFF probe lacks authoritative request.client_ip');
        assert.notEqual(entry.request.client_ip, forged, 'public edge accepted forged XFF as authoritative client_ip');
        assert.equal(entry.request.headers, undefined, 'Caddy header redaction missing');
        assert.equal(entry.request.uri, undefined, 'Caddy URI redaction missing');
        assert.equal(entry.resp_headers, undefined, 'Caddy response header redaction missing');
        console.log('public XFF integrity: ok');
        return;
      }
      if (Date.now() >= deadline) break;
      await delay(25);
    } while (true);
    throw new Error('No newly appended correlated Caddy XFF probe record; integrity unverified');
  } finally {
    closeSync(fd);
  }
}
