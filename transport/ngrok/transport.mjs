import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { spawn, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { publicOrigin } from '../../lib/origin.mjs';

const marker = 'ngrok-edge-v2';
const policy = fileURLToPath(new URL('./traffic-policy.yml', import.meta.url));
const guard = fileURLToPath(new URL('./assert-agent-config', import.meta.url));

export function ngrokArguments(origin, home = homedir()) {
  return ['http', '127.0.0.1:9000', '--url', origin, '--name', 'host-ingress', '--inspect=false',
    '--traffic-policy-file', `${home}/.config/host-ingress/runtime/current/transport/ngrok/traffic-policy.yml`, '--config', `${home}/.config/ngrok/ngrok.yml`, '--log', 'stdout', '--log-format', 'json'];
}

export function validateAgent() {
  execFileSync('bash', [guard], { stdio: 'inherit' });
  if (!readFileSync(policy, 'utf8').includes(`            x-host-ingress-policy: ${marker}\n`)) {
    throw new Error('ngrok policy marker is missing');
  }
}

export function tunnelIdentity(data, origin) {
  const tunnel = (data.tunnels ?? []).find((item) => item.name === 'host-ingress');
  if (tunnel?.public_url?.replace(/\/$/, '') !== origin || tunnel.config?.addr !== 'http://127.0.0.1:9000') {
    throw new Error('ngrok tunnel URL or loopback upstream mismatch');
  }
}

export function edgeHeaders(headers) {
  if (headers.get('x-host-ingress-policy') !== marker
      || headers.get('strict-transport-security') !== 'max-age=31536000') {
    throw new Error('ngrok edge policy marker or HSTS mismatch');
  }
}

async function status(origin) {
  const response = await fetch('http://127.0.0.1:4040/api/tunnels', { signal: AbortSignal.timeout(2000) });
  if (!response.ok) throw new Error('ngrok local API failed');
  tunnelIdentity(await response.json(), origin);
  const edge = await fetch(origin, { redirect: 'manual', signal: AbortSignal.timeout(5000) });
  edgeHeaders(edge.headers);
  await edge.body?.cancel();
  console.log(`ngrok: ${origin} → http://127.0.0.1:9000; tunnel identity, edge policy, HSTS verified`);
}

if (import.meta.main) {
  const command = process.argv[2];
  if (command === 'validate') validateAgent();
  else if (command === 'status') await status(publicOrigin());
  else if (command === 'run') {
    validateAgent();
    const child = spawn(`${homedir()}/.local/bin/ngrok`, ngrokArguments(publicOrigin()), { stdio: 'inherit' });
    for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => child.kill(signal));
    child.on('error', () => { console.error('ngrok launch failed'); process.exitCode = 1; });
    child.on('exit', (code, signal) => { process.exitCode = code ?? (signal === 'SIGTERM' ? 0 : 1); });
  } else throw new Error('usage: node transport/ngrok/transport.mjs <validate|status|run>');
}
