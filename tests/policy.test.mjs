import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const text = (relative) => readFileSync(new URL(`../${relative}`, import.meta.url), 'utf8');

test('edge policy adds a consent-specific ceiling alongside the coarse abuse limit', () => {
  const policy = text('transport/ngrok/traffic-policy.yml');
  assert.match(policy, /name: host-ingress-consent-per-ip/);
  assert.match(policy, /startsWith\('\/codex-connect\/oauth\/interaction\/'\)/);
  assert.match(policy, /startsWith\('\/opencode-connect\/oauth\/interaction\/'\)/);
  assert.match(policy, /capacity: 20/);
  assert.match(policy, /name: host-ingress-global-per-ip/);
  assert.match(policy, /capacity: 600/);
  assert.match(policy, /x-host-ingress-policy: ngrok-edge-v2/);
  assert.match(policy, /strict-transport-security: max-age=31536000/);
});

test('README documents consent edge limit and OAuth identity/database backup set', () => {
  const readme = text('README.md');
  assert.match(readme, /oauth backup DIR/);
  assert.match(readme, /oauth restore DIR/);
  assert.match(readme, /`opencode-connect-oauth\.sqlite`/);
  assert.match(readme, /20 requests per source IP per minute/);
  assert.match(readme, /`oauth-secrets\.json`, `oauth\.sqlite`, and/);
});

test('robots requests are answered locally and omitted from Caddy access logs', () => {
  const caddy = text('Caddyfile');
  assert.match(caddy, /@robots path \/robots\.txt/);
  assert.match(caddy, /log_skip @robots/);
  assert.match(caddy, /respond <<ROBOTS\n\s+User-agent: \*\n\s+Disallow: \/\n\s+ROBOTS 200/);
});

test('managed services hide home and expose only explicit host paths', () => {
  const ngrok = text('deploy/systemd/host-ngrok.service');
  assert.match(ngrok, /ProtectHome=tmpfs/);
  assert.match(ngrok, /BindReadOnlyPaths=%h\/\.local\/bin\/ngrok/);
  assert.match(ngrok, /BindReadOnlyPaths=%h\/\.config\/ngrok\/ngrok\.yml/);
  assert.match(ngrok, /BindReadOnlyPaths=%h\/\.config\/host-ingress\/runtime/);
  assert.match(text('transport/ngrok/transport.mjs'), /--inspect=false/);
  assert.doesNotMatch(ngrok, /--metadata/);
  assert.doesNotMatch(ngrok, /ProtectHome=read-only/);

  const caddy = text('deploy/systemd/host-ingress.service');
  assert.match(caddy, /ProtectHome=tmpfs/);
  assert.match(caddy, /BindReadOnlyPaths=%h\/\.local\/bin\/caddy/);
  assert.match(caddy, /BindPaths=%h\/\.local\/state\/host-ingress\/logs/);

  const oauth = text('deploy/systemd/host-oauth.service');
  assert.match(oauth, /ProtectHome=tmpfs/);
  assert.match(ngrok, /EnvironmentFile=.*env\.ngrok/);
  assert.doesNotMatch(ngrok, /BASIC_AUTH/);
  assert.match(caddy, /EnvironmentFile=.*env\.caddy/);
  assert.doesNotMatch(caddy, /EnvironmentFile=.*env\.oauth/);
  assert.match(text('scripts/status'), /caddy_env_file=.*env\.caddy/);
  assert.match(oauth, /EnvironmentFile=.*env\.oauth/);
  assert.doesNotMatch(oauth, /BASIC_AUTH/);
  assert.match(text('config/env.caddy.example'), /CODEX_CONNECT_BASIC_AUTH_USER/);
  assert.match(text('config/env.caddy.example'), /CODEX_CONNECT_BASIC_AUTH_HASH/);
  assert.doesNotMatch(text('config/env.ngrok.example'), /BASIC_AUTH/);
  assert.doesNotMatch(text('config/env.oauth.example'), /BASIC_AUTH/);
  assert.match(oauth, /BindReadOnlyPaths=%h\/\.config\/host-ingress\/oauth-secrets\.json/);
  assert.match(oauth, /BindPaths=%h\/\.local\/state\/host-ingress/);
});

test('deployment preserves live ingress when service definitions are unchanged', () => {
  const deploy = text('scripts/deploy');
  const sourceCheck = text('scripts/check');
  const status = text('scripts/status');
  for (const script of [deploy, sourceCheck, status]) {
    assert.match(script, /env\.ngrok and env\.oauth PUBLIC_ORIGIN values must match|env\.oauth and env\.ngrok PUBLIC_ORIGIN values must match/);
    assert.match(script, /^\s*unset PUBLIC_ORIGIN\s*$/m);
  }
  for (const script of [deploy, sourceCheck]) {
    assert.match(script, /unset CODEX_CONNECT_BASIC_AUTH_USER CODEX_CONNECT_BASIC_AUTH_HASH/);
  }
  assert.match(deploy, /systemctl --user reload host-ingress\.service/);
  assert.match(deploy, /host_ingress_unit_changed/);
  assert.match(deploy, /CHECK_PUBLIC=1 "\$\{root\}\/scripts\/check" ingress/);
  assert.match(deploy, /host_ngrok_unit_changed \|\| ngrok_runtime_changed/);
  assert.match(deploy, /host_oauth_unit_changed \|\| oauth_runtime_changed/);
  assert.match(deploy, /diff -qr "\$\{previous_release_dir\}\/auth" "\$\{release_dir\}\/auth"/);
});

test('ngrok config stays agent-only and host-ingress owns the tunnel definition', () => {
  const guard = text('transport/ngrok/assert-agent-config');
  const deploy = text('scripts/deploy');
  const sourceCheck = text('scripts/check');
  const status = text('scripts/status');
  const unit = text('deploy/systemd/host-ngrok.service');
  assert.match(guard, /\^\(tunnels\|endpoints\):/);
  assert.match(deploy, /transport\/ngrok\/transport.mjs" validate/);
  assert.match(sourceCheck, /transport\/ngrok\/transport.mjs" validate/);
  assert.match(status, /live_transport=.*transport\/ngrok\/transport\.mjs/);
  assert.match(status, /node "\$\{live_transport\}" validate/);
  assert.match(unit, /transport\/ngrok\/transport.mjs run/);
  assert.match(text('transport/ngrok/transport.mjs'), /'--name', 'host-ingress'/);
  assert.doesNotMatch(unit, /ngrok start/);
});

test('ngrok agent config guard rejects competing endpoint definitions and loose permissions', (t) => {
  const directory = mkdtempSync(`${tmpdir()}/host-ingress-ngrok-`);
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const guard = fileURLToPath(new URL('../transport/ngrok/assert-agent-config', import.meta.url));
  const run = (name, contents, mode = 0o600) => {
    const path = `${directory}/${name}`;
    writeFileSync(path, contents, { mode });
    chmodSync(path, mode);
    return spawnSync('bash', [guard, path], { encoding: 'utf8' });
  };

  assert.equal(run('agent.yml', 'version: "3"\nagent:\n  authtoken: redacted\n').status, 0);
  assert.notEqual(run('tunnel.yml', 'version: "3"\ntunnels:\n  rogue: {}\n').status, 0);
  assert.notEqual(run('endpoint.yml', 'version: "3"\nendpoints:\n  - name: rogue\n').status, 0);
  assert.notEqual(run('loose.yml', 'version: "3"\nagent: {}\n', 0o644).status, 0);
});


test('transport source, deployed status and release staging use the tracked offline snapshot', () => {
  assert.match(text('scripts/check'), /scripts\/render-caddy\.mjs/);
  assert.match(text('scripts/check'), /runtime_root.*scripts\/network\.mjs.*status/);
  assert.match(text('scripts/status'), /runtime_root.*scripts\/network\.mjs.*status/);
  assert.match(text('scripts/operator'), /networkCommand\(operation\)/);
  for (const file of ['transport/assurance.mjs', 'transport/openai-network.json', 'config/transport-assurance.json', 'scripts/network.mjs']) {
    assert.ok(text('scripts/deploy').includes(file));
  }
  assert.doesNotMatch(text('scripts/deploy'), /network\.mjs.*refresh|refreshSnapshot/);
  assert.doesNotMatch(text('scripts/render-caddy.mjs'), /fetch|refreshSnapshot/);
  assert.match(text('scripts/render-caddy.mjs'), /assertFresh\(loadSnapshot\(\)\)/);
  assert.match(text('Caddyfile'), /request>headers delete/);
  assert.match(text('Caddyfile'), /request>uri delete/);
  assert.match(text('Caddyfile'), /resp_headers delete/);
});
