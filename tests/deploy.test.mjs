import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { writeFreshSnapshot } from './network-fixture.mjs';

// Exercise the real deployment transaction only inside a disposable fake host.
// Service, network, dependency-install and Git boundaries are stubbed; rendering,
// copying, digesting, release selection and rollback execute normally.
test('immutable app releases selectively restart owners and roll back a failed activation', (t) => {
  const directory = mkdtempSync(`${tmpdir()}/host-deploy-test-`);
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const source = join(directory, 'source');
  const home = join(directory, 'home');
  const bin = join(home, '.local/bin');
  const config = join(home, '.config/host-ingress');
  const units = join(home, '.config/systemd/user');
  const log = join(directory, 'commands');
  for (const path of [source, bin, config, units]) mkdirSync(path, { recursive: true });
  const repo = fileURLToPath(new URL('../', import.meta.url));
  for (const path of ['auth', 'config', 'deploy', 'lib', 'scripts', 'transport', 'Caddyfile', 'package.json', 'package-lock.json']) {
    cpSync(join(repo, path), join(source, path), { recursive: true });
  }
  writeFreshSnapshot(source);
  for (const file of ['env.ngrok', 'env.oauth']) writeFileSync(join(config, file), 'PUBLIC_ORIGIN=https://ingress.example\n', { mode: 0o600 });
  writeFileSync(join(config, 'env.caddy'), 'CODEX_CONNECT_BASIC_AUTH_USER=operator\nCODEX_CONNECT_BASIC_AUTH_HASH=hash\n', { mode: 0o600 });
  writeFileSync(join(config, 'oauth-secrets.json'), '{}', { mode: 0o600 });
  writeFileSync(join(units, 'dummy.service'), '# owned by the app\n');
  const script = (path, body) => { writeFileSync(path, `#!/usr/bin/env bash\nset -euo pipefail\n${body}\n`); chmodSync(path, 0o755); };
  for (const name of ['npm', 'systemd-analyze', 'ngrok', 'caddy', 'curl']) script(join(bin, name), 'exit 0');
  script(join(bin, 'git'), 'exit 128');
  script(join(bin, 'systemctl'), `printf "%s\\n" "$*" >> "$TEST_COMMAND_LOG"
if [[ "\${TEST_ROLLBACK_FAILURE:-0}" == 1 && "\${1:-}" == --user && "\${2:-}" == restart && "\${3:-}" == host-oauth.service && -f "$TEST_ACTIVATION_MARKER" ]]; then exit 9; fi
if [[ "\${TEST_SELECTOR_FAILURE:-0}" == 1 && "\${1:-}" == --user && "\${2:-}" == restart && "\${3:-}" == host-oauth.service && -f "$TEST_ACTIVATION_MARKER" ]]; then ln -sfn releases/selector-test-failure "$HOME/.config/host-ingress/runtime/current"; fi`);
  // Actual Node is used for manifest reads, route generation and other file work.
  const quotedNode = `'${process.execPath.replaceAll("'", "'\\''")}'`;
  script(join(bin, 'node'), `case "\${1:-}" in
  */transport/ngrok/transport.mjs|*/scripts/check-apps.mjs|*/lib/origin.mjs) exit 0 ;;
esac
exec ${quotedNode} "$@"`);
  script(join(source, 'scripts/check'), 'exit 0');
  script(join(source, 'scripts/status'), 'if [[ "${TEST_ACTIVATION_FAILURE:-0}" == 1 ]]; then touch "$TEST_ACTIVATION_MARKER"; exit 1; fi');
  const marker = join(directory, 'activation-failed');
  const run = (failure = false, rollbackFailure = false, selectorFailure = false) => {
    writeFileSync(log, '');
    rmSync(marker, { force: true });
    const result = spawnSync('bash', [join(source, 'scripts/deploy')], {
      env: { ...process.env, HOME: home, PATH: `${bin}:${process.env.PATH}`, TEST_COMMAND_LOG: log,
        TEST_ACTIVATION_FAILURE: failure ? '1' : '0', TEST_ROLLBACK_FAILURE: rollbackFailure ? '1' : '0',
        TEST_SELECTOR_FAILURE: selectorFailure ? '1' : '0',
        TEST_ACTIVATION_MARKER: marker }, encoding: 'utf8', timeout: 30000,
    });
    assert.equal(result.error, undefined);
    assert.equal(result.status, failure ? 1 : 0, `${result.stdout}\n${result.stderr}`);
    return { commands: readFileSync(log, 'utf8'), stderr: result.stderr };
  };
  const selected = () => readlinkSync(join(config, 'runtime/current'));
  const releaseFile = (path) => join(config, 'runtime/current', path);
  let { commands } = run();
  const first = selected();
  assert.match(commands, /restart host-oauth.service/);
  assert.match(commands, /restart host-ingress.service/);
  assert.match(commands, /restart host-ngrok.service/);
  assert.match(readFileSync(releaseFile('apps.caddy'), 'utf8'), /path \/codex-connect\/mcp/);
  assert.equal(JSON.parse(readFileSync(releaseFile('config/codex-connect.json'))).oauth.database, 'oauth.sqlite');
  assert.equal(JSON.parse(readFileSync(releaseFile('config/opencode-connect.json'))).oauth.database, 'opencode-connect-oauth.sqlite');
  assert.match(readFileSync(releaseFile('apps.caddy'), 'utf8'), /path \/opencode-connect\/mcp/);
  assert.match(readFileSync(releaseFile('lib/origin.mjs'), 'utf8'), /PUBLIC_ORIGIN/);
  const digest = () => spawnSync('python3', [join(source, 'scripts/release-digest'), releaseFile('')], { encoding: 'utf8' }).stdout.trim();
  assert.equal(digest(), JSON.parse(readFileSync(releaseFile('release-manifest.json'))).contentSha256);
  for (const path of ['config/transport-assurance.json', 'transport/assurance.mjs', 'transport/openai-network.json', 'scripts/network.mjs', 'assurance.caddy']) {
    const bytes = readFileSync(releaseFile(path), 'utf8');
    assert.ok(bytes.length);
    writeFileSync(releaseFile(path), `${bytes}\n`);
    assert.notEqual(digest(), JSON.parse(readFileSync(releaseFile('release-manifest.json'))).contentSha256, `${path} must be digested`);
    writeFileSync(releaseFile(path), bytes);
  }
  const modePath = join(source, 'config/transport-assurance.json');
  writeFileSync(modePath, JSON.stringify({ mode: 'observe' }));
  ({ commands } = run());
  assert.doesNotMatch(readFileSync(releaseFile('apps.caddy'), 'utf8'), /Transport assurance required/);
  assert.notEqual(selected(), first);
  assert.match(commands, /reload host-ingress.service/);
  assert.doesNotMatch(commands, /restart /);

  const profilePath = join(source, 'config/opencode-connect.json');
  const profile = JSON.parse(readFileSync(profilePath));
  profile.title = 'Changed OpenCode Connect consent';
  writeFileSync(profilePath, JSON.stringify(profile));
  ({ commands } = run());
  assert.match(commands, /restart host-oauth.service/);
  assert.match(commands, /reload host-ingress.service/);
  assert.doesNotMatch(commands, /restart host-(ngrok|ingress).service/);

  const publishedProfile = releaseFile('config/opencode-connect.json');
  const publishedText = readFileSync(publishedProfile, 'utf8');
  writeFileSync(publishedProfile, `${publishedText}\n`);
  assert.notEqual(digest(), JSON.parse(readFileSync(releaseFile('release-manifest.json'))).contentSha256, 'profile tampering must change release digest');
  writeFileSync(publishedProfile, publishedText);

  const policy = join(source, 'transport/ngrok/traffic-policy.yml');
  writeFileSync(policy, `${readFileSync(policy, 'utf8')}\n# Transport update\n`);
  ({ commands } = run());
  assert.match(commands, /restart host-ngrok.service/);
  assert.doesNotMatch(commands, /restart host-oauth.service/);

  const previous = selected();
  const previousDigest = digest();
  const unitPath = join(units, 'host-ngrok.service');
  const previousUnit = readFileSync(unitPath, 'utf8');
  writeFileSync(join(source, 'deploy/systemd/host-ngrok.service'), `${previousUnit}\n# Changed unit\n`);
  profile.title = 'Failed OpenCode Connect release';
  writeFileSync(profilePath, JSON.stringify(profile));
  const rollback = run(true);
  commands = rollback.commands;
  assert.match(rollback.stderr, /rollback verified: prior OAuth, Caddy, and tunnel services are healthy/);
  assert.equal(selected(), previous, 'failed verification must restore the previous selector');
  assert.equal(digest(), previousDigest, 'immutable prior release must remain unchanged');
  assert.equal(readFileSync(unitPath, 'utf8'), previousUnit, 'rollback restores the unit');
  assert.equal(readFileSync(join(units, 'dummy.service'), 'utf8'), '# owned by the app\n');
  assert.doesNotMatch(commands, /(?:restart|stop|enable) (?:dummy|codex-connect|opencode-connect).service/);
  assert.equal(commands.match(/restart host-oauth.service/g).length, 2, 'activation and rollback both restart changed auth');

  profile.title = 'Failed recovery release';
  writeFileSync(profilePath, JSON.stringify(profile));
  const recoveryFailure = run(true, true);
  assert.match(recoveryFailure.stderr, /ROLLBACK FAILED: prior release recovery or health verification failed/);
  assert.match(recoveryFailure.stderr, /original deployment failure remains the primary error/);
  assert.equal(selected(), previous, 'even failed health recovery leaves prior release selected');

  const selectorFailure = run(true, false, true);
  assert.match(selectorFailure.stderr, /ROLLBACK SELECTOR FAILED: runtime\/current does not point to the exact previous release/);
  assert.match(selectorFailure.stderr, /ROLLBACK FAILED: prior release recovery or health verification failed/);
});
