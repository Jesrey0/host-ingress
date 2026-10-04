import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { test } from 'node:test';

test('the service entry point runs through the deployment symlink and enforces secret permissions', (t) => {
  const directory = mkdtempSync(`${tmpdir()}/host-oauth-startup-`);
  t.after(() => rmSync(directory, { recursive: true }));
  const config = `${directory}/.config/host-ingress`;
  mkdirSync(config, { recursive: true });
  // Fail before reading any key material, opening a database, or binding a port.
  writeFileSync(`${config}/oauth-secrets.json`, '{}');
  chmodSync(`${config}/oauth-secrets.json`, 0o644);
  const entrypoint = `${directory}/current.mjs`;
  symlinkSync(new URL('../auth/server.mjs', import.meta.url), entrypoint);
  const preloader = `${directory}/fixture-home.mjs`;
  writeFileSync(preloader, `
    import os from 'node:os';
    import { syncBuiltinESMExports } from 'node:module';
    os.homedir = () => ${JSON.stringify(directory)};
    syncBuiltinESMExports();
  `);
  const child = spawnSync(process.execPath, ['--import', preloader, entrypoint], {
    encoding: 'utf8', timeout: 10000,
  });
  assert.equal(child.error, undefined);
  assert.equal(child.status, 1, 'entry point must not silently exit successfully');
  assert.match(child.stderr, /OAuth secrets must have mode 0600/);
});


test('initialization refuses to replace identity when existing OAuth database state remains', (t) => {
  const directory = mkdtempSync(`${tmpdir()}/host-oauth-init-`);
  t.after(() => rmSync(directory, { recursive: true }));
  const state = `${directory}/.local/state/host-ingress`;
  mkdirSync(state, { recursive: true });
  writeFileSync(`${state}/oauth.sqlite`, 'existing state');
  const preloader = `${directory}/fixture-home.mjs`;
  writeFileSync(preloader, `
    import os from 'node:os';
    import { syncBuiltinESMExports } from 'node:module';
    os.homedir = () => ${JSON.stringify(directory)};
    syncBuiltinESMExports();
  `);
  const child = spawnSync(process.execPath, ['--import', preloader, new URL('../scripts/init-oauth.mjs', import.meta.url).pathname], {
    encoding: 'utf8', timeout: 10000,
  });
  assert.equal(child.error, undefined);
  assert.equal(child.status, 1);
  assert.match(child.stderr, /OAuth state already exists/);
});
