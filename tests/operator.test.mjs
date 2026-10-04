import { strict as assert } from 'node:assert';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { CHATGPT_CLIENT } from '../auth/chatgpt.mjs';
import { openStore } from '../auth/store.mjs';
import { backupOAuth, hashPassword, restoreOAuth, rotateBasicAuth, revokeAllOAuth } from '../scripts/operator';

const hash = `$2b$12$${'A'.repeat(53)}`;

test('Caddy hashes interactively with inherited TTY and only the hash is captured', () => {
  let captured;
  const result = hashPassword((binary, args, options) => {
    captured = { binary, args, options };
    return { stdout: `prompt text\n${hash}\n` };
  });
  assert.equal(result, hash);
  assert.deepEqual(captured.args, ['hash-password', '--algorithm', 'bcrypt']);
  assert.deepEqual(captured.options.stdio, ['inherit', 'pipe', 'inherit']);
  assert.ok(!captured.args.includes('--plaintext'));
});

test('Basic Auth rotation validates, atomically updates, reloads, and restores on reload failure', (t) => {
  const directory = mkdtempSync(`${tmpdir()}/host-operator-basic-`);
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const envFile = join(directory, 'env.caddy');
  const original = "CODEX_CONNECT_BASIC_AUTH_USER=before\nCODEX_CONNECT_BASIC_AUTH_HASH='$2b$12$old'\n";
  writeFileSync(envFile, original, { mode: 0o600 });
  const events = [];
  let expectedUsername = 'operator-2';
  const isActive = () => true;
  const run = (binary, args, options = {}) => {
    events.push({ binary, args, options });
    if (args[0] === 'validate') {
      assert.equal(options.env.CODEX_CONNECT_BASIC_AUTH_USER, expectedUsername);
      assert.equal(options.env.CODEX_CONNECT_BASIC_AUTH_HASH, hash);
      return { status: 0 };
    }
    return { status: 0 };
  };

  rotateBasicAuth({ envFile, username: 'operator-2', hash, isActive, run });
  assert.match(readFileSync(envFile, 'utf8'), /CODEX_CONNECT_BASIC_AUTH_USER=operator-2/);
  assert.match(readFileSync(envFile, 'utf8'), new RegExp(hash.replaceAll('$', '\\$')));
  assert.equal(statSync(envFile).mode & 0o777, 0o600);
  assert.deepEqual(events.filter(({ binary }) => binary === 'systemctl').map(({ args }) => args), [
    ['--user', 'reload', 'host-ingress.service'],
  ]);

  writeFileSync(envFile, original, { mode: 0o600 });
  expectedUsername = 'operator-3';
  let reloads = 0;
  const failFirstReload = (binary, args, options = {}) => {
    if (binary === 'systemctl' && args[1] === 'reload' && ++reloads === 1) throw new Error('injected reload failure');
    return run(binary, args, options);
  };
  assert.throws(() => rotateBasicAuth({ envFile, username: 'operator-3', hash, isActive, run: failFirstReload }), /previous env\.caddy was restored/);
  assert.equal(readFileSync(envFile, 'utf8'), original);
  assert.equal(reloads, 2, 'rollback reloads the restored environment');

  writeFileSync(envFile, original, { mode: 0o600 });
  expectedUsername = 'operator-4';
  let rollbackWriteBlocked = false;
  const failReloadAndRollbackWrite = (binary, args, options = {}) => {
    if (binary === 'systemctl' && args[1] === 'reload') {
      chmodSync(directory, 0o500);
      rollbackWriteBlocked = true;
      throw new Error('injected reload failure');
    }
    return run(binary, args, options);
  };
  try {
    assert.throws(
      () => rotateBasicAuth({ envFile, username: 'operator-4', hash, isActive, run: failReloadAndRollbackWrite }),
      /restoring previous env\.caddy also failed.*may still contain the new credentials/,
    );
  } finally {
    if (rollbackWriteBlocked) chmodSync(directory, 0o700);
  }
  assert.match(readFileSync(envFile, 'utf8'), /CODEX_CONNECT_BASIC_AUTH_USER=operator-4/);
});

test('OAuth revoke-all clears grant-owned and pending browser state but preserves replay state', async (t) => {
  const directory = mkdtempSync(`${tmpdir()}/host-operator-revoke-`);
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const database = join(directory, 'oauth.sqlite');
  const secretsFile = join(directory, 'oauth-secrets.json');
  const signingIdentity = '{"accountId":"single-operator","jwks":{"keys":["private-key-material"]}}\n';
  writeFileSync(secretsFile, signingIdentity, { mode: 0o600 });
  const store = openStore(database);
  const add = async (model, id, payload, ttl = 3600) => new store.Adapter(model).upsert(id, payload, ttl);
  await add('Grant', 'grant-1', { clientId: 'single-operator', accountId: 'operator' });
  await add('AccessToken', 'access-1', { clientId: 'single-operator', grantId: 'grant-1' }, 600);
  await add('RefreshToken', 'refresh-1', { clientId: 'single-operator', grantId: 'grant-1' }, 600);
  await add('FutureGrantOwnedArtifact', 'future-1', { grantId: 'grant-1' }, 600);
  await add('Interaction', 'pending-interaction', { uid: 'pending' }, 600);
  await add('Session', 'operator-session', { uid: 'session' }, 600);
  await add('ReplayDetection', 'assertion-replay', { jti: 'already-seen' }, 600);
  await add('UnrelatedArtifact', 'unrelated', { value: true }, 600);
  store.close();
  chmodSync(database, 0o600);

  let running = true;
  const calls = [];
  const run = (_binary, args) => {
    calls.push(args);
    if (args[1] === 'stop') running = false;
    if (args[1] === 'restart') running = true;
    return { status: 0 };
  };
  const grants = await revokeAllOAuth({ databaseFiles: [database], run, isActive: () => running, waitUntilReady: async () => true });
  assert.equal(grants, 1);
  assert.deepEqual(calls.map((args) => args.slice(1)), [
    ['stop', 'host-oauth.service'], ['restart', 'host-oauth.service'],
  ]);

  const after = openStore(database);
  t.after(() => after.close());
  for (const [model, id] of [
    ['Grant', 'grant-1'], ['AccessToken', 'access-1'], ['RefreshToken', 'refresh-1'],
    ['FutureGrantOwnedArtifact', 'future-1'], ['Interaction', 'pending-interaction'], ['Session', 'operator-session'],
  ]) assert.equal(await new after.Adapter(model).find(id), undefined, `${model} should be revoked`);
  assert.ok(await new after.Adapter('ReplayDetection').find('assertion-replay'));
  assert.ok(await new after.Adapter('UnrelatedArtifact').find('unrelated'));
  assert.equal(readFileSync(secretsFile, 'utf8'), signingIdentity, 'revoke-all keeps OAuth signing identity intact');
});

test('OAuth revoke-all recovers when stop fails after making the service inactive', async (t) => {
  const directory = mkdtempSync(`${tmpdir()}/host-operator-stop-recovery-`);
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const database = join(directory, 'oauth.sqlite');
  const store = openStore(database);
  await new store.Adapter('Grant').upsert('grant-stays', { clientId: 'single-operator', accountId: 'operator' }, 3600);
  store.close();
  chmodSync(database, 0o600);

  let running = true;
  const calls = [];
  const run = (_binary, args) => {
    calls.push(args);
    if (args[1] === 'stop') {
      running = false;
      throw new Error('injected stop timeout');
    }
    if (args[1] === 'restart') running = true;
    return { status: 0 };
  };
  await assert.rejects(
    revokeAllOAuth({ databaseFiles: [database], run, isActive: () => running, waitUntilReady: async () => true }),
    /stop failed after the service became inactive.*no authorization state was changed and host-oauth recovered/,
  );
  assert.equal(running, true);
  assert.deepEqual(calls.map((args) => args.slice(1)), [
    ['stop', 'host-oauth.service'], ['restart', 'host-oauth.service'],
  ]);
  const after = openStore(database);
  t.after(() => after.close());
  assert.ok(await new after.Adapter('Grant').find('grant-stays'), 'failed stop must not revoke authorization state');
});

test('OAuth backup and restore keep a private, integrity-checked identity/database set', async (t) => {
  const directory = mkdtempSync(`${tmpdir()}/host-operator-backup-`);
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const state = join(directory, 'state');
  mkdirSync(state, { recursive: true });
  const secrets = join(directory, 'oauth-secrets.json');
  const databaseFile = join(state, 'oauth.sqlite');
  const backup = join(directory, 'backup');
  const signingIdentity = JSON.stringify({ accountId: 'operator', jwks: { keys: [{ kty: 'oct', k: 'private' }] } });
  writeFileSync(secrets, signingIdentity, { mode: 0o600 });
  const initial = openStore(databaseFile);
  await new initial.Adapter('Grant').upsert('grant-saved', { clientId: 'chatgpt' }, 3600);
  initial.close(); chmodSync(databaseFile, 0o600);

  let running = true;
  const calls = [];
  let failRestoredStartup = false;
  const run = (_binary, args) => {
    calls.push(args);
    if (args[1] === 'stop') running = false;
    if (args[1] === 'restart') {
      running = true;
      if (failRestoredStartup && calls.filter((call) => call[1] === 'restart').length === 3) {
        writeFileSync(`${databaseFile}-wal`, 'stale WAL');
        writeFileSync(`${databaseFile}-shm`, 'stale SHM');
      }
    }
    return { status: 0 };
  };
  const lifecycle = { run, isActive: () => running, waitUntilReady: async () => true };
  await backupOAuth({ destination: backup, secrets, databaseFiles: [databaseFile], ...lifecycle });
  assert.deepEqual(calls.map((args) => args.slice(1)), [['stop', 'host-oauth.service'], ['restart', 'host-oauth.service']]);
  assert.equal(statSync(backup).mode & 0o777, 0o700);
  assert.equal(statSync(join(backup, 'oauth-secrets.json')).mode & 0o777, 0o600);
  assert.equal(statSync(join(backup, 'oauth.sqlite')).mode & 0o777, 0o600);
  assert.equal(readFileSync(join(backup, 'oauth-secrets.json'), 'utf8'), signingIdentity);

  const changed = openStore(databaseFile);
  await new changed.Adapter('Grant').upsert('grant-current', { clientId: 'chatgpt' }, 3600);
  changed.close(); chmodSync(databaseFile, 0o600);
  await restoreOAuth({ source: backup, secrets, databaseFiles: [databaseFile], ...lifecycle });
  assert.equal(readFileSync(secrets, 'utf8'), signingIdentity);
  const restored = openStore(databaseFile);
  t.after(() => restored.close());
  assert.ok(await new restored.Adapter('Grant').find('grant-saved'));
  assert.equal(await new restored.Adapter('Grant').find('grant-current'), undefined);

  const priorIdentity = JSON.stringify({ accountId: 'before-restore', jwks: { keys: [{ kty: 'oct', k: 'prior' }] } });
  writeFileSync(secrets, priorIdentity, { mode: 0o600 });
  const priorStore = openStore(databaseFile);
  await new priorStore.Adapter('Grant').upsert('grant-before-failed-restore', { clientId: 'chatgpt' }, 3600);
  priorStore.close(); chmodSync(databaseFile, 0o600);
  failRestoredStartup = true;
  let healthChecks = 0;
  const beforeRestoreCalls = calls.length;
  await assert.rejects(
    restoreOAuth({ source: backup, secrets, databaseFiles: [databaseFile], run, isActive: () => running,
      waitUntilReady: async () => ++healthChecks > 1 }),
    /OAuth restore failed; prior identity\/database pair was restored and host-oauth is healthy.*restored OAuth service failed health verification/,
  );
  failRestoredStartup = false;
  assert.equal(readFileSync(secrets, 'utf8'), priorIdentity);
  if (existsSync(`${databaseFile}-wal`)) assert.notEqual(readFileSync(`${databaseFile}-wal`, 'utf8'), 'stale WAL');
  if (existsSync(`${databaseFile}-shm`)) assert.notEqual(readFileSync(`${databaseFile}-shm`, 'utf8'), 'stale SHM');
  const recovered = openStore(databaseFile);
  t.after(() => recovered.close());
  assert.ok(await new recovered.Adapter('Grant').find('grant-before-failed-restore'));
  assert.ok(await new recovered.Adapter('Grant').find('grant-saved'), 'prior state keeps grants that existed before the failed restore');
  assert.deepEqual(calls.slice(beforeRestoreCalls).map((args) => args.slice(1)), [
    ['stop', 'host-oauth.service'], ['restart', 'host-oauth.service'],
    ['stop', 'host-oauth.service'], ['restart', 'host-oauth.service'],
  ]);
  let recoveryFailure;
  try {
    await restoreOAuth({ source: backup, secrets, databaseFiles: [databaseFile], run, isActive: () => running,
      waitUntilReady: async () => false });
  } catch (error) { recoveryFailure = error; }
  assert.match(recoveryFailure?.message ?? '', /OAUTH RESTORE RECOVERY FAILED: restore failed .*prior state recovery also failed/);
  const evidence = recoveryFailure.message.match(/staged evidence at (.+) and (.+)$/);
  assert.ok(evidence);
  assert.equal(existsSync(evidence[1]), true);
  assert.equal(existsSync(evidence[2]), true);
  assert.equal(existsSync(join(evidence[1], 'prior')), true);
  assert.equal(existsSync(join(evidence[2], 'prior')), true);
  await assert.rejects(backupOAuth({ destination: backup, secrets, databaseFiles: [databaseFile], ...lifecycle }), /already exists/);
});

test('OAuth restore rejects non-current ChatGPT authorization state before stopping the service', async (t) => {
  const directory = mkdtempSync(`${tmpdir()}/host-operator-current-oauth-`);
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const source = join(directory, 'backup');
  const secrets = join(directory, 'oauth-secrets.json');
  const databaseFile = join(directory, 'oauth.sqlite');
  mkdirSync(source, { mode: 0o700 });
  const identity = JSON.stringify({ accountId: 'operator', jwks: { keys: [{ kty: 'oct', k: 'fixture' }] } });
  writeFileSync(secrets, identity, { mode: 0o600 });
  writeFileSync(join(source, 'oauth-secrets.json'), identity, { mode: 0o600 });

  for (const file of [databaseFile, join(source, 'oauth.sqlite')]) {
    const store = openStore(file);
    await new store.Adapter('Grant').upsert('grant', { accountId: 'operator', clientId: CHATGPT_CLIENT }, 3600);
    store.close();
    chmodSync(file, 0o600);
  }
  const backupDb = new DatabaseSync(join(source, 'oauth.sqlite'));
  const expiry = Math.floor(Date.now() / 1000) + 3600;
  backupDb.prepare(`
    UPDATE artifacts
       SET expires = ?, payload = json_set(payload, '$.exp', ?)
     WHERE model = 'Grant' AND id = 'grant'
  `).run(expiry, expiry);
  backupDb.close();

  let running = true;
  let stopCalls = 0;
  const run = (_binary, args) => {
    if (args[1] === 'stop') { stopCalls++; running = false; }
    if (args[1] === 'restart') running = true;
    return { status: 0 };
  };
  const lifecycle = { run, isActive: () => running, waitUntilReady: async () => true };
  await assert.rejects(
    restoreOAuth({ source, secrets, databaseFiles: [databaseFile], ...lifecycle }),
    /non-current ChatGPT Grant authorization state/,
  );
  assert.equal(stopCalls, 0, 'invalid backup must be rejected before service interruption');

  const currentBackup = new DatabaseSync(join(source, 'oauth.sqlite'));
  currentBackup.prepare(`
    UPDATE artifacts
       SET expires = NULL, payload = json_remove(payload, '$.exp')
     WHERE model = 'Grant' AND id = 'grant'
  `).run();
  currentBackup.close();
  const staleLive = new DatabaseSync(databaseFile);
  staleLive.prepare(`
    UPDATE artifacts
       SET expires = ?, payload = json_set(payload, '$.exp', ?)
     WHERE model = 'Grant' AND id = 'grant'
  `).run(expiry, expiry);
  staleLive.close();

  await restoreOAuth({ source, secrets, databaseFiles: [databaseFile], ...lifecycle });
  assert.equal(stopCalls, 1, 'current backup must be able to replace non-current live state');
  const restored = new DatabaseSync(databaseFile, { readOnly: true });
  const row = restored.prepare("SELECT expires, json_type(payload, '$.exp') AS payloadExpiry FROM artifacts WHERE model = 'Grant' AND id = 'grant'").get();
  restored.close();
  assert.equal(row.expires, null);
  assert.equal(row.payloadExpiry, null);
});

test('operator help and status use the script location rather than the caller working directory', (t) => {
  const operator = new URL('../scripts/operator', import.meta.url).pathname;
  const help = spawnSync(process.execPath, [operator, 'help'], { encoding: 'utf8' });
  assert.equal(help.status, 0);
  assert.match(help.stdout, /basic rotate USER/);
  assert.match(help.stdout, /oauth revoke-all/);

  const home = mkdtempSync(`${tmpdir()}/host-operator-status-`);
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const status = spawnSync(process.execPath, [operator, 'status'], {
    cwd: home, env: { ...process.env, HOME: home }, encoding: 'utf8',
  });
  assert.notEqual(status.status, 0);
  assert.match(status.stderr, /missing .*\.config\/host-ingress\/env\.oauth/);
  assert.doesNotMatch(status.stderr, /scripts\/status.*not found/);
});


test('operator maintenance snapshots, restores and revokes both isolated databases with one identity', async (t) => {
  const directory = mkdtempSync(`${tmpdir()}/host-operator-two-apps-`);
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const secrets = join(directory, 'oauth-secrets.json');
  const identity = JSON.stringify({ accountId: 'operator', jwks: { keys: [{ kty: 'oct', k: 'fixture' }] } });
  writeFileSync(secrets, identity, { mode: 0o600 });
  const databaseFiles = ['oauth.sqlite', 'opencode-connect-oauth.sqlite'].map((name) => join(directory, name));
  async function add(file, id) {
    const store = openStore(file);
    try { await new store.Adapter('Grant').upsert(id, { accountId: 'operator', clientId: 'fixture' }, 3600); }
    finally { store.close(); }
    chmodSync(file, 0o600);
  }
  for (const file of databaseFiles) await add(file, 'saved');
  let running = true;
  const run = (_binary, args) => {
    if (args[1] === 'stop') running = false;
    if (args[1] === 'restart') running = true;
    return { status: 0 };
  };
  const options = { secrets, databaseFiles, run, isActive: () => running, waitUntilReady: async () => true };
  const destination = join(directory, 'backup');
  await backupOAuth({ destination, ...options });
  for (const file of databaseFiles) {
    assert.equal(statSync(join(destination, file.split('/').at(-1))).mode & 0o777, 0o600);
    await add(file, 'new');
  }
  let checks = 0;
  await assert.rejects(restoreOAuth({ source: destination, ...options, waitUntilReady: async () => ++checks > 1 }),
    /prior identity\/database pair was restored and host-oauth is healthy/);
  for (const file of databaseFiles) {
    const store = openStore(file);
    try { assert.ok(await new store.Adapter('Grant').find('new'), 'rollback must recover both app databases'); }
    finally { store.close(); }
  }
  await restoreOAuth({ source: destination, ...options });
  for (const file of databaseFiles) {
    const store = openStore(file);
    try {
      assert.ok(await new store.Adapter('Grant').find('saved'));
      assert.equal(await new store.Adapter('Grant').find('new'), undefined);
    } finally { store.close(); }
  }
  assert.equal(await revokeAllOAuth(options), 2);
  for (const file of databaseFiles) {
    const store = openStore(file);
    try { assert.equal(await new store.Adapter('Grant').find('saved'), undefined); }
    finally { store.close(); }
  }
  assert.equal(readFileSync(secrets, 'utf8'), identity);
});
