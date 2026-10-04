#!/usr/bin/env node
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';

process.umask(0o077);
const config = `${homedir()}/.config/host-ingress`;
const state = `${homedir()}/.local/state/host-ingress`;
const path = `${config}/oauth-secrets.json`;
// Existing SQLite state may still contain durable grants: never replace identity.
if (existsSync(path) || (existsSync(state) && readdirSync(state).some((name) => name.endsWith('.sqlite')))) {
  throw new Error('OAuth state already exists; initialization must not replace signing keys or account identity');
}
mkdirSync(config, { recursive: true, mode: 0o700 });
mkdirSync(state, { recursive: true, mode: 0o700 });
const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const key = { ...privateKey.export({ format: 'jwk' }), kid: randomUUID(), use: 'sig', alg: 'RS256' };
writeFileSync(path, JSON.stringify({ accountId: randomUUID(), cookieKeys: [randomBytes(32).toString('base64url')], jwks: { keys: [key] } }), { mode: 0o600, flag: 'wx' });
console.log('Initialized private OAuth signing keys and operator identity.');
