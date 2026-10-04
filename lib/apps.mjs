import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const codexConnectProfile = fileURLToPath(new URL('../config/codex-connect.json', import.meta.url));
export const opencodeConnectProfile = fileURLToPath(new URL('../config/opencode-connect.json', import.meta.url));
const matches = (pattern, value) => typeof value === 'string' && pattern.test(value);
const pathPattern = /^\/(?:[a-zA-Z0-9_-]+\/)*[a-zA-Z0-9_-]+$/;

export function validateApp(app) {
  const fail = (detail) => { throw new Error(`Invalid app ${app?.id ?? '(unnamed)'}: ${detail}`); };
  if (!['codex-connect', 'opencode-connect'].includes(app?.id)) fail('only the two declared Connect profiles are supported');
  if (!app.title || typeof app.title !== 'string' || !app.description || typeof app.description !== 'string') fail('title and description required');
  for (const path of [app.resource?.path, app.oauth?.path]) {
    if (!pathPattern.test(path) || !path.startsWith(`/${app.id}/`)) fail('public paths must belong to the app namespace');
  }
  if (app.resource.path === app.oauth.path || app.resource.path.startsWith(`${app.oauth.path}/`)
      || app.oauth.path.startsWith(`${app.resource.path}/`)) fail('resource and OAuth paths overlap');
  if (!pathPattern.test(app.resource.upstreamPath) || !pathPattern.test(app.backend?.healthPath)) fail('invalid backend paths');
  if (app.resource.scope !== `${app.id}:access`) fail('invalid resource scope');
  if (!Number.isInteger(app.backend.port) || app.backend.port < 1024 || app.backend.port > 65535
      || [2019, 4040, 9000, 9001].includes(app.backend.port)) fail('invalid or reserved backend port');
  if (!/^[a-zA-Z0-9][a-zA-Z0-9@_.-]*\.service$/.test(app.backend.service)) fail('invalid backend service');
  if (!/^[a-zA-Z0-9_-]+\.sqlite$/.test(app.oauth.database)) fail('database must be unique and local to host state');
  if (!app.oauth.cookies || typeof app.oauth.cookies !== 'object') fail('OAuth cookie names are required');
  const cookieNames = new Set();
  for (const type of ['session', 'interaction', 'resume']) {
    const name = app.oauth.cookies[type];
    if (!matches(/^[a-zA-Z0-9_-]+$/, name) || cookieNames.has(name)) fail('OAuth cookie names must be safe and unique');
    cookieNames.add(name);
  }
  return app;
}

export function loadApp(path = codexConnectProfile) {
  return validateApp(JSON.parse(readFileSync(path, 'utf8')));
}

export function validateApps(apps) {
  if (!Array.isArray(apps) || !apps.length || apps.length > 2) throw new Error('One or two declared Connect profiles required');
  apps.forEach(validateApp);
  for (const values of [apps.map((a) => a.id), apps.map((a) => a.backend.port),
    apps.map((a) => a.oauth.database), apps.flatMap((a) => Object.values(a.oauth.cookies))]) {
    if (new Set(values).size !== values.length) throw new Error('Connect profiles must isolate ids, ports, databases and cookies');
  }
  return apps;
}

export function loadApps() {
  return validateApps([loadApp(codexConnectProfile), loadApp(opencodeConnectProfile)]);
}

export function appPaths(app) {
  const metadata = `/.well-known/oauth-protected-resource${app.resource.path}`;
  const issuerMetadata = `/.well-known/oauth-authorization-server${app.oauth.path}`;
  const prefix = app.oauth.path;
  const literal = (path) => path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const protocol = [metadata, issuerMetadata, `${prefix}/.well-known/openid-configuration`,
    `${prefix}/auth`, `${prefix}/token`, `${prefix}/token/revocation`, `${prefix}/jwks`];
  return {
    metadata, issuerMetadata,
    oauthPattern: `^(${protocol.map(literal).join('|')}|${prefix}/auth/[A-Za-z0-9_-]+)$`,
    consentPattern: `^${prefix}/interaction/[A-Za-z0-9_-]+$`,
    verify: `/_host-ingress/verify/${app.id}`,
    eventsAuthorize: `/_host-ingress/events/authorize/${app.id}`,
  };
}

if (import.meta.main) {
  for (const app of loadApps()) console.log([app.id, app.backend.service, app.backend.port, app.backend.healthPath, app.resource.path].join('\t'));
}
