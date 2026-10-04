#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { loadApps } from '../lib/apps.mjs';
import { renderApps } from '../lib/routes.mjs';
import { loadAssurance, loadSnapshot, renderNetwork, assuranceStatus, assertFresh } from '../transport/assurance.mjs';

const destination = process.argv[2];
if (!destination) throw new Error('usage: node scripts/render-caddy.mjs <output-directory>');
const apps = loadApps();
const policy = loadAssurance();
const snapshot = assertFresh(loadSnapshot());
const routes = renderApps(apps, undefined, policy);
mkdirSync(destination, { recursive: true });
writeFileSync(resolve(destination, 'apps.caddy'), routes);
writeFileSync(resolve(destination, 'assurance.caddy'), renderNetwork(snapshot));
writeFileSync(resolve(destination, 'Caddyfile'), readFileSync(new URL('../Caddyfile', import.meta.url)));
process.stdout.write(assuranceStatus(policy, snapshot));
