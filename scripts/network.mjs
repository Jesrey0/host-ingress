#!/usr/bin/env node
import { loadAssurance, loadSnapshot, refreshSnapshot, assuranceStatus, assertFresh } from '../transport/assurance.mjs';
import { existsSync } from 'node:fs';

export async function networkCommand(operation) {
  if (!['status', 'refresh'].includes(operation)) throw new Error('usage: node scripts/network.mjs <status|refresh>');
  if (operation === 'refresh' && existsSync(new URL('../release-manifest.json', import.meta.url))) {
    throw new Error('Cannot refresh an immutable deployed release; refresh the source checkout instead');
  }
  const policy = loadAssurance();
  const snapshot = operation === 'refresh' ? await refreshSnapshot() : loadSnapshot();
  process.stdout.write(assuranceStatus(policy, snapshot));
  assertFresh(snapshot);
  if (operation === 'refresh') process.stdout.write('Tracked source snapshot refreshed; review the diff and run ./scripts/check source. Mode and deployed runtime were not changed.\n');
}

if (import.meta.main) {
  if (process.argv.length !== 3) throw new Error('usage: node scripts/network.mjs <status|refresh>');
  networkCommand(process.argv[2]).catch((error) => {
    process.stderr.write(`network: ${error.message}\n`);
    process.exitCode = 1;
  });
}
