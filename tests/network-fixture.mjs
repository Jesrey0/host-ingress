import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseSource, snapshotText } from '../transport/assurance.mjs';

export function writeFreshSnapshot(root) {
  const now = Date.now();
  const snapshot = parseSource({ creationTime: new Date(now).toISOString(),
    prefixes: [{ ipv4Prefix: '100.31.168.162/32' }, { ipv6Prefix: '2606:4700::/32' }] }, now);
  writeFileSync(join(root, 'transport/openai-network.json'), snapshotText(snapshot));
}
