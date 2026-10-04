import { readFileSync, openSync, writeFileSync, fsyncSync, closeSync, renameSync, rmSync } from 'node:fs';
import { isIP } from 'node:net';
import { randomUUID } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CHATGPT_CLIENT } from '../auth/chatgpt.mjs';

export const OPENAI_SOURCE = 'https://openai.com/chatgpt-connectors.json';
// An operator maintenance deadline, not a promise about the publisher's cadence.
export const MAX_SOURCE_AGE_DAYS = 30;
const snapshotURL = new URL('./openai-network.json', import.meta.url);
const policyURL = new URL('../config/transport-assurance.json', import.meta.url);
const day = 86400000;

function exactKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === keys;
}

export function cidr(input) {
  if (typeof input !== 'string' || input.trim() !== input || !/^[0-9a-fA-F:.]+\/(0|[1-9][0-9]*)$/.test(input)) throw new Error('Invalid CIDR');
  const [ip, length] = input.split('/');
  const family = isIP(ip);
  if (!family) throw new Error('Invalid CIDR address');
  const bits = family === 4 ? 32 : 128;
  const prefix = Number(length);
  if (prefix > bits) throw new Error('Invalid CIDR prefix length');
  // WHATWG URL serialization canonicalizes IPv6, including embedded IPv4.
  const canonical = family === 4 ? ip : new URL(`http://[${ip}]/`).hostname.slice(1, -1);
  let value;
  if (family === 4) value = ip.split('.').reduce((n, octet) => (n << 8n) | BigInt(octet), 0n);
  else {
    const halves = canonical.split('::').map((part) => part ? part.split(':') : []);
    const words = halves.length === 1 ? halves[0]
      : [...halves[0], ...Array(8 - halves[0].length - halves[1].length).fill('0'), ...halves[1]];
    value = words.reduce((n, word) => (n << 16n) | BigInt(`0x${word}`), 0n);
  }
  if (value % (1n << BigInt(bits - prefix)) !== 0n) throw new Error('CIDR has host bits set');
  return { family, value, prefix, text: `${canonical}/${prefix}` };
}

function timestamp(value) {
  if (typeof value !== 'string' || value.trim() !== value || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z?$/.test(value)) throw new Error('Invalid source timestamp');
  // The official feed omits a zone; its creationTime is interpreted explicitly as UTC.
  const base = value.slice(0, 19);
  const time = Date.parse(`${base}Z`);
  if (!Number.isFinite(time) || new Date(time).toISOString().slice(0, 19) !== base) throw new Error('Invalid source timestamp');
  const fraction = (value.match(/\.(\d+)/)?.[1] ?? '').padEnd(6, '0');
  return `${base}.${fraction}Z`;
}

const micros = (value) => BigInt(Date.parse(value.slice(0, 19) + 'Z')) * 1000n + BigInt(value.slice(20, 26));

function prefixes(values) {
  if (!Array.isArray(values) || !values.length || values.length > 10000) throw new Error('Invalid prefix list');
  const parsed = values.map(cidr).sort((a, b) => a.family - b.family || (a.value < b.value ? -1 : a.value > b.value ? 1 : a.prefix - b.prefix));
  if (new Set(parsed.map((p) => p.text)).size !== parsed.length) throw new Error('Duplicate CIDR');
  return parsed.map((p) => p.text);
}

export function assertFresh(snapshot, now = Date.now()) {
  const age = now - Number(micros(snapshot.creationTime)) / 1000;
  if (age < -300000) throw new Error('Source timestamp is in the future');
  if (age > MAX_SOURCE_AGE_DAYS * day) throw new Error(`Network snapshot is stale (maximum ${MAX_SOURCE_AGE_DAYS} days); explicitly refresh the source`);
  return snapshot;
}

export function parseSource(document, now = Date.now()) {
  if (!exactKeys(document, 'creationTime,prefixes') || !Array.isArray(document.prefixes)) throw new Error('Invalid OpenAI source schema');
  const snapshot = { schemaVersion: 1, source: OPENAI_SOURCE, creationTime: timestamp(document.creationTime),
    prefixes: prefixes(document.prefixes.map((entry) => {
      if (!exactKeys(entry, 'ipv4Prefix') && !exactKeys(entry, 'ipv6Prefix')) throw new Error('Invalid source prefix schema');
      const key = Object.keys(entry)[0];
      const parsed = cidr(entry[key]);
      if (parsed.family !== (key === 'ipv4Prefix' ? 4 : 6)) throw new Error('Invalid prefix family');
      return parsed.text;
    })) };
  return assertFresh(snapshot, now);
}

export function validateSnapshot(snapshot) {
  if (!exactKeys(snapshot, 'creationTime,prefixes,schemaVersion,source')
      || snapshot.schemaVersion !== 1 || snapshot.source !== OPENAI_SOURCE) throw new Error('Invalid network snapshot schema');
  const normalized = { schemaVersion: 1, source: OPENAI_SOURCE, creationTime: timestamp(snapshot.creationTime), prefixes: prefixes(snapshot.prefixes) };
  if (normalized.creationTime !== snapshot.creationTime || JSON.stringify(normalized.prefixes) !== JSON.stringify(snapshot.prefixes)) throw new Error('Snapshot must be canonical');
  return normalized;
}

export const snapshotText = (snapshot) => `${JSON.stringify(validateSnapshot(snapshot), null, 2)}\n`;
export function loadSnapshot(path = snapshotURL) {
  const text = readFileSync(path, 'utf8');
  const snapshot = validateSnapshot(JSON.parse(text));
  if (snapshotText(snapshot) !== text) throw new Error('Snapshot file must be canonical');
  return snapshot;
}

export function validateAssurance(policy) {
  if (!exactKeys(policy, 'mode') || !['observe', 'enforce'].includes(policy.mode)) throw new Error('Invalid transport assurance policy');
  return policy;
}
export const loadAssurance = (path = policyURL) => validateAssurance(JSON.parse(readFileSync(path, 'utf8')));

export function renderNetwork(snapshot = loadSnapshot()) {
  validateSnapshot(snapshot);
  return `# Generated from ${snapshot.source}; source timestamp ${snapshot.creationTime}\n(openai-network) {\n\tclient_ip ${snapshot.prefixes.join(' ')}\n}\n`;
}

export function renderAdmission(app, policy) {
  validateAssurance(policy);
  const client = `${app.id}_chatgpt`;
  const mismatch = `${app.id}_network_mismatch`;
  const rejection = policy.mode === 'enforce'
    ? `\t\trespond @${mismatch} "Transport assurance required" 403\n` : '';
  return `		@${client} header X-Host-Ingress-Client-Id ${CHATGPT_CLIENT}
		@${mismatch} {
			header X-Host-Ingress-Client-Id ${CHATGPT_CLIENT}
			not {
				import openai-network
			}
		}
		log_append @${client} assurance_required openai-network
		log_append @${mismatch} assurance_decision ${policy.mode === 'enforce' ? 'deny' : 'would-deny'}
${rejection}`;
}

export function assuranceStatus(policy, snapshot, now = Date.now()) {
  validateAssurance(policy);
  validateSnapshot(snapshot);
  const age = (now - Number(micros(snapshot.creationTime)) / 1000) / day;
  let state = 'current';
  try { assertFresh(snapshot, now); } catch (error) { state = error.message; }
  return `Transport assurance: mode=${policy.mode}; exact client=${CHATGPT_CLIENT}; MCP resources only\nOpenAI network: source=${snapshot.source}; timestamp=${snapshot.creationTime}; count=${snapshot.prefixes.length}; age=${age.toFixed(1)} days; ${state}\n`;
}

// Explicit source maintenance only. No request, startup, or deployment fetches.
export async function refreshSnapshot({ path = snapshotURL, fetcher = fetch, now = Date.now() } = {}) {
  const response = await fetcher(OPENAI_SOURCE, { redirect: 'error', signal: AbortSignal.timeout(30000) });
  if (!response.ok) throw new Error('OpenAI snapshot fetch failed; last-known-good unchanged');
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.byteLength;
    if (size > 1024 * 1024) throw new Error('OpenAI source exceeds size limit');
    chunks.push(Buffer.from(chunk));
  }
  const next = parseSource(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))), now);
  let previous;
  try { previous = loadSnapshot(path); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (previous) {
    if (micros(next.creationTime) < micros(previous.creationTime)) throw new Error('Source timestamp regressed');
    if (micros(next.creationTime) === micros(previous.creationTime)) {
      if (snapshotText(next) !== snapshotText(previous)) throw new Error('Source changed without a new timestamp');
      return previous;
    }
  }
  const target = path instanceof URL ? fileURLToPath(path) : resolve(path);
  const directory = dirname(target);
  const temporary = join(directory, `.openai-network-${randomUUID()}.tmp`);
  let fd;
  try {
    fd = openSync(temporary, 'wx', 0o644);
    writeFileSync(fd, snapshotText(next));
    fsyncSync(fd);
    closeSync(fd); fd = undefined;
    renameSync(temporary, target);
    fd = openSync(directory, 'r');
    fsyncSync(fd);
  } finally {
    if (fd !== undefined) closeSync(fd);
    rmSync(temporary, { force: true });
  }
  return next;
}
