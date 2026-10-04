import { DatabaseSync } from 'node:sqlite';
import { errors } from 'oidc-provider';
import { CHATGPT_CLIENT } from './chatgpt.mjs';

export function openStore(path) {
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS artifacts (
      model TEXT NOT NULL, id TEXT NOT NULL, payload TEXT NOT NULL,
      expires INTEGER, uid TEXT, grant_id TEXT,
      PRIMARY KEY (model, id)
    );
    CREATE INDEX IF NOT EXISTS artifact_expiry ON artifacts(expires);
    CREATE INDEX IF NOT EXISTS artifact_uid ON artifacts(model, uid);
    CREATE INDEX IF NOT EXISTS artifact_grant ON artifacts(grant_id);
  `);
  const now = () => Math.floor(Date.now() / 1000);
  const find = db.prepare('SELECT payload FROM artifacts WHERE model = ? AND id = ? AND (expires IS NULL OR expires > ?)');
  const byUid = db.prepare('SELECT payload FROM artifacts WHERE model = ? AND uid = ? AND (expires IS NULL OR expires > ?)');
  const upsert = db.prepare('INSERT OR REPLACE INTO artifacts VALUES (?, ?, ?, ?, ?, ?)');
  const insertReplay = db.prepare('INSERT OR IGNORE INTO artifacts VALUES (?, ?, ?, ?, ?, ?)');
  const prune = db.prepare('DELETE FROM artifacts WHERE expires <= ?');
  const consume = db.prepare("UPDATE artifacts SET payload = json_set(payload, '$.consumed', ?) WHERE model = ? AND id = ? AND json_extract(payload, '$.consumed') IS NULL");
  const destroy = db.prepare('DELETE FROM artifacts WHERE model = ? AND id = ?');
  const revoke = db.prepare('DELETE FROM artifacts WHERE grant_id = ?');
  const countGrants = db.prepare("SELECT count(*) AS count FROM artifacts WHERE model = 'Grant'");
  const revokeArtifactsForStoredGrants = db.prepare(`
    DELETE FROM artifacts
     WHERE grant_id IN (SELECT id FROM artifacts WHERE model = 'Grant')
  `);
  const clearPendingBrowserState = db.prepare("DELETE FROM artifacts WHERE model IN ('Session', 'Interaction')");
  const deleteGrants = db.prepare("DELETE FROM artifacts WHERE model = 'Grant'");
  class Adapter {
    constructor(model) { this.model = model; }
    async upsert(id, payload, expiresIn) {
      const time = now();
      prune.run(time);
      const statement = this.model === 'ReplayDetection' ? insertReplay : upsert;
      const durableChatGPTAuthorization = ['Grant', 'RefreshToken'].includes(this.model)
        && payload.clientId === CHATGPT_CLIENT;
      const storedPayload = durableChatGPTAuthorization ? { ...payload } : payload;
      if (durableChatGPTAuthorization) delete storedPayload.exp;
      const result = statement.run(this.model, id, JSON.stringify(storedPayload),
        durableChatGPTAuthorization ? null : expiresIn ? time + expiresIn : null,
        payload.uid ?? null, payload.grantId ?? null);
      if (result.changes !== 1) throw new errors.InvalidClientAuth('client assertion already used');
    }
    async find(id) {
      const row = find.get(this.model, id, now());
      return row && JSON.parse(row.payload);
    }
    async findByUid(uid) {
      const row = byUid.get(this.model, uid, now());
      return row && JSON.parse(row.payload);
    }
    async consume(id) {
      if (consume.run(now(), this.model, id).changes !== 1) throw new errors.InvalidGrant('artifact already consumed');
    }
    async destroy(id) { destroy.run(this.model, id); }
    async revokeByGrantId(grantId) { revoke.run(grantId); }
  }
  return {
    Adapter,
    revokeAll() {
      db.exec('BEGIN IMMEDIATE');
      try {
        const grants = countGrants.get().count;
        revokeArtifactsForStoredGrants.run();
        // Sessions and interactions are browser login/consent state, not
        // grant-owned records. Clear them so pre-revocation flows cannot finish.
        clearPendingBrowserState.run();
        deleteGrants.run();
        db.exec('COMMIT');
        return grants;
      } catch (error) {
        db.exec('ROLLBACK');
        throw error;
      }
    },
    close: () => db.close(),
  };
}
