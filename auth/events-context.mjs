import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';

// Only ingress holds these keys. Domain separation keeps cookie/CSRF use distinct.
// The private backchannel authenticates opaque contexts, not caller identity fields.
export function eventContexts(cookieKeys, issuer) {
  const keys = cookieKeys.map((key) => createHmac('sha256', key)
    .update('host-ingress MCP Events context').digest());
  const aad = Buffer.from(issuer);
  return {
    seal(value) {
      const nonce = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', keys[0], nonce);
      cipher.setAAD(aad);
      const bytes = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
      return Buffer.concat([nonce, cipher.getAuthTag(), bytes]).toString('base64url');
    },
    open(value) {
      if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{40,4096}$/.test(value)) return undefined;
      const bytes = Buffer.from(value, 'base64url');
      for (const key of keys) {
        try {
          const cipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(0, 12));
          cipher.setAAD(aad);
          cipher.setAuthTag(bytes.subarray(12, 28));
          return JSON.parse(Buffer.concat([cipher.update(bytes.subarray(28)), cipher.final()]).toString('utf8'));
        } catch { /* Invalid authentication or retired key: deny below. */ }
      }
      return undefined;
    },
  };
}
