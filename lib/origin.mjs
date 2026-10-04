// One resolved public authority for OAuth and transport identity.
export function publicOrigin(env = process.env) {
  const normalize = (value) => {
    if (typeof value !== 'string' || !value) throw new Error('PUBLIC_ORIGIN must be an HTTPS origin');
    const origin = value.replace(/\/$/, '');
    const url = new URL(origin);
    if (url.protocol !== 'https:' || url.origin !== origin) {
      throw new Error('PUBLIC_ORIGIN must be an HTTPS origin without credentials, path, query, or fragment');
    }
    return origin;
  };
  return normalize(env.PUBLIC_ORIGIN);
}

if (import.meta.main) console.log(publicOrigin());
