export const CHATGPT_CLIENT = 'https://chatgpt.com/oauth/client.json';
export const CHATGPT_REDIRECT = 'https://chatgpt.com/connector_platform_oauth_redirect';
export const CHATGPT_JWKS = 'https://chatgpt.com/oauth/jwks.json';
// ChatGPT authorizations are persisted without an expiry and end on revocation.
// Access tokens remain short-lived and refresh remains client-bound.

export const CHATGPT_STATIC_CLIENT = {
  client_id: CHATGPT_CLIENT,
  client_name: 'ChatGPT',
  client_uri: 'https://chatgpt.com/',
  redirect_uris: [CHATGPT_REDIRECT],
  response_types: ['code'],
  grant_types: ['authorization_code', 'refresh_token'],
  token_endpoint_auth_method: 'private_key_jwt',
  token_endpoint_auth_signing_alg: 'RS256',
  jwks_uri: CHATGPT_JWKS,
};
