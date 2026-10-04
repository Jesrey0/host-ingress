# Host ingress

> Host ingress is an independent project and is not affiliated with or endorsed
> by OpenAI, ngrok, or Caddy.

Host ingress owns the public route allocation, authentication, and ngrok/Caddy
runtime for Codex Connect and OpenCode Connect. Each sibling backend owns its
loopback service and deployment lifecycle; neither runtime depends on the other.

## Architecture

`config/codex-connect.json` and `config/opencode-connect.json` are the two explicit
production profiles. Each declares its protected resource, OAuth issuer, private
backend, cookies, and durable database.
`lib/apps.mjs` validates their namespaces and isolated state, rejects unsafe paths,
and owns the exact OAuth route patterns. There is no arbitrary app/plugin registry.

`lib/routes.mjs` renders each protected resource, operator consent route, and exact
OAuth protocol allowlist. Authorization continuation and consent accept exactly one
opaque path segment. Both consent routes use the fixed
`CODEX_CONNECT_BASIC_AUTH_USER` / `CODEX_CONNECT_BASIC_AUTH_HASH` environment names
defined in the renderer. `Caddyfile` owns the loopback listener, redacted access logging,
and final 404. Routes are generated into each immutable release as `apps.caddy`;
there is no second handwritten route registry. To inspect without deploying:

```bash
node scripts/render-caddy.mjs /tmp/host-ingress-preview
# Inspect /tmp/host-ingress-preview/{Caddyfile,apps.caddy,assurance.caddy}.
```

`auth/server.mjs` serves two independent providers and SQLite stores on the shared
loopback auth listener. Both use the same fixed operator identity and signing
secrets. Caddy owns the operator Basic credential environment and forwards only
the authenticated consent identity to host-oauth. `auth/chatgpt.mjs` owns the
trusted ChatGPT client metadata and CIMD/private_key_jwt and persistent-refresh
policy. Provider clients, tokens, grants, browser cookies, and issuer-bound Events
contexts remain isolated.

`lib/origin.mjs` resolves **PUBLIC_ORIGIN** once per process and normalizes one
trailing slash. It is the only public authority; the OAuth and ngrok service
environments must declare the same HTTPS origin. No generated environment file or
transport-discovered URL becomes another authority.

`transport/ngrok/` owns the agent-only config guard, launch arguments, Traffic
Policy, tunnel identity checks, and edge marker/HSTS verification. Routing and
OAuth do not consume the ngrok API. Deployment explicitly manages the three
ingress services; it never owns or restarts either Connect backend.

## Canonical Connect paths

```text
ChatGPT → stable ngrok HTTPS endpoint → Caddy → Codex Connect :8767
                                        │   → OpenCode Connect :8788
                                        └→ host-oauth :9001 (local validation)
```

The canonical MCP URLs are `${PUBLIC_ORIGIN}/codex-connect/mcp` and
`${PUBLIC_ORIGIN}/opencode-connect/mcp`. Both public paths rewrite to private `/mcp`. `PUBLIC_ORIGIN` is
set in the ngrok and OAuth service environments; `./scripts/operator status` reports the live URL.
The public endpoint uses ChatGPT-native OAuth. Backend readiness, ingress
readiness, and a working ChatGPT connection are independently verified states.

| Surface | Private listener | Policy |
| --- | --- | --- |
| `/codex-connect/mcp` | `127.0.0.1:8767/mcp` | OAuth Bearer token on every request |
| `/opencode-connect/mcp` | `127.0.0.1:8788/mcp` | OAuth Bearer token on every request |
| `/codex-connect/oauth/interaction/*` | `127.0.0.1:9001` | Operator Basic login and explicit CSRF-protected consent |
| `/opencode-connect/oauth/interaction/*` | `127.0.0.1:9001` | Same operator Basic login and CSRF-protected consent |
| OAuth discovery, authorization, token, revocation, public keys | `127.0.0.1:9001` | OAuth protocol validation |
| Caddy gateway | `127.0.0.1:9000` | Exact declared routes; default deny |

Public application paths are project-namespaced. The only root-level exceptions
are protected-resource and authorization-server discovery for each declared app.
`/mcp`, `/status`, `/health`, `/healthz`, `/verify`, all internal auth-check paths,
and raw OpenCode routes such as `/session`, `/provider`, `/config`, `/event`,
`/global`, `/permission` and `/file` return 404, including namespaced undeclared
variants. The raw OpenCode control plane has no public proxy route.

## Authentication

`host-oauth` uses the pinned `oidc-provider` library, with durable SQLite storage.
The single operator identity and issuer signing/cookie keys are generated once.
Caddy authenticates the operator using the existing bcrypt credential and sets
an internal identity header only on the consent route. Public callers cannot
assert that identity. The issuers are `${PUBLIC_ORIGIN}/codex-connect/oauth` and
`${PUBLIC_ORIGIN}/opencode-connect/oauth`; each accepts only its own resource and
scope. Codex uses `codex-connect:access`, `oauth.sqlite`, `_session`,
`_interaction`, and `_interaction_resume` exactly. OpenCode uses
`opencode-connect:access`, `opencode-connect-oauth.sqlite`, `_opencode_session`,
`_opencode_interaction`, and `_opencode_interaction_resume`.

- Only ChatGPT's `https://chatgpt.com/oauth/client.json` CIMD client identifier
  is accepted. Its stable metadata is registered locally with the provider so
  repeated token refreshes reuse one verified JWKS cache instead of fetching
  ChatGPT's signing keys on every request. CIMD remains advertised for protocol
  discovery, and `private_key_jwt` remains the selected authentication method.
  Service startup and deployment do not fetch the CIMD document or signing keys;
  the provider fetches and caches signing keys when verifying client assertions.
  No dynamic registration or shared client secret is required.
- The exact callback is `https://chatgpt.com/connector_platform_oauth_redirect`.
  The provider returns issuer identification (`iss`) on authorization responses.
- Authorization-code flow requires S256 PKCE. Token requests require ChatGPT's
  `private_key_jwt` assertion, verified against its published signing keys.
- `resource` is the exact canonical MCP URL. `codex-connect:access` authorizes
  the existing single-user HostPlane and WorkerPlane surface.
  OpenCode uses its own exact MCP URL and `opencode-connect:access`.
  All ChatGPT authorizations through the trusted client map to the same host
  operator identity; there is no per-account identity or account-label state.
- Protected-resource metadata follows
  [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html#section-2), using the app
  title as `resource_name` and advertising only that app's resource scope
  in `scopes_supported`. Authorization-server metadata separately advertises
  `offline_access`; persistent ChatGPT refresh does not require requesting it.
- Access tokens are opaque, issuer-local, and valid for ten minutes. Each request
  checks the stored token's expiration, audience, subject, scope, and live grant.
  No network identity-provider lookup occurs on normal MCP calls.
- The trusted ChatGPT CIMD client receives a persistent refresh credential even
  when it does not request the OIDC `offline_access` scope. Access tokens remain
  short-lived (ten minutes), while normal renewal is silent and independent of
  the browser session. ChatGPT refresh credentials are client-bound through
  `private_key_jwt`, non-rotating to tolerate concurrent refresh attempts, and
  are stored durably until revoked. Other clients keep the normal
  `offline_access`/rotation policy. OAuth state survives service restarts; explicit
  revocation remains available at the advertised revocation endpoint.
- Caddy strips credentials before proxying MCP requests to either Connect backend.
  All request/response headers and raw request URIs are excluded from Caddy
  access and runtime error logs; authoritative `client_ip`, route surface, status and assurance
  audit fields remain available. ngrok request inspection is disabled.

This is a high-trust single-user host. Local processes can reach the loopback
listeners; use OS/account isolation for untrusted local users. ngrok owns public
TLS and HSTS. The agent-to-host hop stays on loopback. A coarse shared-endpoint
rate ceiling remains at the edge, but Codex Connect does not apply a second
per-client-IP namespace bucket because ChatGPT egress IPs establish network provenance,
not operator/workspace identity. The edge also injects `x-host-ingress-policy:
ngrok-edge-v2`; public verification treats that marker plus HSTS as proof that the
intended Traffic Policy is active. The consent interaction path has an additional
20 requests per source IP per minute limit for login-abuse control, alongside the
600 requests per minute global ceiling.

## Compositional transport assurance

Admission composes **transport assurance × verified OAuth client identity ×
resource authorization**. OAuth remains authoritative for the exact issuer,
resource, scope, live grant and operator principal. Its private token verifier
exposes the verified `clientId` in the generic `X-Host-Ingress-Client-Id` header;
it introduces no transport scope, grant, token, resource or Events field.
Only `https://chatgpt.com/oauth/client.json` requires `openai-network` assurance
on every declared MCP resource route. Future clients using the same resources
keep ordinary OAuth authorization. Browser authorization, discovery, token and
consent routes are never CIDR gated.

`openai-network` means a source address in the official OpenAI-operated egress
feed. It is neither mTLS nor user/workspace identity, and the published ranges
may serve multiple OpenAI users. Caddy trusts only the ngrok agent's loopback
peer (`127.0.0.1/32`, `::1/128`), uses `trusted_proxies_strict` to parse
`X-Forwarded-For` right to left, and chooses the first untrusted address.
[ngrok documents appending the actual public caller address](https://ngrok.com/docs/gateway/endpoints/http#upstream-headers)
after caller-supplied XFF. This append behavior is a live verified deployment
assumption: each `public` or `gates-public` check sends one distinctive default-deny
request through `PUBLIC_ORIGIN` with a forged address from the bundled snapshot.
It reads only newly appended Caddy access-log records, correlates a dedicated
random probe field, and requires authoritative `request.client_ip` to differ
from that address. Missing evidence or accepted spoofing fails the check.
Headers and URIs remain redacted. Local processes share
OS-account trust and can impersonate the agent; OS isolation remains necessary
for untrusted local processes. Source fixtures verify parsing and admission,
not the active edge's behavior.

Caddy strips all incoming `X-Host-Ingress-*` headers before private decisions,
copies the verifier's sealed request context and generic client ID, and rejects
success missing either header with 502. The exact client ID and authoritative
`client_ip` jointly determine assurance. Caddy strips the client ID and all
transport headers and caller-supplied `X-OpenAI-*` identity headers before
proxying. Only the existing sealed request context reaches Connect; its contents and Events contract are unchanged.

`config/transport-assurance.json` contains only `mode`. The rollout was first
deployed in `observe`; after live authenticated ChatGPT traffic from multiple
published OpenAI egress addresses passed without a mismatch, production was
promoted to `enforce`. Observe logs `assurance_mode=observe`,
`assurance_required=openai-network` for
ChatGPT and `assurance_decision=would-deny` for a mismatch, then forwards with
unchanged backend semantics. Enforce logs `deny` and returns 403 before reaching
the backend on mismatch. Mode is reviewed source configuration, never hidden
runtime state. Before selecting enforce, verify authenticated ChatGPT calls
through the active edge and inspect authoritative `client_ip` audit records;
source tests alone do not establish those live assumptions.

`transport/openai-network.json` is the canonical, numerically sorted snapshot
of [the official feed](https://openai.com/chatgpt-connectors.json). Rendering is
deterministic and offline; requests, startup and deployment never fetch it.
Deployment bundles the snapshot, assurance module, mode, maintenance script and
generated `assurance.caddy`; the release digest covers all of them. There is no
handwritten prefix list in Caddy.

```bash
./scripts/operator network status   # tracked source mode, count, timestamp, age
./scripts/operator network refresh  # explicit HTTPS fetch; changes only source snapshot
./scripts/check source
```

Refresh validates exactly `creationTime,prefixes`, each single `ipv4Prefix` or
`ipv6Prefix` entry, CIDR host bits, duplicates and timestamps. It supports IPv4
and IPv6 across their full valid prefix lengths, canonicalizes IPv6 and retains
microsecond timestamp ordering. The feed's zone-less timestamp is explicitly
interpreted as UTC. The 30-day maximum source age is an operator maintenance
deadline, not a publisher freshness guarantee; timestamps more than five minutes
in the future are also rejected. Source/deployment rendering and status fail
visibly for malformed or stale snapshots. An already running matcher remains
the deployed last-known-good until a reviewed release reload; status reports
its age and fails when stale. If the official feed itself becomes stale, refresh
fails instead of laundering freshness with a fetch time.

Fetch, parse, schema, stale/future timestamp and regression failures preserve
the last-known-good file. An older timestamp, or changed prefixes without a new
timestamp, is rejected. A valid newer feed replaces the file through an exclusive
same-directory temporary file, file fsync, atomic rename and directory fsync.
Refresh rejects roots containing `release-manifest.json` before fetching or
writing; deployed status still works. Refresh never changes mode, deploys, or
reloads services. Review its source diff
and use the ordinary release flow when authorized. `operator status` reports
the deployed snapshot/mode separately from `network status`'s source checkout.

This stays within the existing ngrok Free HTTP endpoint: public TLS terminates
at ngrok, the agent forwards to the unchanged loopback listener, and Caddy adds
admission offline. No extra Traffic Policy rule, raw TLS, `terminate-tls`, paid
feature, custom domain or second provider origin is required. The existing edge
rate limits and HSTS remain unchanged. See [Caddy's trusted proxy parsing](https://caddyserver.com/docs/caddyfile/options#trusted-proxies-strict)
for the right-to-left trust model.

## MCP Events private authorization contract

The OAuth provider and fixed local operator remain authoritative. A successful
private token verifier returns `X-Host-Ingress-Auth-Context`. Caddy uses an
ordered `route` to delete all caller copies before `forward_auth`, copies only
the verifier response, and rejects a success without context with 502. It still
strips bearer credentials, cookies and the consent-only operator header. The
context header is excluded from access logs; request bodies are not logged.

The header is an opaque AES-256-GCM request context, with an ingress-keyed,
domain-separated key derived from the existing cookie signing key. Associated
data binds the configured issuer. It contains the fixed operator principal,
client ID, opaque grant ID, exact resource and scope, issuance time and an expiry
at most 30 seconds later, capped by the validating access token. Keys never leave
ingress. Configured older cookie keys can decrypt contexts during key rotation.

Only the app-specific `POST /_host-ingress/events/authorize/codex-connect` and
`POST /_host-ingress/events/authorize/opencode-connect` on the OAuth loopback
listener resolve or check their own contexts. Context encryption binds the issuer
as authenticated additional data. Identical grant IDs or shared signing keys cannot
authorize a context across issuers. It is excluded from the public Caddy
allowlist. JSON bodies are limited to 8192 bytes:

- `{ "requestContext": "<opaque header>" }` validates the short-lived context
  and current provider grant. An allow response contains `allowed: true` and
  `authorization` with `principal`, `clientId`, `grantId`, `resource`, `scope`
  and a separate opaque `grantContext` for later checks.
- `{ "authorization": { ... } }` authenticates that durable context and exact
  tuple, then checks the current grant through `provider.Grant.find`. A durable
  context is accepted only here, never as a request context. It contains no
  OAuth bearer or refresh token and has no authority independent of its grant.
- Missing, tampered, mismatched, stale request contexts, missing/revoked grants
  and scope removal return 403 with `allowed: false`. Unexpected provider
  failures return 500; Connect must treat all unavailable decisions as deny
  for admission. The route never returns provider payloads or tokens.

OAuth token/refresh-token revocation explicitly uses the provider's native
whole-grant revocation policy. Ordinary access-token expiry or removal does not
revoke a grant. Separate grants for the same fixed operator remain independent;
a new grant cannot make an old grant context valid again. No users, tenants,
roles or external identity providers are introduced. This is still a trusted
local deployment: loopback processes share OS-account authority, and the sealed
context authenticates private checks. Isolate untrusted local processes at the
OS boundary. Connect must not read the OAuth database or mirror grant state.

The source gate includes real Caddy forwarding, duplicate/spoofed header
replacement, success without context, private-path denial, tuple/issuer/expiry
checks, scope removal, revocation, separate grants and auth restart/outage cases.
These fixture checks do not establish an installed or live Events deployment.

## Configuration and installation

Requirements: user systemd, Caddy, ngrok, and Node **24.16.0 or later**, including
`node:sqlite`. The service uses `~/.local/bin/node`; npm installs the locked
provider dependency. Keep executables user-global.

Host-local inputs:

```text
~/.config/host-ingress/env.ngrok
    PUBLIC_ORIGIN
~/.config/host-ingress/env.oauth
    PUBLIC_ORIGIN
~/.config/host-ingress/env.caddy
    CODEX_CONNECT_BASIC_AUTH_USER
    CODEX_CONNECT_BASIC_AUTH_HASH
~/.config/ngrok/ngrok.yml
~/.config/host-ingress/oauth-secrets.json
```

`~/.config/ngrok/ngrok.yml` is agent/account configuration only. Do not define
named `tunnels:` or `endpoints:` there: `host-ingress` is the sole owner of the
stable public endpoint, upstream, tunnel name, Traffic Policy, and lifecycle.
The managed service launches that definition explicitly rather than through
`ngrok start <name>`, preventing a second ingress source of truth.

Keep all three environment files, `ngrok.yml`, and `oauth-secrets.json` mode 0600.
Copy the matching examples from
`config/env.*.example`; the service units read only their own file. Keep the
Basic Auth hash value single-quoted in `env.caddy` because it contains `$` signs.
The Basic credential is the human operator's browser
login, never the MCP connector's authentication method. Use Caddy's interactive
`hash-password` command when initially provisioning it; do not put plaintext
passwords into shell arguments or repository files.

Initialize OAuth exactly once:

```bash
node scripts/init-oauth.mjs
npm ci --ignore-scripts
./scripts/check source
./scripts/deploy
```

Initialization refuses to overwrite existing identity/token state. Back up the
secret file and both OAuth SQLite databases securely together. Do not regenerate
identity or keys during ordinary deployment or recovery.

Deployments publish immutable code/config/dependency releases under
`~/.config/host-ingress/runtime/releases/` and atomically select `runtime/current`.
Codex Connect OAuth state stays at `~/.local/state/host-ingress/oauth.sqlite`;
OpenCode state is `~/.local/state/host-ingress/opencode-connect-oauth.sqlite`.
Caddy logs stay at `~/.local/state/host-ingress/logs`. Tracked units in `deploy/systemd/` are copied
to the user systemd directory. Each release records the source Git SHA and a
deterministic content SHA-256; `./scripts/operator status` recomputes the digest and reports
the live identity. Deployment refuses a dirty Git checkout, preserves the previous
selector and unit files, restarts only services whose unit/runtime changed (otherwise
reloading Caddy atomically), verifies the local and public boundaries, and
automatically restores the prior release if activation fails.
Only after successful verification are old releases pruned to the five newest.
Deployment never restarts application backends. It verifies ingress independently
of backend readiness; `check backend` establishes readiness separately. Status
reports each backend separately, while its exit status reflects ingress integrity.
Rendering consumes copied release profiles, and both profiles plus the renderer
are included in the release digest. Any app profile change restarts the shared OAuth
owner; it cannot restart either backend.

The systemd services hide the home directory by default and bind only the inputs
each process requires. ngrok receives only `PUBLIC_ORIGIN`; Caddy receives only
the operator Basic Auth user and hash; OAuth receives only `PUBLIC_ORIGIN`. ngrok
can read its binary, Node launcher, ngrok config, and published runtime policy;
Caddy can read its binary/runtime and write only its storage/log paths; OAuth can
read Node, the published runtime and signing secrets and write only host-ingress state.

## ChatGPT setup

Create or edit each Connect custom app using the canonical HTTPS URL and
**OAuth** authentication. Choose **CIMD** when offered; leave client ID/secret
fields empty. Complete the browser's operator login and consent, scan tools, and
enable the app.

Use the exact callback and client metadata shown above. If ChatGPT displays a
different callback mode, inspect its configuration before expanding the allowlist.
See [OpenAI's authentication contract](https://developers.openai.com/plugins/build/auth).

## Health and recovery

```bash
./scripts/operator status
./scripts/check source       # source configuration, OAuth tests, unit validation
./scripts/check ingress      # private OAuth health, routing, discovery, denial checks
./scripts/check backend      # both private backend readiness endpoints
CHECK_PUBLIC=1 ./scripts/check
```

These checks establish routing, denial behavior, and the real ChatGPT CIMD
authorization handoff to operator login (including issuer identification on
errors). `operator status` reads **both deployed profiles**, reports
each service, readiness and canonical resource URL, checks both local/public auth gates, and
requires configured URL = live ngrok URL,
the expected `127.0.0.1:9000` upstream, a verified installed-release digest, the
public 401 auth gate, HSTS, and the edge-policy marker. They do not approve access
or substitute for authenticated MCP calls or ChatGPT-side validation. Validate `status`, `inspect`,
command/process APIs, worker/action flows, and idle reconnect from the connector.
A small 5 × status / 5 × inspect sanity check is sufficient for transport latency.

Startup ordering is ngrok → wants Caddy → wants host-oauth. Each service is enabled
and independently restartable. Shared OAuth uses `Restart=always` with a three-second
retry delay so unexpected clean exits also recover; explicit `systemctl --user stop
host-oauth.service` still leaves it stopped for maintenance. Caddy and ngrok use
`Restart=on-failure`. Each Connect backend starts
under its own independently managed service. While auth is unavailable Caddy fails closed;
while one backend is unavailable its authorized MCP calls fail until it recovers,
while the sibling remains usable.
Neither backend restarts nor ngrok reconnects invalidate OAuth grants. MCP clients
must initialize a new session after a backend restart.

Deployments avoid unnecessary transport churn. If the Caddy unit is unchanged,
the new release is activated with an atomic Caddy reload instead of a restart;
unchanged ngrok policy leaves the stable tunnel running; and host-oauth restarts
only when its auth code, profile, origin resolver, dependencies, or unit changed.
Changes limited to the route renderer reload Caddy. Changes to ngrok transport
code/policy or the shared origin resolver restart ngrok. Assurance snapshot or
mode changes only reload Caddy. This prevents unrelated
deployments from interrupting long-lived MCP requests.

## Operator lifecycle

```bash
./scripts/operator help
./scripts/operator status
./scripts/operator basic rotate NEW_USERNAME
./scripts/operator oauth revoke-all
./scripts/operator oauth backup /secure/path/oauth-backup
./scripts/operator oauth restore /secure/path/oauth-backup
```

Basic Auth rotation takes the non-secret username as an argument and runs
Caddy's own interactive `hash-password --algorithm bcrypt` prompt. Caddy reads
the password from the inherited terminal without echo; only the bcrypt hash is
captured. The command validates Caddy's current config with the proposed values,
atomically updates mode-0600 `env.caddy`, then runs
`systemctl --user reload host-ingress.service`. Systemd rereads that EnvironmentFile for `ExecReload`, so
Caddy applies the changed credentials through its zero-downtime config reload. If
validation or reload fails, the old file is restored and Caddy is reloaded with
the old values.

`oauth revoke-all` requires typing the command name to confirm. It stops
`host-oauth`, transactionally deletes all artifacts linked to stored grants,
clears pending `Session` and `Interaction` browser state, then restarts and checks
OAuth health. It preserves client-assertion replay records and the OAuth signing
identity. All ChatGPT connections must authorize again; the temporary OAuth
outage fails closed through Caddy. This operation covers both deployed issuer databases for the single operator
identity and does not pretend to target an individual ChatGPT account.

`oauth backup DIR` stops `host-oauth`, checkpoints SQLite, verifies the signing
identity and database, and atomically creates a new mode-0700 directory
containing mode-0600 `oauth-secrets.json`, `oauth.sqlite`, and
`opencode-connect-oauth.sqlite`. Maintenance reads the profiles from the selected
immutable release, never inferring targets from an editable source checkout. The destination
must not already exist; store it on protected storage and preserve all three files
together. The service is restarted and its health endpoint is checked even when
backup creation fails. `oauth restore DIR` requires typing `restore`; it checks
the same private-file permissions and contents, stops the service, stages all three
new files and their current files beside its target on private same-filesystem
directories, installs all files, and checks database integrity before
restarting. If installation fails, the old set is put back. If restart or
health verification fails, the command stops OAuth, removes SQLite WAL/SHM
sidecars, restores the prior set, and restarts/checks the prior service when
possible. It reports successful prior-state recovery separately from a failure
to recover; when prior recovery fails, private staging evidence is retained and
its locations are reported for operator recovery. The identity and databases
still require three filesystem replacements, so a host crash during restore can
leave a partial set that needs recovery from the private staging directories.
A successful restore intentionally replaces grants and signing keys with the
exact saved snapshot for both apps. Backups must contain the complete shared
identity/database set and the current durable ChatGPT grant/refresh representation;
incomplete or non-current sets are refused rather than migrated during restore.
Revocation is transactional within each database; an unexpected failure between
databases can leave partial revocation and is reported visibly.

ngrok account and authtoken rotation remain upstream-owned: use ngrok's own CLI
and `~/.config/ngrok/ngrok.yml`. `host-ingress` intentionally does not wrap or
duplicate ngrok credential management.

A future mTLS upgrade requires a TLS endpoint that can verify the client
certificate and evidence that ChatGPT supports that connection mode. ngrok Free
HTTP endpoints cannot pass public client certificates through their terminated
TLS hop. Such an upgrade needs separately approved edge capability and certificate
trust/rotation design, while preserving OAuth client binding and resource
authorization. Secure MCP Tunnel is also a separately approved architecture;
this deployment does not configure it.

Public resource and issuer paths stay inside their declared `/codex-connect/` and
`/opencode-connect/` namespaces. Paths are exact and
cannot contain wildcards or Caddy directives. Resource and issuer paths cannot
overlap. Discovery paths are derived from the resource and issuer paths; backend
hosts are always `127.0.0.1`. Private-path regression probes live in
`scripts/check-oauth.mjs` and are reused by the Caddy gateway test. Public route
semantics come from the fixed allowlist and terminal 404. Existing issuers,
resources, scopes, databases, and cookies are persistent authorization identities.

The tests exercise real Caddy routing, authenticated MCP POST forwarding,
OAuth/refresh/revocation flows, origin validation, and deployment/rollback in a
disposable fake host. Source tests and local fixtures do not establish live
ChatGPT connector behavior. Deployment rollback restores the previous release
selector and units while preserving both durable OAuth databases. A source
rollback cannot undo explicit operator revocation or state restore.
