import { appPaths, validateApp, validateApps } from './apps.mjs';
import { loadAssurance, renderAdmission } from '../transport/assurance.mjs';

const OPERATOR_USER_ENV = 'CODEX_CONNECT_BASIC_AUTH_USER';
const OPERATOR_HASH_ENV = 'CODEX_CONNECT_BASIC_AUTH_HASH';

// Fixed allowlist: one protected resource and one OAuth issuer per app.
// Everything else reaches the Caddyfile's terminal 404.
export function renderApps(apps, authAddress, policy = loadAssurance()) {
  return validateApps(apps).map((app) => renderRoutes(app, authAddress, policy)).join('\n');
}

export function renderRoutes(app, authAddress = '127.0.0.1:9001', policy = loadAssurance()) {
  validateApp(app);
  if (!/^127\.0\.0\.1:\d+$/.test(authAddress)) throw new Error('Auth must listen on loopback');
  const paths = appPaths(app);
  return `# ${app.id}
@${app.id}_resource path ${app.resource.path}
handle @${app.id}_resource {
	route {
		log_append surface ${app.id}-mcp
		log_append assurance_mode ${policy.mode}
		forward_auth ${authAddress} {
			uri ${paths.verify}
			copy_headers X-Host-Ingress-Auth-Context X-Host-Ingress-Client-Id
		}
		@${app.id}_missing_context not header X-Host-Ingress-Auth-Context *
		respond @${app.id}_missing_context 502
		@${app.id}_missing_client not header X-Host-Ingress-Client-Id *
		respond @${app.id}_missing_client 502
${renderAdmission(app, policy).trimEnd()}
		rewrite * ${app.resource.upstreamPath}
		reverse_proxy 127.0.0.1:${app.backend.port} {
			header_up Host localhost
			header_up -Authorization
			header_up -Cookie
			header_up -X-Host-Ingress-Operator
			header_up -X-OpenAI-*
			header_up -X-Host-Ingress-Client-Id
			header_up -X-Host-Ingress-Transport-*
		}
	}
}

@${app.id}_consent path_regexp ${paths.consentPattern}
handle @${app.id}_consent {
	basic_auth {
		{$${OPERATOR_USER_ENV}} {$${OPERATOR_HASH_ENV}}
	}
	log_append surface ${app.id}-consent
	reverse_proxy ${authAddress} {
		header_up -Authorization
		header_up -X-Host-Ingress-Auth-Context
		header_up X-Host-Ingress-Operator authenticated
	}
}

@${app.id}_oauth path_regexp ${paths.oauthPattern}
handle @${app.id}_oauth {
	log_append surface ${app.id}-oauth
	reverse_proxy ${authAddress} {
		header_up -X-Host-Ingress-Operator
		header_up -X-Host-Ingress-Auth-Context
	}
}
`;
}
