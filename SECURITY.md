# Security

Host ingress is a single-user, self-hosted security boundary. Its production
credentials and durable OAuth/tunnel state must stay outside the repository.

Never commit environment files, Basic-auth credentials or hashes, OAuth keys,
cookies, SQLite databases, ngrok credentials/configuration, private endpoint
URLs, or request logs. The tracked configuration uses examples, templates, and
loopback addresses only.

If you find a security issue, do not publish credentials, exploit details, or
live endpoint information in a public issue. Use GitHub's private vulnerability
reporting/security-advisory channel for this repository when available.
