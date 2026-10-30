# Architecture

See [DESIGN.md](../DESIGN.md) for the full topology diagram and token chain.

## Components

- **vault-s** — OSS Vault, Shamir seal, Transit engine for auto-unseal.
- **vault-1** — Enterprise Vault, Transit auto-unseal via vault-s. Hosts KV v2, Transit secrets, and AppRoles.
- **krot-seal-rotator / krot-seal-agent** — Durin seal plane; keep the seal Transit token fresh.
- **krot-rotator / krot-vault-agent** — Durin app plane; keep the booklib AppRole token fresh.
- **krot-booklib** — Node.js Express API. Reads Vault token from file per request. No VAULT_TOKEN env var.
- **krot-web** — nginx HTTPS serving the React SPA. Proxies `/api/` and `/health` to booklib.

## Network

Single Podman network `krot-internal`. All containers resolve each other by hostname.
Only published ports (127.0.0.1 loopback) are accessible from the host.
