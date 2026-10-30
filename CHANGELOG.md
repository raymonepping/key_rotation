# Changelog

All notable changes to this project will be documented here.

## [Unreleased]

### Changed — modernisation to Podman + Durin pattern

**Infrastructure**
- Replaced Docker Compose + external Vault with a fully self-contained Podman stack.
- Three independent compose stacks: `krot-seal`, `krot-vault`, `krot-app`.
- Container prefix `krot-`, network `krot-internal`.
- Ports: vault-s 18700, vault-1 18701, booklib 13400, frontend 13401.

**Vault topology**
- vault-s: OSS 2.0.4, Shamir 1-of-1 seal, Transit engine for auto-unseal.
- vault-1: ENT 2.0.4-ent, Transit auto-unseal, KV v2, Transit secrets (booklib-aes).
- Terraform manages all AppRoles, policies, Transit key and KV seed secrets.

**Token chain (Durin pattern)**
- No `VAULT_TOKEN` in any compose environment block.
- `krot-seal-rotator` / `krot-seal-agent` manage the seal Transit token.
- `krot-rotator` / `krot-vault-agent` manage the booklib AppRole token.
- booklib reads the token file (`/run/vault/token`) per request via `readFileSync`.

**booklib backend**
- Removed `VAULT_TOKEN` env var; replaced with `getToken()` reading `VAULT_TOKEN_FILE`.
- Added `VAULT_CACERT` support via Node's `NODE_EXTRA_CA_CERTS`.
- Added `/health` endpoint probing vault-s + vault-1 `sys/health`.
- Added `POST /api/test-key` — internally tests the current API key against `/protected`.
- Moved rotation scripts to `booklib/scripts/`.

**Frontend**
- New React 19 / Vite SPA with Daylight Glass design system.
- 4 panels: Secret Status, Transit Demo, API Key, Rotation Log.
- Shell: rail navigation, vault-s + vault-1 live status pills, sig-name shimmer footer.
- HTTPS nginx on port 8443 (`krot-web`), `/api/` proxied to booklib.

**Removed**
- `docker-compose.yml`, `Dockerfile` (root), `.dockerignore` (root).
- `nginx/booklib.conf`, `nginx/.htpasswd`.
- `status/` directory (replaced by React frontend).
- `rendered/` and `vault-token/` directories (replaced by agent-token volume).
- `booklib.env` (old rendered env file).

**Added**
- `Makefile` with 25+ targets matching vault_portal / vault_pki pattern.
- `scripts/` — full suite: common.sh, compose.sh, gen-certs.sh, vault-bootstrap.sh, etc.
- `config/defaults.env` — image pins and port defaults.
- `terraform/vault-seal/` and `terraform/vault-platform/` roots.
- `compose/seal/`, `compose/vault/`, `compose/app/` stacks.
- `compose/common/` — generic rotator.sh, healthcheck.sh, agent entrypoint.sh.
- `booklib/` — modernised Node.js backend with Containerfile.
- `frontend/` — React SPA with Containerfile.
- `vault/vault-s/config.hcl`, `vault/vault-1/config.hcl`, `vault/policies/autounseal.hcl`.
- `DESIGN.md` — full topology, token chain, state map.
- `docs/architecture.md`, `docs/operations.md`, `docs/security-model.md`.
- `make verify` — 25-point end-to-end check.

## [0.x.x] — previous Docker era

See git history.
