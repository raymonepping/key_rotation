# Security model

## Zero-secret containers

No `VAULT_TOKEN` environment variable in any compose service.
The token is written to a named volume by `krot-vault-agent` and read
from `/run/vault/token` by `krot-booklib` at request time.

## Credential chain

1. A human runs `make rotator-bootstrap` once per plane. This delivers:
   - `.secrets/vault/seal-rotator/` (role-id + secret-id) → `krot-seal-rotator`
   - `.secrets/vault/rotator/` (role-id + secret-id) → `krot-rotator`
2. Everything else is machine-issued and rotated automatically.
3. The rotator issues fresh secret-ids before they expire, destroys old ones.
4. The agent re-logs-in whenever its token is rejected (watchdog exits on-failure).

## TLS

All Vault traffic is TLS 1.3. The lab CA (`vault-tls/ca-chain.pem`) signs:
- The Vault listener cert (shared by vault-s and vault-1).
- The web cert (krot-web nginx, HTTPS on 8443).

`NODE_EXTRA_CA_CERTS` makes Node trust the lab CA for outbound fetch.

## ENT licence

Stored in `.secrets/vault/vault.hclic` (mode 0600), bind-mounted read-only.
Never in a compose environment variable.
