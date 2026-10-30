# key_rotation

> **Durin-pattern key rotation lab** — KV v2 versioning, Transit AES-GCM encryption,
> and AppRole credential rotation on a self-contained Podman stack.

Lineage: vault_reference → secret_rotation → vault_goldie_locks → vault_portal → vault_pki → **this project**

---

## What you get

| Feature | Details |
|---|---|
| Two Vault nodes | vault-s (OSS, Shamir) + vault-1 (ENT, Transit auto-unseal) |
| KV v2 demo secret | Version badge in the UI increments on every `make rotate-demo` |
| Transit AES-GCM | `booklib-aes` key; booklib encrypts/decrypts without ever exporting the key |
| AppRole rotation | The rotator keeps credentials fresh; the agent holds a valid token at all times |
| Token-file pattern | No `VAULT_TOKEN` in any container environment — booklib reads the file per request |
| React UI (HTTPS) | Daylight Glass design; 4 panels; vault-s + vault-1 live status pills |

## Ports

| Service | Port |
|---|---|
| vault-s (OSS) | 18700 |
| vault-1 (ENT) | 18701 |
| booklib API | 13400 |
| Frontend HTTPS | 13401 |

## Prerequisites

- Podman 4+ and `podman compose`
- `vault`, `terraform`, `jq`, `openssl`, `curl` on PATH
- A Vault Enterprise licence (set `VAULT_LICENSE` in `.env`)

## Quick start

```sh
make env-init    # creates .env from .env.example
make license     # installs the ENT licence from VAULT_LICENSE
make bootstrap   # TLS → Vault → Terraform → rotators → build → up → verify
```

Or step by step — see [DESIGN.md](DESIGN.md).

## Daily use

```sh
make up           # start from a stopped state
make down         # stop all stacks (data kept)
make rotate-demo  # rotate the KV demo secret; watch the UI update
make api-test     # test API key rotation against the live stack
make verify       # 25/25 end-to-end checks
make doctor       # explain any problem and name the fix
```

## Architecture

See [DESIGN.md](DESIGN.md) and [docs/architecture.md](docs/architecture.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
